// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.netstack;

import static com.skanavi.javaguard.netstack.TestNode.LONG;
import static com.skanavi.javaguard.netstack.TestNode.LOOPBACK;
import static com.skanavi.javaguard.netstack.TestNode.address;
import static com.skanavi.javaguard.netstack.TestNode.await;
import static com.skanavi.javaguard.netstack.TestNode.awaitThreadsGone;
import static com.skanavi.javaguard.netstack.TestNode.liveThreads;
import static com.skanavi.javaguard.netstack.TestNode.loopbackBind;
import static com.skanavi.javaguard.netstack.TestNode.sha256;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.skanavi.javaguard.core.Bind;
import com.skanavi.javaguard.core.PeerConfig;
import com.skanavi.javaguard.crypto.PrivateKey;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.nio.channels.ClosedChannelException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/** One tunnel changing, closing or being attacked while its neighbours carry on. */
@Timeout(value = 120, unit = TimeUnit.SECONDS)
class TunnelLifecycleTest extends TunnelTestBase {
  private static final int PORT = 9000;
  private static final String CLIENT = "10.9.0.1";
  private static final String SERVER = "10.9.0.2";

  /** A client and server joined by a tunnel, with the server verifying transfers. */
  private record Pair(TestNode client, TestNode server) {
    void transfer(byte[] data) throws IOException {
      assertThat(client.exchange(SERVER, PORT, data)).isEqualTo(sha256(data));
    }
  }

  private Pair pair(String name) throws IOException {
    TestNode client = node(name + "-client", CLIENT + "/24");
    TestNode server = node(name + "-server", SERVER + "/24");
    link(client, CLIENT, server, SERVER);
    server.serveDigest(PORT);
    return new Pair(client, server);
  }

  /** Keeps a tunnel busy in the background; closing it reports any failed transfer. */
  private static final class Traffic implements AutoCloseable {
    private final AtomicBoolean stop = new AtomicBoolean();
    private final AtomicLong transfers = new AtomicLong();
    private final ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor();
    private final Future<Void> run;

    Traffic(Pair pair) {
      byte[] data = new byte[64 << 10];
      new Random(3).nextBytes(data);
      run =
          pool.submit(
              () -> {
                while (!stop.get()) {
                  pair.transfer(data);
                  transfers.incrementAndGet();
                }
                return null;
              });
    }

    long transfers() {
      return transfers.get();
    }

    @Override
    public void close() {
      stop.set(true);
      try {
        run.get();
      } catch (ExecutionException e) {
        throw new AssertionError("neighbour traffic failed", e.getCause());
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new AssertionError(e);
      } finally {
        pool.close();
      }
    }
  }

  @Test
  void tunnelsCanComeAndGoUnderLoadWithoutLeakingThreads() throws Exception {
    Pair warmup = pair("warmup");
    warmup.transfer(new byte[1024]);
    warmup.client.close();
    warmup.server.close();
    Set<Thread> baseline = liveThreads(Set.of());

    Pair neighbour = pair("neighbour");
    try (Traffic traffic = new Traffic(neighbour)) {
      for (int i = 0; i < 15; i++) {
        Pair p = pair("churn-" + i);
        p.transfer(new byte[16 << 10]);
        p.client.close();
        p.server.close();
      }
      long seen = traffic.transfers();
      await("traffic after the churn", () -> traffic.transfers() > seen);
    }
    neighbour.client.close();
    neighbour.server.close();

    awaitThreadsGone(baseline);
  }

  @Test
  void changingOneTunnelsKeysLeavesItsNeighbourRunning() throws Exception {
    Pair target = pair("target");
    Pair neighbour = pair("neighbour");
    target.transfer(new byte[1024]);

    try (Traffic traffic = new Traffic(neighbour)) {
      PrivateKey newKey = PrivateKey.generate();
      target.server.device.removePeer(target.client.device.publicKey());
      target.client.device.privateKey(newKey);
      target.server.device.addPeer(
          PeerConfig.builder(newKey.publicKey()).allowedIp(CLIENT + "/32").build());

      target.transfer(new byte[64 << 10]);

      long seen = traffic.transfers();
      await("neighbour traffic", () -> traffic.transfers() > seen);
    }
  }

  @Test
  void roamingMovesOnlyThatTunnelsEndpoint() throws Exception {
    Pair roamer = pair("roamer");
    Pair neighbour = pair("neighbour");
    roamer.transfer(new byte[1024]);
    neighbour.transfer(new byte[1024]);
    InetSocketAddress neighbourEndpoint =
        neighbour.server.peer(neighbour.client).endpoint().orElseThrow();

    try (Traffic traffic = new Traffic(neighbour)) {
      int oldPort = roamer.client.device.listenPort();
      roamer.client.device.bind(loopbackBind());
      int newPort = roamer.client.device.listenPort();
      assertThat(newPort).isNotEqualTo(oldPort);

      roamer.transfer(new byte[64 << 10]);

      assertThat(roamer.server.peer(roamer.client).endpoint().orElseThrow().getPort())
          .isEqualTo(newPort);
      long seen = traffic.transfers();
      await("neighbour traffic", () -> traffic.transfers() > seen);
    }
    assertThat(neighbour.server.peer(neighbour.client).endpoint()).contains(neighbourEndpoint);
  }

  /**
   * Junk with a handshake's type and length reaches the device's handshake queue. It fails MAC
   * checks, so this covers queue pressure and neighbours; the cookie reply itself is covered by
   * {@code DeviceSimulationTest}.
   */
  @Test
  void floodingOneDeviceLeavesOtherTunnelsAbleToHandshake() throws Exception {
    Pair target = pair("target");
    AtomicBoolean stop = new AtomicBoolean();
    int port = target.server.device.listenPort();
    List<Thread> flooders = new ArrayList<>();
    AtomicLong sent = new AtomicLong();
    for (int i = 0; i < 4; i++) {
      long seed = i;
      flooders.add(Thread.ofVirtual().start(() -> flood(port, seed, stop, sent)));
    }
    try {
      await("the flood to start", () -> sent.get() > 1000);
      Pair fresh = pair("fresh");
      fresh.transfer(new byte[64 << 10]);
      assertThat(fresh.client.peer(fresh.server).lastHandshake()).isPresent();
    } finally {
      stop.set(true);
      for (Thread t : flooders) {
        t.join();
      }
    }

    target.transfer(new byte[64 << 10]);
    assertThat(target.client.peer(target.server).lastHandshake()).isPresent();
  }

  private static void flood(int port, long seed, AtomicBoolean stop, AtomicLong sent) {
    byte[] packet = new byte[148]; // the length of a handshake initiation
    Random random = new Random(seed);
    try (DatagramSocket socket = new DatagramSocket()) {
      while (!stop.get()) {
        random.nextBytes(packet);
        packet[0] = 1;
        packet[1] = packet[2] = packet[3] = 0;
        socket.send(new DatagramPacket(packet, packet.length, LOOPBACK, port));
        sent.incrementAndGet();
      }
    } catch (IOException e) {
      throw new AssertionError(e);
    }
  }

  @Test
  void tunnelsWithDifferentMtusCarryFullSizedTraffic() throws Exception {
    for (int[] mtus : new int[][] {{1280, 1280}, {1420, 1420}, {1280, 1420}, {1420, 1280}}) {
      String name = mtus[0] + "-" + mtus[1];
      TestNode client = mtuNode("client-" + name, CLIENT, mtus[0]);
      TestNode server = mtuNode("server-" + name, SERVER, mtus[1]);
      link(client, CLIENT, server, SERVER);
      server.serveDigest(PORT);
      byte[] data = new byte[1 << 20];
      new Random(mtus[0]).nextBytes(data);
      assertThat(client.exchange(SERVER, PORT, data)).as(name).isEqualTo(sha256(data));

      int largest = mtus[0] - 28;
      try (UdpSocket sink = server.stack.openUdp(7000);
          UdpSocket sender = client.stack.openUdp()) {
        sender.send(address(SERVER, 7000), new byte[largest]);
        UdpSocket.Datagram got = sink.receive(LONG);
        assertThat(got).as(name).isNotNull();
        assertThat(got.data()).as(name).hasSize(largest);
        assertThatThrownBy(() -> sender.send(address(SERVER, 7000), new byte[largest + 1]))
            .isInstanceOf(IllegalArgumentException.class);
      }
    }
  }

  private TestNode mtuNode(String name, String ip, int mtu) throws IOException {
    return track(new TestNode(name, Netstack.builder().address(ip + "/24").mtu(mtu).build()));
  }

  @Test
  void aTunnelCanRunInsideAnotherTunnel() throws Exception {
    Pair outer = pair("outer");
    int innerPort = 51820;
    TestNode client =
        innerNode("inner-client", "10.42.0.1/24", outer.client.stack.openUdp(innerPort));
    TestNode server =
        innerNode("inner-server", "10.42.0.2/24", outer.server.stack.openUdp(innerPort));
    client.addPeer(server, address(SERVER, innerPort), "10.42.0.2/32");
    server.addPeer(client, null, "10.42.0.1/32");
    client.start();
    server.start();
    server.serveDigest(PORT);

    byte[] data = new byte[1 << 20];
    new Random(4).nextBytes(data);
    assertThat(client.exchange("10.42.0.2", PORT, data)).isEqualTo(sha256(data));

    assertThat(outer.server.peer(outer.client).rxBytes()).isGreaterThan(data.length);
    assertThat(server.peer(client).endpoint().orElseThrow().getAddress().getHostAddress())
        .isEqualTo(CLIENT);
  }

  private TestNode innerNode(String name, String address, UdpSocket socket) {
    // 1280 leaves room for the inner WireGuard and UDP headers within the outer tunnel's MTU.
    Netstack stack = Netstack.builder().address(address).mtu(1280).build();
    return track(new TestNode(name, PrivateKey.generate(), stack, new NetstackBind(socket), null));
  }

  /** Carries a device's WireGuard messages over a UDP socket of another tunnel's netstack. */
  private record NetstackBind(UdpSocket socket) implements Bind {
    @Override
    public Datagram receive(byte[] buf) throws IOException {
      try {
        while (true) {
          UdpSocket.Datagram d = socket.receive(Duration.ofSeconds(1));
          if (d != null) {
            System.arraycopy(d.data(), 0, buf, 0, d.data().length);
            return new Datagram(d.data().length, d.source());
          }
        }
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new ClosedChannelException();
      }
    }

    @Override
    public void send(byte[] buf, int off, int len, InetSocketAddress target) throws IOException {
      socket.send(target, buf, off, len);
    }

    @Override
    public int localPort() {
      return socket.localPort();
    }

    @Override
    public void close() {
      socket.close();
    }
  }
}
