// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.netstack;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.skanavi.javaguard.core.Bind;
import com.skanavi.javaguard.core.Device;
import com.skanavi.javaguard.core.Peer;
import com.skanavi.javaguard.core.PeerConfig;
import com.skanavi.javaguard.core.UdpBind;
import com.skanavi.javaguard.crypto.PrivateKey;
import com.skanavi.javaguard.crypto.PublicKey;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * One JVM running several independent tunnels, the way a multi-tenant service would. Every tunnel
 * deliberately uses the same inner addresses and port, so anything shared between them by accident
 * shows up as a reply from the wrong tenant.
 */
@Timeout(value = 120, unit = TimeUnit.SECONDS)
class MultiTunnelTest {
  private static final InetAddress LOOPBACK = InetAddress.getLoopbackAddress();
  private static final String CLIENT_IP = "10.9.0.1";
  private static final String SERVER_IP = "10.9.0.2";
  private static final InetAddress SERVER = InetAddress.ofLiteral(SERVER_IP);
  private static final int PORT = 9000;
  private static final Duration SHORT = Duration.ofSeconds(2);
  private static final Duration LONG = Duration.ofSeconds(30);

  private final List<AutoCloseable> resources = new ArrayList<>();

  @AfterEach
  void closeEverything() throws Exception {
    for (AutoCloseable c : resources.reversed()) {
      c.close();
    }
  }

  @Test
  void tunnelsWithIdenticalAddressesCarryConcurrentTrafficWithoutMixing() throws Exception {
    List<Tunnel> tunnels = new ArrayList<>();
    for (int i = 0; i < 8; i++) {
      tunnels.add(tunnel("tenant-" + i));
    }
    int transfers = 5;
    int size = 256 << 10;

    CountDownLatch go = new CountDownLatch(tunnels.size());
    runAll(
        tunnels,
        t ->
            () -> {
              go.countDown();
              go.await();
              Random random = new Random(t.name.hashCode());
              for (int n = 0; n < transfers; n++) {
                byte[] data = new byte[size];
                random.nextBytes(data);
                t.transfer(data);
                assertThat(t.clientStack.ping(SERVER, LONG)).isPresent();
              }
              return null;
            });

    for (Tunnel t : tunnels) {
      assertThat(t.serverPeer().rxBytes()).as(t.name).isGreaterThan((long) transfers * size);
      assertThat(t.clientPeer().txBytes()).as(t.name).isGreaterThan((long) transfers * size);
    }
    Set<PublicKey> keys = new HashSet<>();
    tunnels.forEach(t -> keys.add(t.client.publicKey()));
    assertThat(keys).hasSameSizeAs(tunnels);
  }

  @Test
  void closingOneTunnelLeavesTheOthersRunning() throws Exception {
    Tunnel victim = tunnel("victim");
    List<Tunnel> survivors = List.of(tunnel("survivor-0"), tunnel("survivor-1"));
    byte[] data = new byte[64 << 10];
    new Random(1).nextBytes(data);
    CountDownLatch running = new CountDownLatch(survivors.size() + 1);
    AtomicBoolean victimClosed = new AtomicBoolean();

    try (ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor()) {
      Future<Void> doomed =
          pool.submit(
              () -> {
                while (true) {
                  victim.transfer(data);
                  running.countDown();
                }
              });
      List<Future<Void>> others = new ArrayList<>();
      for (Tunnel t : survivors) {
        others.add(
            pool.submit(
                () -> {
                  int afterClose = 0;
                  while (afterClose < 3) {
                    boolean counted = victimClosed.get();
                    t.transfer(data);
                    running.countDown();
                    afterClose += counted ? 1 : 0;
                  }
                  return null;
                }));
      }

      assertThat(running.await(60, TimeUnit.SECONDS)).isTrue();
      victim.close();
      victimClosed.set(true);

      for (Future<Void> f : others) {
        f.get();
      }
      assertThatThrownBy(doomed::get).isInstanceOf(ExecutionException.class);
    }
    assertThat(victim.client.isUp()).isFalse();
    for (Tunnel t : survivors) {
      assertThat(t.client.isUp()).isTrue();
      assertThat(t.clientStack.ping(SERVER, LONG)).isPresent();
    }
  }

  @Test
  void closingATunnelReleasesItsThreadsAndPorts() throws Exception {
    Tunnel neighbour = tunnel("neighbour");
    byte[] data = "hello".getBytes(UTF_8);
    neighbour.transfer(data);

    // A first cycle lets the JDK start whatever it starts lazily, so only per-tunnel threads count.
    Tunnel warmup = tunnel("warmup");
    warmup.transfer(data);
    warmup.close();
    Set<Thread> baseline = liveThreads(Set.of());

    Tunnel tunnel = tunnel("transient");
    tunnel.transfer(data);
    assertThat(liveThreads(baseline)).isNotEmpty();
    int clientPort = tunnel.client.listenPort();
    int serverPort = tunnel.server.listenPort();
    tunnel.close();

    awaitNoNewThreads(baseline, Duration.ofSeconds(10));
    for (int port : List.of(clientPort, serverPort)) {
      try (Bind rebound = UdpBind.open(new InetSocketAddress(LOOPBACK, port))) {
        assertThat(rebound).isNotNull();
      }
    }
    neighbour.transfer(data);
  }

  @Test
  void aDeviceCannotReachATunnelItDoesNotBelongTo() throws Exception {
    Tunnel own = tunnel("own");
    Tunnel target = tunnel("target");
    int targetPort = target.server.listenPort();

    // A stranger who knows the real server key, then one who has the wrong key for that endpoint.
    for (PublicKey key : List.of(target.server.publicKey(), own.server.publicKey())) {
      Netstack stack = Netstack.builder().address(CLIENT_IP + "/24").build();
      PrivateKey strangerKey = PrivateKey.generate();
      try (Device stranger = device(strangerKey, stack)) {
        stranger.addPeer(
            PeerConfig.builder(key)
                .endpoint(new InetSocketAddress(LOOPBACK, targetPort))
                .allowedIp(SERVER_IP + "/32")
                .build());
        stranger.start();
        assertThat(stack.ping(SERVER, SHORT)).isEmpty();
        assertThat(stranger.peer(key).lastHandshake()).isEmpty();
      }
    }

    assertThat(target.serverPeer().rxBytes()).isZero();
    assertThat(target.serverPeer().lastHandshake()).isEmpty();
    target.transfer("still fine".getBytes(UTF_8));
  }

  @Test
  void oneDeviceRoutesBetweenTwoLivePeers() throws Exception {
    PrivateKey hubKey = PrivateKey.generate();
    Netstack hubStack = Netstack.builder().address("10.10.0.1/24").build();
    Device hub = device(hubKey, hubStack);
    resources.add(hub);
    Spoke big = spoke(hub, "10.10.0.2");
    Spoke small = spoke(hub, "10.10.0.3");
    hub.start();
    big.device.start();
    small.device.start();

    // The hub reports who it saw, so a reply proves which peer the connection really came from.
    TcpListener listener = hubStack.listenTcp(PORT);
    Thread.ofVirtual()
        .start(
            () ->
                serve(
                    listener,
                    s -> {
                      long read = s.inputStream().readAllBytes().length;
                      String who = s.remoteAddress().getAddress().getHostAddress();
                      return (who + " " + read).getBytes(UTF_8);
                    }));

    int bigSize = 1 << 20;
    int smallSize = 16 << 10;
    List<Spoke> spokes = List.of(big, small);
    runAll(
        spokes,
        s ->
            () -> {
              int size = s == big ? bigSize : smallSize;
              String reply = new String(exchange(s.stack, "10.10.0.1", new byte[size]), UTF_8);
              assertThat(reply).isEqualTo(s.ip + " " + size);
              return null;
            });

    Peer bigPeer = hub.peer(big.device.publicKey());
    Peer smallPeer = hub.peer(small.device.publicKey());
    assertThat(bigPeer.rxBytes()).isGreaterThan(bigSize);
    assertThat(smallPeer.rxBytes()).isGreaterThan(smallSize).isLessThan(bigSize);
    assertThat(hubStack.ping(InetAddress.ofLiteral(big.ip), LONG)).isPresent();
    assertThat(hubStack.ping(InetAddress.ofLiteral(small.ip), LONG)).isPresent();

    assertThat(hub.removePeer(big.device.publicKey())).isTrue();
    assertThat(hubStack.ping(InetAddress.ofLiteral(big.ip), SHORT)).isEmpty();
    assertThat(hubStack.ping(InetAddress.ofLiteral(small.ip), LONG)).isPresent();
  }

  // ---------------------------------------------------------------- helpers

  private Tunnel tunnel(String name) throws IOException {
    Tunnel t = new Tunnel(name);
    resources.add(t);
    return t;
  }

  private Spoke spoke(Device hub, String ip) throws IOException {
    PrivateKey key = PrivateKey.generate();
    Netstack stack = Netstack.builder().address(ip + "/24").build();
    Device device = device(key, stack);
    resources.add(device);
    device.addPeer(
        PeerConfig.builder(hub.publicKey())
            .endpoint(new InetSocketAddress(LOOPBACK, hub.listenPort()))
            .allowedIp("10.10.0.1/32")
            .build());
    hub.addPeer(PeerConfig.builder(key.publicKey()).allowedIp(ip + "/32").build());
    return new Spoke(ip, stack, device);
  }

  private static Device device(PrivateKey key, Netstack stack) throws IOException {
    return Device.builder()
        .privateKey(key)
        .bind(UdpBind.open(new InetSocketAddress(LOOPBACK, 0)))
        .tun(stack)
        .build();
  }

  /** Runs one task per item concurrently and rethrows the first failure. */
  private static <T> void runAll(List<T> items, Function<T, Callable<Void>> task) throws Exception {
    try (ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor()) {
      List<Future<Void>> futures = new ArrayList<>();
      for (T item : items) {
        futures.add(pool.submit(task.apply(item)));
      }
      for (Future<Void> f : futures) {
        f.get();
      }
    }
  }

  private static byte[] exchange(Netstack stack, String host, byte[] data) throws IOException {
    InetSocketAddress remote = new InetSocketAddress(InetAddress.ofLiteral(host), PORT);
    try (TcpSocket s = stack.connectTcp(remote, LONG)) {
      s.readTimeout(LONG);
      s.outputStream().write(data);
      s.shutdownOutput();
      return s.inputStream().readAllBytes();
    }
  }

  /** Answers each connection with {@code handler}'s reply until the listener closes. */
  private static void serve(TcpListener listener, Handler handler) {
    try {
      while (true) {
        TcpSocket socket = listener.accept();
        Thread.ofVirtual()
            .start(
                () -> {
                  try (socket) {
                    socket.outputStream().write(handler.reply(socket));
                    socket.shutdownOutput();
                  } catch (Exception e) {
                    // the client side reports the failure
                  }
                });
      }
    } catch (IOException e) {
      // closed
    }
  }

  /** Live platform threads not in {@code known}, leaving out the JDK's virtual thread carriers. */
  private static Set<Thread> liveThreads(Set<Thread> known) {
    Set<Thread> live = new HashSet<>(Thread.getAllStackTraces().keySet());
    live.removeAll(known);
    live.removeIf(t -> !t.isAlive() || t.getName().startsWith("ForkJoinPool"));
    return live;
  }

  private static void awaitNoNewThreads(Set<Thread> baseline, Duration timeout)
      throws InterruptedException {
    long deadline = System.nanoTime() + timeout.toNanos();
    while (System.nanoTime() < deadline && !liveThreads(baseline).isEmpty()) {
      Thread.sleep(50);
    }
    assertThat(liveThreads(baseline)).extracting(Thread::getName).isEmpty();
  }

  @FunctionalInterface
  private interface Handler {
    byte[] reply(TcpSocket socket) throws Exception;
  }

  private record Spoke(String ip, Netstack stack, Device device) {}

  /** A client and a server device joined by their own tunnel, with a tenant-stamping TCP server. */
  private static final class Tunnel implements AutoCloseable {
    final String name;
    final Netstack clientStack = Netstack.builder().address(CLIENT_IP + "/24").build();
    final Netstack serverStack = Netstack.builder().address(SERVER_IP + "/24").build();
    final Device client;
    final Device server;

    Tunnel(String name) throws IOException {
      this.name = name;
      PrivateKey clientKey = PrivateKey.generate();
      PrivateKey serverKey = PrivateKey.generate();
      client = device(clientKey, clientStack);
      server = device(serverKey, serverStack);
      client.addPeer(
          PeerConfig.builder(serverKey.publicKey())
              .endpoint(new InetSocketAddress(LOOPBACK, server.listenPort()))
              .allowedIp(SERVER_IP + "/32")
              .build());
      server.addPeer(
          PeerConfig.builder(clientKey.publicKey()).allowedIp(CLIENT_IP + "/32").build());
      client.start();
      server.start();
      TcpListener listener = serverStack.listenTcp(PORT);
      Thread.ofVirtual().start(() -> serve(listener, s -> stamped(s.inputStream().readAllBytes())));
    }

    Peer clientPeer() {
      return client.peer(server.publicKey());
    }

    Peer serverPeer() {
      return server.peer(client.publicKey());
    }

    /** Sends {@code data} and checks it reached this tunnel's server, unchanged. */
    void transfer(byte[] data) throws Exception {
      assertThat(exchange(clientStack, SERVER_IP, data)).as(name).isEqualTo(stamped(data));
    }

    private byte[] stamped(byte[] data) throws Exception {
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      out.write(name.getBytes(UTF_8));
      out.write(MessageDigest.getInstance("SHA-256").digest(data));
      return out.toByteArray();
    }

    @Override
    public void close() throws IOException {
      client.close();
      server.close();
    }
  }
}
