// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.netstack;

import static com.skanavi.javaguard.netstack.TestNode.LONG;
import static com.skanavi.javaguard.netstack.TestNode.LOOPBACK;
import static com.skanavi.javaguard.netstack.TestNode.SHORT;
import static com.skanavi.javaguard.netstack.TestNode.await;
import static com.skanavi.javaguard.netstack.TestNode.runAll;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.skanavi.javaguard.core.Scheduler;
import com.skanavi.javaguard.core.UdpBind;
import com.skanavi.javaguard.crypto.PrivateKey;
import java.io.IOException;
import java.net.BindException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/** What tunnels in one JVM may share: a server, keys, a scheduler, a port, a DNS name. */
@Timeout(value = 120, unit = TimeUnit.SECONDS)
class TunnelIdentityTest extends TunnelTestBase {
  private static final int PORT = 9000;

  @Test
  void tenantsSharingOneServerAreToldApartByTheirKeys() throws Exception {
    TestNode server = node("server", "10.31.0.1/24");
    server.serveIdentity(PORT);
    List<TestNode> clients = new ArrayList<>();
    for (int i = 0; i < 6; i++) {
      String ip = "10.31.0." + (10 + i);
      TestNode client = node(ip, ip + "/24");
      client.connect(server, "10.31.0.1/32");
      server.addPeer(client, null, ip + "/32");
      client.start();
      clients.add(client);
    }
    server.start();

    // Each client sends a different amount, so a mixed-up peer shows in its counters.
    runAll(
        clients,
        c ->
            () -> {
              int size = size(c);
              String reply = new String(c.exchange("10.31.0.1", PORT, new byte[size]));
              assertThat(reply).isEqualTo(server.identity(c.name, size));
              return null;
            });

    for (TestNode c : clients) {
      assertThat(server.peer(c).rxBytes()).as(c.name).isGreaterThan(size(c));
      assertThat(server.peer(c).endpoint().orElseThrow().getPort())
          .as(c.name)
          .isEqualTo(c.device.listenPort());
    }
  }

  private static int size(TestNode client) {
    return (1 + client.name.hashCode() % 7 + 7) * (32 << 10);
  }

  @Test
  void twoLocalDevicesKeepIndependentSessionsWithTheSamePeer() throws Exception {
    TestNode server = node("server", "10.32.0.1/24");
    TestNode first = node("first", "10.32.0.2/24");
    TestNode second = node("second", "10.32.0.3/24");
    for (TestNode c : List.of(first, second)) {
      c.connect(server, "10.32.0.1/32");
      c.start();
    }
    server.addPeer(first, null, "10.32.0.2/32");
    server.addPeer(second, null, "10.32.0.3/32");
    server.start();
    assertThat(first.canPing("10.32.0.1", LONG)).isTrue();
    assertThat(second.canPing("10.32.0.1", LONG)).isTrue();

    assertThat(first.device.removePeer(server.device.publicKey())).isTrue();

    assertThat(first.canPing("10.32.0.1", SHORT)).isFalse();
    assertThat(second.canPing("10.32.0.1", LONG)).isTrue();
    assertThat(second.peer(server).lastHandshake()).isPresent();
  }

  /**
   * Two devices sharing a private key are one peer to the server, so they fight over its session
   * and endpoint. That is a misconfiguration with no good outcome for those two, but the last one
   * to handshake must win, and it must stay contained.
   */
  @Test
  void devicesSharingAPrivateKeyOnlyDisturbEachOther() throws Exception {
    PrivateKey shared = PrivateKey.generate();
    TestNode server = node("server", "10.33.0.1/24");
    TestNode first = twin("first", shared);
    TestNode second = twin("second", shared);
    TestNode neighbour = node("neighbour", "10.33.0.3/24");
    server.addPeer(first, null, "10.33.0.2/32");
    server.addPeer(neighbour, null, "10.33.0.3/32");
    for (TestNode c : List.of(first, second, neighbour)) {
      c.connect(server, "10.33.0.1/32");
      c.start();
    }
    server.start();

    assertThat(first.canPing("10.33.0.1", LONG)).isTrue();
    assertThat(neighbour.canPing("10.33.0.1", LONG)).isTrue();
    assertThat(second.canPing("10.33.0.1", LONG)).isTrue();
    assertThat(server.peer(first).endpoint().orElseThrow().getPort())
        .isEqualTo(second.device.listenPort());

    first.canPing("10.33.0.1", SHORT); // may well fail: the session now belongs to the other twin

    assertThat(neighbour.canPing("10.33.0.1", LONG)).isTrue();
    assertThat(server.device.isUp()).isTrue();
  }

  private TestNode twin(String name, PrivateKey key) throws IOException {
    return track(new TestNode(name, key, Netstack.builder().address("10.33.0.2/24").build()));
  }

  @Test
  void closingOneTunnelLeavesASharedSchedulerRunningForTheOthers() throws Exception {
    Scheduler shared = track(Scheduler.newDefault());
    TestNode doomedA = scheduled("doomed-a", "10.34.0.1/24", shared);
    TestNode doomedB = scheduled("doomed-b", "10.34.0.2/24", shared);
    TestNode liveA = scheduled("live-a", "10.34.0.1/24", shared);
    TestNode liveB = scheduled("live-b", "10.34.0.2/24", shared);
    link(doomedA, "10.34.0.1", doomedB, "10.34.0.2");
    link(liveA, "10.34.0.1", liveB, "10.34.0.2");
    liveB.serveDigest(PORT);
    assertThat(doomedA.canPing("10.34.0.2", LONG)).isTrue();
    assertThat(liveA.canPing("10.34.0.2", LONG)).isTrue();

    // Keepalives run only from the scheduler, so a growing count means it is still working.
    liveA.peer(liveB).persistentKeepalive(Duration.ofSeconds(1));
    doomedA.close();
    doomedB.close();

    long before = liveA.peer(liveB).txBytes();
    await("keepalives after the close", () -> liveA.peer(liveB).txBytes() >= before + 64);
    byte[] data = new byte[256 << 10];
    assertThat(liveA.exchange("10.34.0.2", PORT, data)).isEqualTo(TestNode.sha256(data));
  }

  private TestNode scheduled(String name, String address, Scheduler scheduler) throws IOException {
    Netstack stack = Netstack.builder().address(address).scheduler(scheduler).build();
    return track(
        new TestNode(name, PrivateKey.generate(), stack, TestNode.loopbackBind(), scheduler));
  }

  @Test
  void aPortAlreadyInUseFailsWithoutDisturbingItsOwner() throws Exception {
    TestNode a = node("a", "10.35.0.1/24");
    TestNode b = node("b", "10.35.0.2/24");
    link(a, "10.35.0.1", b, "10.35.0.2");
    int taken = b.device.listenPort();

    assertThatThrownBy(() -> UdpBind.open(new InetSocketAddress(LOOPBACK, taken)))
        .isInstanceOf(BindException.class);

    assertThat(b.device.listenPort()).isEqualTo(taken);
    assertThat(a.canPing("10.35.0.2", LONG)).isTrue();
  }

  @Test
  void eachTunnelResolvesNamesThroughItsOwnDns() throws Exception {
    Map<String, List<String>> zoneA =
        Map.of("svc.test", List.of("A 10.36.0.10"), "only-a.test", List.of("A 10.36.0.11"));
    Map<String, List<String>> zoneB = Map.of("svc.test", List.of("A 10.36.0.20"));
    TestNode clientA = dnsTenant("a", zoneA);
    TestNode clientB = dnsTenant("b", zoneB);

    assertThat(clientA.stack.dns().resolve("svc.test"))
        .containsExactly(InetAddress.ofLiteral("10.36.0.10"));
    assertThat(clientB.stack.dns().resolve("svc.test"))
        .containsExactly(InetAddress.ofLiteral("10.36.0.20"));
    assertThat(clientA.stack.dns().resolve("only-a.test"))
        .containsExactly(InetAddress.ofLiteral("10.36.0.11"));
    assertThatThrownBy(() -> clientB.stack.dns().resolve("only-a.test"))
        .isInstanceOf(UnknownHostException.class);
  }

  /** A client whose DNS server, at the same address for every tenant, answers from {@code zone}. */
  private TestNode dnsTenant(String name, Map<String, List<String>> zone) throws IOException {
    Netstack clientStack = Netstack.builder().address("10.36.0.1/24").dns("10.36.0.2").build();
    TestNode client = track(new TestNode("client-" + name, clientStack));
    TestNode server = node("dns-" + name, "10.36.0.2/24");
    link(client, "10.36.0.1", server, "10.36.0.2");
    UdpSocket socket = server.stack.openUdp(53);
    Thread.ofVirtual()
        .start(
            () -> {
              try {
                while (true) {
                  UdpSocket.Datagram q = socket.receive(LONG);
                  if (q != null) {
                    socket.send(q.source(), DnsResolverTest.answer(q.data(), zone, 3));
                  }
                }
              } catch (Exception e) {
                // closed
              }
            });
    return client;
  }
}
