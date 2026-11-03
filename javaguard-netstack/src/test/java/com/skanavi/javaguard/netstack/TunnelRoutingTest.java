// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.netstack;

import static com.skanavi.javaguard.netstack.TestNode.LONG;
import static com.skanavi.javaguard.netstack.TestNode.SHORT;
import static com.skanavi.javaguard.netstack.TestNode.address;
import static com.skanavi.javaguard.netstack.TestNode.await;
import static com.skanavi.javaguard.netstack.TestNode.sha256;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.skanavi.javaguard.core.IpPrefix;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.security.MessageDigest;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/** Traffic between tunnels in one JVM, and how addresses select (or refuse) a route. */
@Timeout(value = 120, unit = TimeUnit.SECONDS)
class TunnelRoutingTest extends TunnelTestBase {
  private static final int PORT = 9000;
  private static final int UDP_PORT = 7000;

  @Test
  void tenantsInDifferentSubnetsTalkDirectlyBothWays() throws Exception {
    TestNode a = node("a", "10.20.0.1/24");
    TestNode b = node("b", "10.30.0.1/24");
    link(a, "10.20.0.1", b, "10.30.0.1");
    for (TestNode n : new TestNode[] {a, b}) {
      n.serveIdentity(PORT);
      n.serveUdpEcho(UDP_PORT);
    }

    assertThat(a.whoIs("10.30.0.1", PORT)).isEqualTo(b.identity("10.20.0.1", 0));
    assertThat(b.whoIs("10.20.0.1", PORT)).isEqualTo(a.identity("10.30.0.1", 0));
    assertThat(a.udpExchange("10.30.0.1", UDP_PORT, "hi")).isEqualTo("b:hi");
    assertThat(b.udpExchange("10.20.0.1", UDP_PORT, "hi")).isEqualTo("a:hi");
  }

  @Test
  void anApplicationCanBridgeTwoTunnels() throws Exception {
    TestNode left = node("left", "10.21.0.1/24");
    TestNode bridgeLeft = node("bridge-left", "10.21.0.2/24");
    TestNode bridgeRight = node("bridge-right", "10.22.0.1/24");
    TestNode right = node("right", "10.22.0.2/24");
    link(left, "10.21.0.1", bridgeLeft, "10.21.0.2");
    link(bridgeRight, "10.22.0.1", right, "10.22.0.2");

    // A slow far end, so the bridge has to hold back the sender rather than buffer everything.
    right.serve(
        PORT,
        s -> {
          MessageDigest digest = MessageDigest.getInstance("SHA-256");
          byte[] chunk = new byte[16 << 10];
          int n;
          while ((n = s.inputStream().read(chunk)) >= 0) {
            digest.update(chunk, 0, n);
            Thread.sleep(1);
          }
          return digest.digest();
        });
    TcpListener bridge = bridgeLeft.stack.listenTcp(PORT);
    Thread.ofVirtual()
        .start(
            () -> {
              try (TcpSocket in = bridge.accept();
                  TcpSocket out = bridgeRight.stack.connectTcp(address("10.22.0.2", PORT), LONG)) {
                Thread reply = Thread.ofVirtual().start(() -> relay(out, in));
                relay(in, out);
                reply.join();
              } catch (IOException | InterruptedException e) {
                // the client side reports the failure
              }
            });

    byte[] data = new byte[4 << 20];
    new Random(2).nextBytes(data);
    assertThat(left.exchange("10.21.0.2", PORT, data)).isEqualTo(sha256(data));
  }

  /** Copies {@code from} to {@code to}, passing on the half-close. */
  private static void relay(TcpSocket from, TcpSocket to) {
    try {
      InputStream in = from.inputStream();
      OutputStream out = to.outputStream();
      in.transferTo(out);
      to.shutdownOutput();
    } catch (IOException e) {
      // the client side reports the failure
    }
  }

  /**
   * A Netstack hub ends traffic rather than routing it, unlike a kernel WireGuard server with IP
   * forwarding: spokes reach the hub but never each other, and the hub's own sockets must not pick
   * up packets meant for another address. Change this test if forwarding is ever added.
   */
  @Test
  void aHubDoesNotForwardBetweenSpokes() throws Exception {
    TestNode hub = node("hub", "10.23.0.1/24");
    TestNode a = node("a", "10.23.0.2/24");
    TestNode b = node("b", "10.23.0.3/24");
    hub.connect(a, "10.23.0.2/32");
    hub.connect(b, "10.23.0.3/32");
    a.connect(hub, "10.23.0.0/24");
    b.connect(hub, "10.23.0.0/24");
    hub.start();
    a.start();
    b.start();
    assertThat(a.canPing("10.23.0.1", LONG)).isTrue();
    assertThat(b.canPing("10.23.0.1", LONG)).isTrue();

    try (UdpSocket atHub = hub.stack.openUdp(UDP_PORT);
        UdpSocket atB = b.stack.openUdp(UDP_PORT);
        UdpSocket sender = a.stack.openUdp()) {
      long before = hub.peer(a).rxBytes();
      sender.send(address("10.23.0.3", UDP_PORT), "for b".getBytes(UTF_8));
      await("the packet to reach the hub", () -> hub.peer(a).rxBytes() > before);

      assertThat(atB.receive(SHORT)).isNull();
      assertThat(atHub.receive(java.time.Duration.ZERO)).isNull();
    }
    assertThat(a.canPing("10.23.0.3", SHORT)).isFalse();
  }

  @Test
  void aPeerCannotSendFromAnotherPeersAddress() throws Exception {
    TestNode hub = node("hub", "10.25.0.1/24");
    TestNode honest = node("honest", "10.25.0.3/24");
    // Its stack claims the honest peer's address, but the hub only routes .2 to it.
    TestNode spoofer = node("spoofer", "10.25.0.3/24");
    hub.connect(honest, "10.25.0.3/32");
    hub.connect(spoofer, "10.25.0.2/32");
    honest.connect(hub, "10.25.0.1/32");
    spoofer.connect(hub, "10.25.0.1/32");
    hub.start();
    honest.start();
    spoofer.start();

    try (UdpSocket server = hub.stack.openUdp(UDP_PORT);
        UdpSocket fake = spoofer.stack.openUdp();
        UdpSocket real = honest.stack.openUdp()) {
      fake.send(address("10.25.0.1", UDP_PORT), "forged".getBytes(UTF_8));
      await("the spoofer's session", () -> hub.peer(spoofer).lastHandshake().isPresent());
      fake.send(address("10.25.0.1", UDP_PORT), "forged again".getBytes(UTF_8));
      assertThat(server.receive(SHORT)).isNull();

      real.send(address("10.25.0.1", UDP_PORT), "genuine".getBytes(UTF_8));
      UdpSocket.Datagram got = server.receive(LONG);
      assertThat(got).isNotNull();
      assertThat(new String(got.data(), UTF_8)).isEqualTo("genuine");
    }
  }

  @Test
  void theLongestMatchingPrefixPicksThePeerAndFollowsLiveChanges() throws Exception {
    TestNode hub = node("hub", "10.24.0.1/16");
    // Both can answer for 10.24.1.2, so the reply shows which peer the hub actually chose.
    TestNode wide = node("wide", "10.24.0.2/16", "10.24.1.2/16");
    TestNode narrow = node("narrow", "10.24.1.2/16");
    hub.connect(wide, "10.24.0.0/16");
    hub.connect(narrow, "10.24.1.0/24");
    wide.connect(hub, "10.24.0.1/32");
    narrow.connect(hub, "10.24.0.1/32");
    hub.start();
    wide.start();
    narrow.start();
    wide.serveIdentity(PORT);
    narrow.serveIdentity(PORT);

    assertThat(hub.whoIs("10.24.0.2", PORT)).startsWith("wide ");
    assertThat(hub.whoIs("10.24.1.2", PORT)).startsWith("narrow ");

    hub.peer(narrow).removeAllowedIp(IpPrefix.parse("10.24.1.0/24"));
    assertThat(hub.whoIs("10.24.1.2", PORT)).startsWith("wide ");

    hub.peer(narrow).addAllowedIp(IpPrefix.parse("10.24.1.2/32"));
    assertThat(hub.whoIs("10.24.1.2", PORT)).startsWith("narrow ");

    // A prefix belongs to one peer, so giving it to another takes it away from the first.
    hub.peer(narrow).addAllowedIp(IpPrefix.parse("10.24.0.0/16"));
    assertThat(hub.peer(wide).allowedIps()).isEmpty();
    assertThat(hub.canPing("10.24.0.2", SHORT)).isFalse();
  }

  @Test
  void tunnelsMixIpv4Ipv6AndSeveralAddresses() throws Exception {
    TestNode v4Client = node("v4-client", "10.26.0.1/24");
    TestNode v4Server = node("v4-server", "10.26.0.2/24");
    link(v4Client, "10.26.0.1", v4Server, "10.26.0.2");

    TestNode v6Client = node("v6-client", "fd26::1/64");
    TestNode v6Server = node("v6-server", "fd26::2/64");
    link(v6Client, "fd26::1", v6Server, "fd26::2");

    TestNode dualClient = node("dual-client", "10.27.0.1/24", "fd27::1/64");
    TestNode dualServer = node("dual-server", "10.27.0.2/24", "10.27.0.3/24", "fd27::2/64");
    dualClient.connect(dualServer, "10.27.0.2/32", "10.27.0.3/32", "fd27::2/128");
    dualServer.connect(dualClient, "10.27.0.1/32", "fd27::1/128");
    dualClient.start();
    dualServer.start();

    for (TestNode server : new TestNode[] {v4Server, v6Server, dualServer}) {
      server.serveIdentity(PORT);
    }
    assertThat(v4Client.whoIs("10.26.0.2", PORT)).isEqualTo(v4Server.identity("10.26.0.1", 0));
    assertThat(v6Client.whoIs("fd26::2", PORT)).isEqualTo(v6Server.identity("fd26::1", 0));
    assertThat(dualClient.whoIs("10.27.0.2", PORT)).isEqualTo(dualServer.identity("10.27.0.1", 0));
    assertThat(dualClient.whoIs("10.27.0.3", PORT)).isEqualTo(dualServer.identity("10.27.0.1", 0));
    assertThat(dualClient.whoIs("fd27::2", PORT)).isEqualTo(dualServer.identity("fd27::1", 0));

    assertThat(dualClient.canPing("10.27.0.3", LONG)).isTrue();
    assertThat(dualClient.canPing("fd27::2", LONG)).isTrue();
    assertThat(v6Client.canPing("fd26::2", LONG)).isTrue();

    // A stack with no address of a family has nothing to send from.
    assertThatThrownBy(() -> v4Client.stack.connectTcp(address("fd26::2", PORT), SHORT))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> v6Client.stack.connectTcp(address("10.26.0.2", PORT), SHORT))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void trafficWithNoRouteFailsCleanlyAndLeavesTheTunnelWorking() throws Exception {
    TestNode a = node("a", "10.28.0.1/24");
    TestNode b = node("b", "10.28.0.2/24");
    link(a, "10.28.0.1", b, "10.28.0.2");
    b.serveIdentity(PORT);

    assertThat(a.stack.ping(InetAddress.ofLiteral("10.99.0.1"), SHORT)).isEmpty();
    assertThatThrownBy(() -> a.stack.connectTcp(address("10.99.0.1", PORT), SHORT))
        .isInstanceOf(SocketTimeoutException.class);
    try (UdpSocket socket = a.stack.openUdp()) {
      socket.send(address("10.99.0.1", UDP_PORT), new byte[8]);
    }

    assertThat(a.whoIs("10.28.0.2", PORT)).isEqualTo(b.identity("10.28.0.1", 0));
  }
}
