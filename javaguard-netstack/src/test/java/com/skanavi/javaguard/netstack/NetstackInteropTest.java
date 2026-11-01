// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.netstack;

import static com.skanavi.javaguard.core.interop.WireGuardContainer.CONTAINER_IP6;
import static com.skanavi.javaguard.core.interop.WireGuardContainer.JAVAGUARD_IP6;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.skanavi.javaguard.core.Device;
import com.skanavi.javaguard.core.PeerConfig;
import com.skanavi.javaguard.core.UdpBind;
import com.skanavi.javaguard.core.interop.Docker;
import com.skanavi.javaguard.core.interop.WireGuardContainer;
import com.skanavi.javaguard.core.interop.WireGuardContainer.Implementation;
import com.skanavi.javaguard.crypto.PrivateKey;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Duration;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * A device terminated by a {@link Netstack} talks to a reference WireGuard peer in Docker: ICMP in
 * both directions, UDP echo through socat, and DNS through dnsmasq, over IPv4 and IPv6.
 */
@Tag("interop")
class NetstackInteropTest {
  private static final InetAddress CONTAINER4 = InetAddress.ofLiteral("10.9.0.2");
  private static final InetAddress CONTAINER6 = InetAddress.ofLiteral(CONTAINER_IP6);

  @BeforeAll
  static void requireDocker() throws IOException {
    assumeTrue(Docker.available(), "Docker is not available");
    Docker.buildImage();
  }

  @ParameterizedTest
  @EnumSource(Implementation.class)
  void pingUdpAndDnsAgainstALinuxPeer(Implementation impl) throws Exception {
    PrivateKey key = PrivateKey.generate();
    Netstack stack =
        Netstack.builder()
            .address("10.9.0.1/24")
            .address(JAVAGUARD_IP6 + "/64")
            .dns(CONTAINER4)
            .build();
    try (WireGuardContainer peer = new WireGuardContainer(impl, key.publicKey(), null);
        Device device = Device.builder().privateKey(key).bind(UdpBind.open(0)).tun(stack).build()) {
      peer.exec(
          "socat UDP4-LISTEN:7000,fork,reuseaddr EXEC:cat >/dev/null 2>&1 &"
              + " socat UDP6-LISTEN:7000,fork,reuseaddr,ipv6only=1 EXEC:cat >/dev/null 2>&1 &"
              + " dnsmasq --no-resolv --no-hosts --user=root --listen-address=10.9.0.2"
              + " --bind-interfaces --host-record=test.example,10.9.0.77,fd00:9::77"
              + " --cname=alias.example,test.example"); // --cname needs a host-record target
      device.addPeer(
          PeerConfig.builder(peer.publicKey())
              .endpoint(peer.endpoint())
              .allowedIp("10.9.0.0/24")
              .allowedIp("fd00:9::/64")
              .build());
      device.start();

      // ICMP, both directions and both families.
      assertThat(stack.ping(CONTAINER4, Duration.ofSeconds(10))).as("ping 10.9.0.2").isPresent();
      assertThat(stack.ping(CONTAINER6, Duration.ofSeconds(5))).as("ping fd00:9::2").isPresent();
      assertThat(peer.tryExec("ping -c 2 -W 3 10.9.0.1").exitCode()).isZero();
      assertThat(peer.tryExec("ping -6 -c 2 -W 3 " + JAVAGUARD_IP6).exitCode()).isZero();

      // UDP echo through socat.
      for (InetAddress server : new InetAddress[] {CONTAINER4, CONTAINER6}) {
        byte[] payload = ("echo via " + server.getHostAddress()).repeat(20).getBytes();
        assertThat(udpEcho(stack, new InetSocketAddress(server, 7000), payload))
            .as("UDP echo from %s", server)
            .isEqualTo(payload);
      }

      // DNS through dnsmasq, including a CNAME.
      assertThat(stack.dns().resolve("test.example"))
          .containsExactly(InetAddress.ofLiteral("10.9.0.77"), InetAddress.ofLiteral("fd00:9::77"));
      assertThat(stack.dns().resolve("alias.example"))
          .containsExactly(InetAddress.ofLiteral("10.9.0.77"), InetAddress.ofLiteral("fd00:9::77"));
    }
  }

  /** Sends until echoed (socat may still be starting); returns the reply payload or null. */
  private static byte[] udpEcho(Netstack stack, InetSocketAddress server, byte[] payload)
      throws Exception {
    try (UdpSocket socket = stack.openUdp()) {
      for (int attempt = 0; attempt < 10; attempt++) {
        socket.send(server, payload);
        UdpSocket.Datagram reply = socket.receive(Duration.ofSeconds(1));
        if (reply != null && reply.source().equals(server)) {
          return reply.data();
        }
      }
      return null;
    }
  }
}
