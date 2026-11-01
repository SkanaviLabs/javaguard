// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.netstack;

import static org.assertj.core.api.Assertions.assertThat;

import com.skanavi.javaguard.core.Device;
import com.skanavi.javaguard.core.PeerConfig;
import com.skanavi.javaguard.core.UdpBind;
import com.skanavi.javaguard.crypto.PrivateKey;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Two real devices over loopback UDP, each terminated by a netstack. */
class TunnelTest {
  @Test
  void pingUdpAndDnsThroughWireGuard() throws Exception {
    PrivateKey ka = PrivateKey.generate();
    PrivateKey kb = PrivateKey.generate();
    InetAddress lo = InetAddress.getLoopbackAddress();
    Netstack sa =
        Netstack.builder().address("10.7.0.1/24").address("fd07::1/64").dns("10.7.0.2").build();
    Netstack sb = Netstack.builder().address("10.7.0.2/24").address("fd07::2/64").build();
    try (Device a =
            Device.builder()
                .privateKey(ka)
                .bind(UdpBind.open(new InetSocketAddress(lo, 0)))
                .tun(sa)
                .build();
        Device b =
            Device.builder()
                .privateKey(kb)
                .bind(UdpBind.open(new InetSocketAddress(lo, 0)))
                .tun(sb)
                .build()) {
      a.addPeer(
          PeerConfig.builder(kb.publicKey())
              .endpoint(new InetSocketAddress(lo, b.listenPort()))
              .allowedIp("10.7.0.2/32")
              .allowedIp("fd07::2/128")
              .build());
      b.addPeer(
          PeerConfig.builder(ka.publicKey())
              .allowedIp("10.7.0.1/32")
              .allowedIp("fd07::1/128")
              .build());
      a.start();
      b.start();

      assertThat(sa.ping(InetAddress.ofLiteral("10.7.0.2"), Duration.ofSeconds(5))).isPresent();
      assertThat(sa.ping(InetAddress.ofLiteral("fd07::2"), Duration.ofSeconds(5))).isPresent();
      assertThat(sb.ping(InetAddress.ofLiteral("10.7.0.1"), Duration.ofSeconds(5))).isPresent();

      UdpSocket dns = sb.openUdp(53);
      Thread.ofVirtual()
          .start(
              () -> {
                try {
                  while (true) {
                    UdpSocket.Datagram q = dns.receive(Duration.ofSeconds(30));
                    if (q != null) {
                      dns.send(
                          q.source(),
                          DnsResolverTest.answer(
                              q.data(),
                              Map.of("svc.example", List.of("A 10.7.0.2", "AAAA fd07::2")),
                              3));
                    }
                  }
                } catch (Exception e) {
                  // closed
                }
              });
      assertThat(sa.dns().resolve("svc.example"))
          .containsExactly(InetAddress.ofLiteral("10.7.0.2"), InetAddress.ofLiteral("fd07::2"));
    }
  }
}
