// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.netstack;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayOutputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class DnsResolverTest {
  private Netstack client;
  private Netstack server;

  @AfterEach
  void tearDown() {
    client.close();
    server.close();
  }

  /** Starts a fake server on 10.0.0.53 answering from {@code zone}; returns the client stack. */
  private void start(Map<String, List<String>> zone, int rcodeForUnknown, String... dnsServers)
      throws Exception {
    Netstack.Builder b = Netstack.builder().address("10.0.0.2/24").address("fd00::2/64");
    for (String s : dnsServers) {
      b.dns(s);
    }
    client = b.searchDomains(List.of("corp.example")).build();
    server = Netstack.builder().address("10.0.0.53/24").address("10.0.0.54/24").build();
    Wire.connect(client, server);
    UdpSocket socket = server.openUdp(53);
    Thread.ofVirtual()
        .start(
            () -> {
              try {
                while (true) {
                  UdpSocket.Datagram q = socket.receive(Duration.ofSeconds(30));
                  if (q != null) {
                    socket.send(q.source(), answer(q.data(), zone, rcodeForUnknown));
                  }
                }
              } catch (Exception e) {
                // closed
              }
            });
  }

  @Test
  void resolvesIpv4AndIpv6() throws Exception {
    start(
        Map.of("host.example", List.of("A 10.1.1.1", "A 10.1.1.2", "AAAA fd00::7")),
        3,
        "10.0.0.53");
    assertThat(client.dns().resolve("host.example"))
        .containsExactly(
            InetAddress.ofLiteral("10.1.1.1"),
            InetAddress.ofLiteral("10.1.1.2"),
            InetAddress.ofLiteral("fd00::7"));
  }

  @Test
  void followsCnameChains() throws Exception {
    start(
        Map.of(
            "www.example",
            List.of(
                "CNAME edge.example",
                "CNAME-OF edge.example cdn.example",
                "A-OF cdn.example 10.2.2.2")),
        3,
        "10.0.0.53");
    assertThat(client.dns().resolve("www.example"))
        .containsExactly(InetAddress.ofLiteral("10.2.2.2"));
  }

  @Test
  void nxdomainFails() throws Exception {
    start(Map.of(), 3, "10.0.0.53");
    assertThatThrownBy(() -> client.dns().resolve("missing.example"))
        .isInstanceOf(UnknownHostException.class)
        .hasMessageContaining("no such domain");
  }

  @Test
  void usesSearchDomainsForShortNames() throws Exception {
    start(Map.of("wiki.corp.example", List.of("A 10.3.3.3")), 3, "10.0.0.53");
    assertThat(client.dns().resolve("wiki")).containsExactly(InetAddress.ofLiteral("10.3.3.3"));
    assertThatThrownBy(() -> client.dns().resolve("wiki."))
        .isInstanceOf(UnknownHostException.class);
  }

  @Test
  void failsOverToTheNextServer() throws Exception {
    // 10.0.0.99 never answers; the fake server only listens on .53.
    start(Map.of("host.example", List.of("A 10.4.4.4")), 3, "10.0.0.99", "10.0.0.53");
    client.dns().timeout(Duration.ofMillis(100));
    assertThat(client.dns().resolve("host.example"))
        .containsExactly(InetAddress.ofLiteral("10.4.4.4"));
  }

  @Test
  void serverFailureMovesToTheNextServer() throws Exception {
    start(Map.of(), 2, "10.0.0.53");
    client.dns().timeout(Duration.ofMillis(100));
    assertThatThrownBy(() -> client.dns().resolve("any.example"))
        .isInstanceOf(UnknownHostException.class)
        .hasMessageContaining("rcode 2");
  }

  @Test
  void literalsNeedNoServer() throws Exception {
    start(Map.of(), 3);
    assertThat(client.dns().resolve("192.0.2.1"))
        .containsExactly(InetAddress.ofLiteral("192.0.2.1"));
    assertThatThrownBy(() -> client.dns().resolve("host.example"))
        .hasMessageContaining("no DNS servers");
  }

  /**
   * Builds a response. Zone entries: "A ip", "AAAA ip", "CNAME target" for the queried name, and
   * "CNAME-OF owner target" / "A-OF owner ip" for other names in the answer section.
   */
  static byte[] answer(byte[] query, Map<String, List<String>> zone, int rcodeForUnknown) {
    int[] pos = {12};
    String name = DnsMessage.readName(query, pos);
    int qtype = IpPacket.u16(query, pos[0]);
    int questionEnd = pos[0] + 4;
    List<String> records = zone.get(name);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.write(query[0]);
    out.write(query[1]);
    out.write(0x81); // QR, RD
    out.write(0x80 | (records == null ? rcodeForUnknown : 0)); // RA, rcode
    out.write(0);
    out.write(1);
    java.util.List<byte[]> rrs = new java.util.ArrayList<>();
    if (records != null) {
      for (String r : records) {
        String[] f = r.split(" ");
        switch (f[0]) {
          case "A" -> {
            if (qtype == 1) rrs.add(rr(pointer(), 1, InetAddress.ofLiteral(f[1]).getAddress()));
          }
          case "AAAA" -> {
            if (qtype == 28) rrs.add(rr(pointer(), 28, InetAddress.ofLiteral(f[1]).getAddress()));
          }
          case "CNAME" -> rrs.add(rr(pointer(), 5, name(f[1])));
          case "CNAME-OF" -> rrs.add(rr(name(f[1]), 5, name(f[2])));
          case "A-OF" -> {
            if (qtype == 1) rrs.add(rr(name(f[1]), 1, InetAddress.ofLiteral(f[2]).getAddress()));
          }
          default -> throw new IllegalArgumentException(r);
        }
      }
    }
    out.write(0);
    out.write(rrs.size());
    out.writeBytes(new byte[4]);
    out.write(query, 12, questionEnd - 12);
    rrs.forEach(out::writeBytes);
    return out.toByteArray();
  }

  private static byte[] pointer() {
    return new byte[] {(byte) 0xc0, 12}; // compression pointer to the question name
  }

  private static byte[] name(String n) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    DnsMessage.writeName(out, n);
    return out.toByteArray();
  }

  private static byte[] rr(byte[] owner, int type, byte[] rdata) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.writeBytes(owner);
    out.write(0);
    out.write(type);
    out.write(0);
    out.write(1);
    out.writeBytes(new byte[] {0, 0, 0, 60});
    out.write(rdata.length >>> 8);
    out.write(rdata.length);
    out.writeBytes(rdata);
    return out.toByteArray();
  }
}
