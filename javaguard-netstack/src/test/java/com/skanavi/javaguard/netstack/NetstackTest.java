// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.netstack;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.skanavi.javaguard.core.HostAddress;
import java.net.BindException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.channels.ClosedChannelException;
import java.time.Duration;
import java.util.Arrays;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class NetstackTest {
  private static final Duration WAIT = Duration.ofSeconds(2);
  private Netstack a;
  private Netstack b;

  @BeforeEach
  void setUp() {
    a = Netstack.builder().address("10.0.0.1/24").address("fd00::1/64").build();
    b = Netstack.builder().address("10.0.0.2/24").address("fd00::2/64").build();
    Wire.connect(a, b);
  }

  @AfterEach
  void tearDown() {
    a.close();
    b.close();
  }

  @ParameterizedTest
  @ValueSource(strings = {"10.0.0.2", "fd00::2"})
  void pingsAreAnswered(String target) throws Exception {
    assertThat(a.ping(InetAddress.ofLiteral(target), WAIT)).isPresent();
    assertThat(b.ping(InetAddress.ofLiteral(target.replace("2", "1")), WAIT)).isPresent();
  }

  @Test
  void pingToNobodyTimesOut() throws Exception {
    assertThat(a.ping(InetAddress.ofLiteral("10.0.0.99"), Duration.ofMillis(200))).isEmpty();
  }

  @ParameterizedTest
  @ValueSource(strings = {"10.0.0.2", "fd00::2"})
  void udpRoundTrip(String server) throws Exception {
    try (UdpSocket echo = b.openUdp(7000);
        UdpSocket client = a.openUdp()) {
      Thread.ofVirtual()
          .start(
              () -> {
                try {
                  UdpSocket.Datagram d = echo.receive(WAIT);
                  echo.send(d.source(), d.data());
                } catch (Exception e) {
                  throw new RuntimeException(e);
                }
              });
      InetSocketAddress target = new InetSocketAddress(InetAddress.ofLiteral(server), 7000);
      byte[] payload = new byte[1000];
      Arrays.fill(payload, (byte) 7);
      client.send(target, payload);
      UdpSocket.Datagram reply = client.receive(WAIT);
      assertThat(reply).isNotNull();
      assertThat(reply.source()).isEqualTo(target);
      assertThat(reply.data()).isEqualTo(payload);
    }
  }

  @Test
  void enforcesMtuWithoutFragmentation() throws Exception {
    try (UdpSocket s = a.openUdp()) {
      InetSocketAddress v4 = new InetSocketAddress(InetAddress.ofLiteral("10.0.0.2"), 9);
      InetSocketAddress v6 = new InetSocketAddress(InetAddress.ofLiteral("fd00::2"), 9);
      s.send(v4, new byte[1420 - 28]);
      s.send(v6, new byte[1420 - 48]);
      assertThatThrownBy(() -> s.send(v4, new byte[1420 - 27]))
          .isInstanceOf(IllegalArgumentException.class);
      assertThatThrownBy(() -> s.send(v6, new byte[1420 - 47]))
          .isInstanceOf(IllegalArgumentException.class);
    }
  }

  @Test
  void portsAreExclusiveAndReleasedOnClose() throws Exception {
    UdpSocket s = a.openUdp(5353);
    assertThatThrownBy(() -> a.openUdp(5353)).isInstanceOf(BindException.class);
    s.close();
    assertThatThrownBy(() -> s.receive(WAIT)).isInstanceOf(ClosedChannelException.class);
    a.openUdp(5353).close();
  }

  @Test
  void requiresAnAddressOfTheTargetFamily() throws Exception {
    Netstack v4only = Netstack.builder().address("10.0.0.3/32").build();
    try (UdpSocket s = v4only.openUdp()) {
      assertThatThrownBy(
              () -> s.send(new InetSocketAddress(InetAddress.ofLiteral("fd00::2"), 1), new byte[1]))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("IPv6");
    }
  }

  @Test
  void dropsMalformedAndMisaddressedPackets() throws Exception {
    BlockingQueue<UdpSocket.Datagram> got = new ArrayBlockingQueue<>(10);
    Netstack c = Netstack.builder().address("10.0.0.2/24").address("fd00::2/64").build();
    try (UdpSocket s = c.openUdp(7)) {
      Thread.ofVirtual()
          .start(
              () -> {
                try {
                  while (true) {
                    UdpSocket.Datagram d = s.receive(Duration.ofSeconds(5));
                    if (d != null) {
                      got.add(d);
                    }
                  }
                } catch (Exception e) {
                  // closed
                }
              });
      byte[] good = udpPacket(a, "10.0.0.2");
      c.write(good, 0, good.length);
      assertThat(got.poll(2, TimeUnit.SECONDS)).isNotNull();

      byte[] badUdp = good.clone();
      badUdp[good.length - 1] ^= 1; // payload change breaks the UDP checksum
      byte[] badIp = good.clone();
      badIp[8] ^= 1; // TTL change breaks the IPv4 header checksum
      byte[] fragment = good.clone();
      fragment[6] |= 0x20; // MF
      byte[] truncated = Arrays.copyOf(good, good.length - 1);
      byte[] wrongDst = udpPacket(a, "10.0.0.9");
      byte[] v6NoChecksum = udpPacket(a, "fd00::2");
      v6NoChecksum[46] = 0;
      v6NoChecksum[47] = 0;
      for (byte[] p : new byte[][] {badUdp, badIp, fragment, truncated, wrongDst, v6NoChecksum}) {
        c.write(p, 0, p.length);
      }
      byte[] goodV6 = udpPacket(a, "fd00::2");
      c.write(goodV6, 0, goodV6.length);
      UdpSocket.Datagram next = got.poll(2, TimeUnit.SECONDS);
      assertThat(next.source().getAddress()).isEqualTo(InetAddress.ofLiteral("fd00::1"));
      assertThat(got.poll(200, TimeUnit.MILLISECONDS)).isNull();
    } finally {
      c.close();
    }
  }

  @Test
  void readReturnsMinusOneAfterClose() {
    Netstack c = Netstack.builder().address("10.0.0.5/32").build();
    c.close();
    assertThat(c.read(new byte[100], 0, 100)).isEqualTo(-1);
  }

  /** Captures the packet {@code from} emits for a UDP datagram to {@code to}:7. */
  private static byte[] udpPacket(Netstack from, String to) throws Exception {
    Netstack capture =
        Netstack.builder()
            .addresses(
                from.addresses().stream()
                    .map(addr -> new HostAddress(addr, addr.getAddress().length * 8))
                    .toList())
            .build();
    try (UdpSocket s = capture.openUdp(1234)) {
      s.send(new InetSocketAddress(InetAddress.ofLiteral(to), 7), "payload".getBytes());
      byte[] buf = new byte[2000];
      int n = capture.read(buf, 0, buf.length);
      return Arrays.copyOf(buf, n);
    } finally {
      capture.close();
    }
  }
}
