// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.netstack;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.InetAddress;
import org.junit.jupiter.api.Test;

class TcpSegmentTest {
  private static final byte[] A = InetAddress.ofLiteral("10.0.0.1").getAddress();
  private static final byte[] B = InetAddress.ofLiteral("10.0.0.2").getAddress();

  @Test
  void roundTripsWithOptions() {
    byte[] payload = "data".getBytes();
    byte[] p =
        TcpSegment.build(
            A,
            B,
            1234,
            80,
            0xfffffff0,
            7,
            TcpSegment.SYN | TcpSegment.ACK,
            65535,
            1380,
            3,
            payload,
            0,
            payload.length,
            1);
    TcpSegment s = TcpSegment.parse(IpPacket.parse(p, p.length));
    assertThat(s.srcPort()).isEqualTo(1234);
    assertThat(s.dstPort()).isEqualTo(80);
    assertThat(s.seq()).isEqualTo(0xfffffff0);
    assertThat(s.ack()).isEqualTo(7);
    assertThat(s.has(TcpSegment.SYN)).isTrue();
    assertThat(s.mss()).isEqualTo(1380);
    assertThat(s.windowScale()).isEqualTo(3);
    assertThat(s.sequenceLength()).isEqualTo(5);
    assertThat(new String(s.data(), s.dataOffset(), s.dataLength())).isEqualTo("data");
  }

  @Test
  void carriesSackOptions() {
    int[] blocks = {100, 200, 300, 400};
    byte[] p =
        TcpSegment.build(
            A, B, 1, 2, 3, 4, TcpSegment.ACK, 100, -1, -1, true, blocks, null, 0, 0, 1);
    TcpSegment s = TcpSegment.parse(IpPacket.parse(p, p.length));
    assertThat(s.sackPermitted()).isTrue();
    assertThat(s.sackBlocks()).containsExactly(100, 200, 300, 400);
  }

  @Test
  void rejectsCorruption() {
    byte[] p =
        TcpSegment.build(A, B, 1, 2, 3, 4, TcpSegment.ACK, 100, -1, -1, new byte[10], 0, 10, 1);
    p[p.length - 1] ^= 1;
    assertThat(TcpSegment.parse(IpPacket.parse(p, p.length))).isNull();
  }

  @Test
  void sequenceComparisonWraps() {
    assertThat(TcpSegment.lt(0xfffffff0, 5)).isTrue();
    assertThat(TcpSegment.lt(5, 0xfffffff0)).isFalse();
    assertThat(TcpSegment.le(5, 5)).isTrue();
  }

  @Test
  void ringBufferWrapsAround() {
    ByteRing r = new ByteRing(8);
    r.write(new byte[] {1, 2, 3, 4, 5, 6}, 0, 6);
    r.skip(5);
    assertThat(r.write(new byte[] {7, 8, 9, 10, 11, 12, 13, 14}, 0, 8)).isEqualTo(7);
    byte[] out = new byte[8];
    assertThat(r.read(out, 0, 8)).isEqualTo(8);
    assertThat(out).containsExactly(6, 7, 8, 9, 10, 11, 12, 13);
  }
}
