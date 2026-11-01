// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.netstack;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import java.time.Duration;
import org.junit.jupiter.api.Tag;

/**
 * Feeds valid-checksum TCP segments with arbitrary fields to a stack with a listener and an open
 * connection; any exception is a finding.
 */
@Tag("fuzz")
class TcpFuzzTest {
  private static final Netstack STACK = Netstack.builder().address("10.0.0.2/24").build();
  private static final byte[] PEER = {10, 0, 0, 1};
  private static final byte[] LOCAL = {10, 0, 0, 2};

  static {
    try {
      STACK.listenTcp(80);
    } catch (java.io.IOException e) {
      throw new ExceptionInInitializerError(e);
    }
  }

  @FuzzTest(maxDuration = "60s")
  void segmentsNeverThrow(FuzzedDataProvider in) {
    int srcPort = in.pickValue(new int[] {40000, 40001, in.consumeInt(1, 65535)});
    int dstPort = in.pickValue(new int[] {80, in.consumeInt(1, 65535)});
    int seq = in.consumeInt();
    int ack = in.consumeInt();
    int flags = in.consumeInt(0, 63);
    int window = in.consumeInt(0, 65535);
    int mss = in.consumeBoolean() ? in.consumeInt(0, 65535) : -1;
    int scale = in.consumeBoolean() ? in.consumeInt(0, 255) : -1;
    byte[] data = in.consumeBytes(in.consumeInt(0, 1400));
    byte[] p =
        TcpSegment.build(
            PEER,
            LOCAL,
            srcPort,
            dstPort,
            seq,
            ack,
            flags,
            window,
            mss,
            scale,
            data,
            0,
            data.length,
            1);
    STACK.receive(p, p.length);
    byte[] raw = in.consumeRemainingAsBytes();
    STACK.receive(raw, raw.length);
    Duration.ZERO.isZero();
  }
}
