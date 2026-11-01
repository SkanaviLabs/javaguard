// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.netstack;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.junit.jupiter.api.Tag;

/** Feeds arbitrary packets to the stack's inbound path; any exception is a finding. */
@Tag("fuzz")
class NetstackFuzzTest {
  private static final Netstack STACK =
      Netstack.builder().address("10.0.0.2/24").address("fd00::2/64").build();

  static {
    try {
      STACK.openUdp(7);
    } catch (java.io.IOException e) {
      throw new ExceptionInInitializerError(e);
    }
  }

  @FuzzTest(maxDuration = "60s")
  void inboundPacketsNeverThrow(FuzzedDataProvider in) {
    byte[] p = in.consumeRemainingAsBytes();
    STACK.receive(p, p.length); // replies queue up and are then dropped; that is fine here
  }
}
