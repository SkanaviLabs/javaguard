// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class TransportTest {
  @Test
  void padsToSixteenWithinMtu() {
    assertThat(Transport.paddedLength(0, 1420)).isZero();
    assertThat(Transport.paddedLength(1, 1420)).isEqualTo(16);
    assertThat(Transport.paddedLength(16, 1420)).isEqualTo(16);
    assertThat(Transport.paddedLength(1415, 1420)).isEqualTo(1420); // 1424 would exceed the MTU
    assertThat(Transport.paddedLength(1420, 1420)).isEqualTo(1420);
  }

  @Test
  void readsIpLengthsAndRejectsGarbage() {
    byte[] v4 = Ipv4.packet(new byte[4], new byte[4], new byte[10]);
    byte[] padded = java.util.Arrays.copyOf(v4, 48);
    assertThat(Transport.ipLength(padded)).isEqualTo(30);
    padded[3] = (byte) 200; // claims more than present
    assertThat(Transport.ipLength(padded)).isEqualTo(-1);
    assertThat(Transport.ipLength(new byte[] {0x60})).isEqualTo(-1);
    assertThat(Transport.ipLength(new byte[] {0x10, 0, 0, 0})).isEqualTo(-1);
  }
}
