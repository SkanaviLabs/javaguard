// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.crypto;

import static com.skanavi.javaguard.crypto.Hex.hex;
import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;

class Tai64nTest {
  @Test
  void encodesWithTai64Offset() {
    byte[] stamp = Tai64n.encode(Instant.ofEpochSecond(0, 1));
    assertThat(hex(stamp)).isEqualTo("400000000000000a00000001");
    assertThat(Tai64n.decode(stamp)).isEqualTo(Instant.ofEpochSecond(0, 1));
  }

  @Test
  void nowWhitensNanoseconds() {
    Instant t = Instant.ofEpochSecond(1_700_000_000L, 123_456_789);
    byte[] stamp = Tai64n.now(Clock.fixed(t, ZoneOffset.UTC));
    Instant decoded = Tai64n.decode(stamp);
    assertThat(decoded.getEpochSecond()).isEqualTo(t.getEpochSecond());
    assertThat(decoded.getNano() % (1 << 24)).isZero();
    assertThat(decoded.getNano()).isLessThanOrEqualTo(t.getNano());
  }

  @Test
  void ordersByTime() {
    byte[] a = Tai64n.encode(Instant.ofEpochSecond(100, 999_999_999));
    byte[] b = Tai64n.encode(Instant.ofEpochSecond(101, 0));
    assertThat(Tai64n.isAfter(b, a)).isTrue();
    assertThat(Tai64n.isAfter(a, b)).isFalse();
    assertThat(Tai64n.isAfter(a, a.clone())).isFalse();
  }
}
