// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.netstack;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.HexFormat;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.Size;
import org.junit.jupiter.api.Test;

class DnsMessageTest {
  @Test
  void encodesQueries() {
    assertThat(HexFormat.of().formatHex(DnsMessage.query(0x1234, "a.bc", 1)))
        .isEqualTo("123401000001000000000000" + "0161026263" + "00" + "0001" + "0001");
  }

  @Test
  void rejectsInvalidNames() {
    for (String n :
        new String[] {
          "", "a..b", "x".repeat(64) + ".com", "has space.com", ("a.".repeat(127)) + "aa"
        }) {
      assertThatThrownBy(() -> DnsMessage.query(1, n, 1))
          .as(n)
          .isInstanceOf(IllegalArgumentException.class);
    }
  }

  @Test
  void detectsCompressionLoops() {
    byte[] m = new byte[14];
    m[12] = (byte) 0xc0;
    m[13] = 12; // points at itself
    assertThatThrownBy(() -> DnsMessage.readName(m, new int[] {12}))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Property(tries = 2000)
  void parsingGarbageNeverThrows(@ForAll @Size(max = 600) byte[] garbage) {
    DnsMessage.parse(garbage, 0, "example.com", 1);
    if (garbage.length > 2) {
      DnsMessage.parse(
          garbage, ((garbage[0] & 0xff) << 8) | (garbage[1] & 0xff), "example.com", 28);
    }
  }
}
