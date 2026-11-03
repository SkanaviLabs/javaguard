// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.tun;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import org.junit.jupiter.api.Test;

class IfReqTest {
  @Test
  void matchesTheLinux64BitLayout() {
    assertThat(IfReq.LAYOUT.byteSize()).isEqualTo(40);
    assertThat(IfReq.LAYOUT.byteAlignment()).isEqualTo(8);
  }

  @Test
  void encodesNameAndFlagsAtTheKernelsOffsets() {
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment s = IfReq.allocate(arena, "wg0", (short) 0x1001);
      byte[] raw = s.toArray(ValueLayout.JAVA_BYTE);
      assertThat(raw).hasSize(40);
      assertThat(new String(raw, 0, 3, java.nio.charset.StandardCharsets.US_ASCII))
          .isEqualTo("wg0");
      for (int i = 3; i < 16; i++) {
        assertThat(raw[i]).as("name byte %d", i).isZero();
      }
      // ifr_flags is a native-endian short at offset 16; both supported targets are little-endian.
      assertThat(raw[16]).isEqualTo((byte) 0x01);
      assertThat(raw[17]).isEqualTo((byte) 0x10);
      for (int i = 18; i < 40; i++) {
        assertThat(raw[i]).as("union byte %d", i).isZero();
      }
      assertThat(IfReq.name(s)).isEqualTo("wg0");
      assertThat(IfReq.flags(s)).isEqualTo((short) 0x1001);
    }
  }

  @Test
  void readsAFifteenCharacterNameWithoutTerminator() {
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment s = IfReq.allocate(arena, "abcdefghijklmno", (short) 0);
      assertThat(IfReq.name(s)).isEqualTo("abcdefghijklmno");
    }
  }

  @Test
  void rejectsNamesTheKernelWould() {
    for (String bad : new String[] {"abcdefghijklmnop", "a/b", "a:b", "a b", ".", ".."}) {
      assertThatThrownBy(() -> IfReq.encodeName(bad)).as(bad).hasMessageContaining("invalid");
    }
    assertThat(IfReq.encodeName("")).isEmpty();
    assertThat(IfReq.encodeName("jg%d")).hasSize(4);
  }
}
