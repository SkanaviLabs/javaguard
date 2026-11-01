// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.netstack;

import static org.assertj.core.api.Assertions.assertThat;

import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.IntRange;
import net.jqwik.api.constraints.Size;

class ChecksumTest {
  @Property(tries = 2000)
  void wordAtATimeMatchesTheRfc1071Definition(
      @ForAll @Size(max = 3000) byte[] data, @ForAll @IntRange(max = 7) int offset) {
    int off = Math.min(offset, data.length);
    int len = data.length - off;
    assertThat(Checksum.finish(Checksum.add(12345, data, off, len)))
        .isEqualTo(Checksum.finish(naive(12345, data, off, len)));
  }

  private static long naive(long sum, byte[] b, int off, int len) {
    for (int i = 0; i < len; i += 2) {
      int hi = b[off + i] & 0xff;
      int lo = i + 1 < len ? b[off + i + 1] & 0xff : 0;
      sum += (hi << 8) | lo;
    }
    return sum;
  }
}
