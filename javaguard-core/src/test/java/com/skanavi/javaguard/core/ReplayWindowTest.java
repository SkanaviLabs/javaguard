// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core;

import static org.assertj.core.api.Assertions.assertThat;

import com.skanavi.javaguard.core.noise.Protocol;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ReplayWindowTest {
  private static final long LIMIT = Protocol.REJECT_AFTER_MESSAGES;

  @Test
  void acceptsEachCounterOnce() {
    ReplayWindow w = new ReplayWindow();
    for (long i = 0; i < 20_000; i++) {
      assertThat(w.accept(i, LIMIT)).isTrue();
      assertThat(w.accept(i, LIMIT)).isFalse();
    }
  }

  @Test
  void acceptsReorderingWithinTheWindowOnly() {
    ReplayWindow w = new ReplayWindow();
    long size = ReplayWindow.windowSize();
    assertThat(w.accept(size + 10, LIMIT)).isTrue();
    assertThat(w.accept(10, LIMIT)).isTrue(); // exactly at the edge
    assertThat(w.accept(9, LIMIT)).isFalse(); // just beyond
    assertThat(w.accept(500, LIMIT)).isTrue();
    assertThat(w.accept(500, LIMIT)).isFalse();
  }

  @Test
  void bigJumpsClearStaleBits() {
    ReplayWindow w = new ReplayWindow();
    for (long i = 0; i < 100; i++) {
      w.accept(i, LIMIT);
    }
    long far = 1_000_000;
    assertThat(w.accept(far, LIMIT)).isTrue();
    // Counters congruent to old ones (same ring slots) must not look like replays.
    long alias = far - 128 * 64 + 64;
    assertThat(w.accept(alias, LIMIT)).isTrue();
  }

  @Test
  void enforcesTheLimitUnsigned() {
    ReplayWindow w = new ReplayWindow();
    assertThat(w.accept(LIMIT, LIMIT)).isFalse();
    assertThat(w.accept(-1L, LIMIT)).isFalse(); // 2^64 - 1
    assertThat(w.accept(LIMIT - 1, LIMIT)).isTrue();
    assertThat(w.accept(LIMIT - 2, LIMIT)).isTrue();
    assertThat(w.accept(0, LIMIT)).isFalse(); // far behind
  }

  @Test
  void matchesAReferenceModelUnderRandomTraffic() {
    Random r = new Random(42);
    ReplayWindow w = new ReplayWindow();
    Set<Long> seen = new HashSet<>();
    long max = -1;
    long size = ReplayWindow.windowSize();
    for (int i = 0; i < 200_000; i++) {
      long c = Math.max(0, max + r.nextInt(300) - 200);
      boolean expected = !seen.contains(c) && (max < 0 || c > max || max - c <= size);
      assertThat(w.accept(c, LIMIT)).as("counter %d after max %d", c, max).isEqualTo(expected);
      if (expected) {
        seen.add(c);
        max = Math.max(max, c);
      }
    }
  }
}
