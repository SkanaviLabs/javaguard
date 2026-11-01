// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.junit.jupiter.api.Tag;

/** Differential fuzzing against Bouncy Castle. Run with {@code ./gradlew fuzz}. */
@Tag("fuzz")
class Blake2sFuzzTest {
  @FuzzTest(maxDuration = "60s")
  void matchesBouncyCastle(FuzzedDataProvider in) {
    int outLen = in.consumeInt(1, 32);
    byte[] key = in.consumeBytes(32);
    int chunk = in.consumeInt(1, 130);
    byte[] data = in.consumeRemainingAsBytes();
    Blake2s b = new Blake2s(outLen, key);
    for (int off = 0; off < data.length; off += chunk) {
      b.update(data, off, Math.min(chunk, data.length - off));
    }
    assertThat(b.digest()).isEqualTo(Blake2sTest.bouncyCastle(key, outLen, data));
  }
}
