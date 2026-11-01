// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.crypto;

import java.security.MessageDigest;

/** Comparisons whose running time does not depend on the contents of secret data. */
public final class ConstantTime {
  private ConstantTime() {}

  /**
   * Returns whether {@code a} and {@code b} are equal. Time depends only on the lengths, never on
   * where the arrays differ.
   */
  public static boolean equals(byte[] a, byte[] b) {
    return MessageDigest.isEqual(a, b);
  }

  /** Returns whether every byte of {@code a} is zero, without early exit. */
  public static boolean isZero(byte[] a) {
    int acc = 0;
    for (byte x : a) {
      acc |= x;
    }
    return acc == 0;
  }
}
