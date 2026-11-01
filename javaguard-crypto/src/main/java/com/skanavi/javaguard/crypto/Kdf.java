// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.crypto;

import java.util.Arrays;

/**
 * The WireGuard key derivation function: HKDF (RFC 5869) with HMAC-BLAKE2s, producing one to three
 * 32-byte outputs. Defined in the WireGuard whitepaper as {@code KDF_n(key, input)}.
 */
public final class Kdf {
  private Kdf() {}

  /** {@code KDF1(key, input)}. */
  public static byte[] kdf1(byte[] key, byte[] input) {
    return derive(key, input, 1)[0];
  }

  /** {@code KDF2(key, input)}, returning {@code [tau1, tau2]}. */
  public static byte[][] kdf2(byte[] key, byte[] input) {
    return derive(key, input, 2);
  }

  /** {@code KDF3(key, input)}, returning {@code [tau1, tau2, tau3]}. */
  public static byte[][] kdf3(byte[] key, byte[] input) {
    return derive(key, input, 3);
  }

  private static byte[][] derive(byte[] key, byte[] input, int n) {
    HmacBlake2s mac = new HmacBlake2s();
    byte[] prk = mac.init(key).update(input).doFinal();
    byte[][] out = new byte[n][];
    byte[] prev = new byte[0];
    for (int i = 0; i < n; i++) {
      mac.init(prk).update(prev).update(new byte[] {(byte) (i + 1)});
      out[i] = mac.doFinal();
      prev = out[i];
    }
    Arrays.fill(prk, (byte) 0);
    return out;
  }
}
