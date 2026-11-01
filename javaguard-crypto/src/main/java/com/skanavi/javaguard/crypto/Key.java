// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.crypto;

import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;

/**
 * An immutable 32-byte WireGuard key. Text forms are base64 (as in {@code wg} configs) and
 * lowercase hex (as in the cross-platform UAPI). Equality is constant-time.
 */
public abstract sealed class Key permits PrivateKey, PublicKey, PresharedKey {
  /** Key length in bytes. */
  public static final int LENGTH = 32;

  private final byte[] bytes;

  Key(byte[] bytes) {
    if (bytes.length != LENGTH) {
      throw new IllegalArgumentException("keys must be " + LENGTH + " bytes, got " + bytes.length);
    }
    this.bytes = bytes.clone();
  }

  /** Returns a copy of the raw key bytes. */
  public final byte[] toBytes() {
    return bytes.clone();
  }

  /** Returns the 44-character base64 form. */
  public final String toBase64() {
    return Base64.getEncoder().encodeToString(bytes);
  }

  /** Returns the 64-character lowercase hex form. */
  public final String toHex() {
    return HexFormat.of().formatHex(bytes);
  }

  /** Returns whether all bytes are zero (an unset key in UAPI terms). */
  public final boolean isZero() {
    return ConstantTime.isZero(bytes);
  }

  /** Raw bytes without copying, for use within this module only. */
  final byte[] raw() {
    return bytes;
  }

  @Override
  public final boolean equals(Object o) {
    return o != null && o.getClass() == getClass() && ConstantTime.equals(bytes, ((Key) o).bytes);
  }

  @Override
  public final int hashCode() {
    return Arrays.hashCode(bytes);
  }

  static byte[] decodeBase64(String text) {
    byte[] b;
    try {
      b = Base64.getDecoder().decode(text.strip());
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("invalid base64 key", e);
    }
    if (b.length != LENGTH) {
      throw new IllegalArgumentException("base64 key must decode to " + LENGTH + " bytes");
    }
    return b;
  }

  static byte[] decodeHex(String text) {
    String s = text.strip();
    if (s.length() != 2 * LENGTH) {
      throw new IllegalArgumentException("hex key must be " + 2 * LENGTH + " characters");
    }
    try {
      return HexFormat.of().parseHex(s);
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("invalid hex key", e);
    }
  }
}
