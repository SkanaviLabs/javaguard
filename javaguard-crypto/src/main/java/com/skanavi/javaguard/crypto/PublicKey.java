// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.crypto;

/** A Curve25519 public key. */
public final class PublicKey extends Key {
  private PublicKey(byte[] bytes) {
    super(bytes);
  }

  /** Wraps raw bytes (copied). */
  public static PublicKey fromBytes(byte[] bytes) {
    return new PublicKey(bytes);
  }

  /** Parses the base64 form. */
  public static PublicKey fromBase64(String text) {
    return new PublicKey(decodeBase64(text));
  }

  /** Parses the hex form. */
  public static PublicKey fromHex(String text) {
    return new PublicKey(decodeHex(text));
  }

  @Override
  public String toString() {
    return "PublicKey[" + toBase64() + "]";
  }
}
