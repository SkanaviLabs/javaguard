// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.crypto;

import java.security.SecureRandom;

/** A symmetric pre-shared key mixed into the handshake. {@link #toString()} never reveals it. */
public final class PresharedKey extends Key {
  /** The all-zero key WireGuard uses when no pre-shared key is configured. */
  public static final PresharedKey NONE = new PresharedKey(new byte[LENGTH]);

  private PresharedKey(byte[] bytes) {
    super(bytes);
  }

  /** Generates a random key, equivalent to {@code wg genpsk}. */
  public static PresharedKey generate() {
    byte[] b = new byte[LENGTH];
    new SecureRandom().nextBytes(b);
    return new PresharedKey(b);
  }

  /** Wraps raw bytes (copied). */
  public static PresharedKey fromBytes(byte[] bytes) {
    return new PresharedKey(bytes);
  }

  /** Parses the base64 form. */
  public static PresharedKey fromBase64(String text) {
    return new PresharedKey(decodeBase64(text));
  }

  /** Parses the hex form. */
  public static PresharedKey fromHex(String text) {
    return new PresharedKey(decodeHex(text));
  }

  @Override
  public String toString() {
    return isZero() ? "PresharedKey[none]" : "PresharedKey[redacted]";
  }
}
