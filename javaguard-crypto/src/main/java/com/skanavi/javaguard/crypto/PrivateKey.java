// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.crypto;

import java.security.InvalidKeyException;
import java.security.SecureRandom;

/** A Curve25519 private key. {@link #toString()} never reveals the key. */
public final class PrivateKey extends Key {
  private PrivateKey(byte[] bytes) {
    super(bytes);
  }

  /** Generates a new clamped private key, equivalent to {@code wg genkey}. */
  public static PrivateKey generate() {
    return generate(new SecureRandom());
  }

  /** Generates a new clamped private key from {@code random}. */
  public static PrivateKey generate(SecureRandom random) {
    return new PrivateKey(X25519.generatePrivateKey(random));
  }

  /** Wraps raw bytes (copied, not clamped). */
  public static PrivateKey fromBytes(byte[] bytes) {
    return new PrivateKey(bytes);
  }

  /** Parses the base64 form. */
  public static PrivateKey fromBase64(String text) {
    return new PrivateKey(decodeBase64(text));
  }

  /** Parses the hex form. */
  public static PrivateKey fromHex(String text) {
    return new PrivateKey(decodeHex(text));
  }

  /** Derives the public key, equivalent to {@code wg pubkey}. */
  public PublicKey publicKey() {
    return PublicKey.fromBytes(X25519.publicKey(raw()));
  }

  /**
   * Computes the raw X25519 shared secret with {@code peer}.
   *
   * @throws InvalidKeyException if {@code peer} is a small-order point
   */
  public byte[] sharedSecret(PublicKey peer) throws InvalidKeyException {
    return X25519.sharedSecret(raw(), peer.raw());
  }

  @Override
  public String toString() {
    return "PrivateKey[redacted]";
  }
}
