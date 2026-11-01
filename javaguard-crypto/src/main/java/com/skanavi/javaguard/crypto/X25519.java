// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.crypto;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.SecureRandom;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;
import java.util.Arrays;
import javax.crypto.KeyAgreement;

/**
 * X25519 Diffie-Hellman (RFC 7748) over raw 32-byte keys, backed by the JDK {@code XDH} provider.
 *
 * <p>Keys are little-endian byte strings as on the WireGuard wire. Private scalars are clamped by
 * the computation itself, so unclamped private keys give the same results as clamped ones.
 */
public final class X25519 {
  /** Length of private keys, public keys and shared secrets in bytes. */
  public static final int KEY_LENGTH = 32;

  private static final byte[] BASE_POINT = new byte[KEY_LENGTH];

  static {
    BASE_POINT[0] = 9;
  }

  private X25519() {}

  /** Returns a new random private key, clamped the way {@code wg genkey} does. */
  public static byte[] generatePrivateKey(SecureRandom random) {
    byte[] k = new byte[KEY_LENGTH];
    random.nextBytes(k);
    clamp(k);
    return k;
  }

  /** Clamps a private scalar in place: clears bits 0-2 and 255, sets bit 254. */
  public static void clamp(byte[] privateKey) {
    checkLength(privateKey);
    privateKey[0] &= (byte) 248;
    privateKey[31] &= 127;
    privateKey[31] |= 64;
  }

  /** Computes the public key {@code X25519(privateKey, 9)}. */
  public static byte[] publicKey(byte[] privateKey) {
    try {
      return scalarMult(privateKey, BASE_POINT);
    } catch (InvalidKeyException e) {
      throw new IllegalStateException("base point multiplication failed", e);
    }
  }

  /**
   * Computes the shared secret {@code X25519(privateKey, publicKey)}.
   *
   * @throws InvalidKeyException if the result is all zeros, which happens when {@code publicKey} is
   *     a small-order point; the WireGuard handshake must then be rejected
   */
  public static byte[] sharedSecret(byte[] privateKey, byte[] publicKey)
      throws InvalidKeyException {
    return scalarMult(privateKey, publicKey);
  }

  private static byte[] scalarMult(byte[] scalar, byte[] u) throws InvalidKeyException {
    checkLength(scalar);
    checkLength(u);
    byte[] out;
    try {
      KeyFactory kf = KeyFactory.getInstance("XDH");
      var sk = kf.generatePrivate(new XECPrivateKeySpec(NamedParameterSpec.X25519, scalar.clone()));
      var pk = kf.generatePublic(new XECPublicKeySpec(NamedParameterSpec.X25519, decodeU(u)));
      KeyAgreement ka = KeyAgreement.getInstance("XDH");
      ka.init(sk);
      ka.doPhase(pk, true);
      out = ka.generateSecret();
    } catch (InvalidKeyException e) {
      // The JDK rejects small-order inputs itself ("Point has small order").
      throw e;
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("XDH provider failure", e);
    }
    if (ConstantTime.isZero(out)) {
      throw new InvalidKeyException("X25519 result is zero (small-order public key)");
    }
    return out;
  }

  /** Decodes a u-coordinate per RFC 7748 section 5: little-endian, top bit masked off. */
  private static BigInteger decodeU(byte[] u) {
    byte[] be = new byte[KEY_LENGTH];
    for (int i = 0; i < KEY_LENGTH; i++) {
      be[i] = u[KEY_LENGTH - 1 - i];
    }
    be[0] &= 0x7f;
    BigInteger value = new BigInteger(1, be);
    Arrays.fill(be, (byte) 0);
    return value;
  }

  private static void checkLength(byte[] key) {
    if (key.length != KEY_LENGTH) {
      throw new IllegalArgumentException("X25519 keys must be " + KEY_LENGTH + " bytes");
    }
  }
}
