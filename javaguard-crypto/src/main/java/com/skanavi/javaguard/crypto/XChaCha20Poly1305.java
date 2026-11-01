// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.crypto;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;

/**
 * XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha) with a 24-byte nonce, used by WireGuard cookie
 * replies. HChaCha20 derives a subkey from the key and the first 16 nonce bytes; the remaining 8
 * bytes form the ChaCha20-Poly1305 nonce. Not thread-safe.
 */
public final class XChaCha20Poly1305 {
  /** Key length in bytes. */
  public static final int KEY_LENGTH = 32;

  /** Nonce length in bytes. */
  public static final int NONCE_LENGTH = 24;

  /** Authentication tag length in bytes. */
  public static final int TAG_LENGTH = ChaCha20Poly1305.TAG_LENGTH;

  private static final VarHandle LE_INT =
      MethodHandles.byteArrayViewVarHandle(int[].class, ByteOrder.LITTLE_ENDIAN);
  private static final VarHandle LE_LONG =
      MethodHandles.byteArrayViewVarHandle(long[].class, ByteOrder.LITTLE_ENDIAN);

  private final ChaCha20Poly1305 aead = new ChaCha20Poly1305();

  /** Creates an instance backed by a fresh JCA cipher. */
  public XChaCha20Poly1305() {}

  /** Encrypts {@code plaintext}, returning ciphertext with the 16-byte tag appended. */
  public byte[] seal(byte[] key, byte[] nonce, byte[] plaintext, byte[] aad) {
    checkNonce(nonce);
    byte[] subkey = hChaCha20(key, nonce);
    try {
      return aead.seal(subkey, (long) LE_LONG.get(nonce, 16), plaintext, aad);
    } finally {
      Arrays.fill(subkey, (byte) 0);
    }
  }

  /**
   * Decrypts and authenticates {@code ciphertext} (with tag appended).
   *
   * @throws AEADBadTagException if authentication fails
   */
  public byte[] open(byte[] key, byte[] nonce, byte[] ciphertext, byte[] aad)
      throws AEADBadTagException {
    checkNonce(nonce);
    byte[] subkey = hChaCha20(key, nonce);
    try {
      return aead.open(subkey, (long) LE_LONG.get(nonce, 16), ciphertext, aad);
    } finally {
      Arrays.fill(subkey, (byte) 0);
    }
  }

  /**
   * HChaCha20: derives a 32-byte subkey from a 32-byte key and the first 16 bytes of {@code nonce}.
   */
  public static byte[] hChaCha20(byte[] key, byte[] nonce) {
    if (key.length != KEY_LENGTH) {
      throw new IllegalArgumentException("key must be " + KEY_LENGTH + " bytes");
    }
    if (nonce.length < 16) {
      throw new IllegalArgumentException("nonce must be at least 16 bytes");
    }
    int[] x = new int[16];
    x[0] = 0x61707865;
    x[1] = 0x3320646e;
    x[2] = 0x79622d32;
    x[3] = 0x6b206574;
    for (int i = 0; i < 8; i++) {
      x[4 + i] = (int) LE_INT.get(key, i * 4);
    }
    for (int i = 0; i < 4; i++) {
      x[12 + i] = (int) LE_INT.get(nonce, i * 4);
    }
    for (int i = 0; i < 10; i++) {
      quarterRound(x, 0, 4, 8, 12);
      quarterRound(x, 1, 5, 9, 13);
      quarterRound(x, 2, 6, 10, 14);
      quarterRound(x, 3, 7, 11, 15);
      quarterRound(x, 0, 5, 10, 15);
      quarterRound(x, 1, 6, 11, 12);
      quarterRound(x, 2, 7, 8, 13);
      quarterRound(x, 3, 4, 9, 14);
    }
    byte[] out = new byte[32];
    for (int i = 0; i < 4; i++) {
      LE_INT.set(out, i * 4, x[i]);
      LE_INT.set(out, 16 + i * 4, x[12 + i]);
    }
    Arrays.fill(x, 0);
    return out;
  }

  private static void quarterRound(int[] x, int a, int b, int c, int d) {
    x[a] += x[b];
    x[d] = Integer.rotateLeft(x[d] ^ x[a], 16);
    x[c] += x[d];
    x[b] = Integer.rotateLeft(x[b] ^ x[c], 12);
    x[a] += x[b];
    x[d] = Integer.rotateLeft(x[d] ^ x[a], 8);
    x[c] += x[d];
    x[b] = Integer.rotateLeft(x[b] ^ x[c], 7);
  }

  private static void checkNonce(byte[] nonce) {
    if (nonce.length != NONCE_LENGTH) {
      throw new IllegalArgumentException("nonce must be " + NONCE_LENGTH + " bytes");
    }
  }
}
