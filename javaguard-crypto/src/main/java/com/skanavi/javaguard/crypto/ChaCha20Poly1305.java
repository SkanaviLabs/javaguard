// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.crypto;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * ChaCha20-Poly1305 (RFC 8439) with WireGuard's nonce layout: 32 zero bits followed by a 64-bit
 * little-endian counter. Backed by the JDK {@code ChaCha20-Poly1305} cipher.
 *
 * <p>The JDK refuses to encrypt twice with the same key and nonce on one instance; WireGuard never
 * does that legitimately, so such a call fails with {@link IllegalStateException}.
 *
 * <p>Ciphertext and plaintext may share a buffer at the same offset (in-place operation). Not
 * thread-safe.
 */
public final class ChaCha20Poly1305 {
  /** Key length in bytes. */
  public static final int KEY_LENGTH = 32;

  /** Authentication tag length in bytes. */
  public static final int TAG_LENGTH = 16;

  /** Nonce length in bytes. */
  public static final int NONCE_LENGTH = 12;

  private final Cipher cipher;
  private final byte[] nonce = new byte[NONCE_LENGTH];

  /** Creates an instance backed by a fresh JCA {@link Cipher}. */
  public ChaCha20Poly1305() {
    try {
      cipher = Cipher.getInstance("ChaCha20-Poly1305");
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("JDK lacks ChaCha20-Poly1305", e);
    }
  }

  /** Wraps a raw 32-byte key for use with this class. The array is copied. */
  public static SecretKey key(byte[] key) {
    if (key.length != KEY_LENGTH) {
      throw new IllegalArgumentException("key must be " + KEY_LENGTH + " bytes");
    }
    return new SecretKeySpec(key, "ChaCha20");
  }

  /** Encrypts {@code plaintext}, returning ciphertext with the 16-byte tag appended. */
  public byte[] seal(byte[] key, long counter, byte[] plaintext, byte[] aad) {
    return seal(key(key), counter, plaintext, aad);
  }

  /** Encrypts {@code plaintext}, returning ciphertext with the 16-byte tag appended. */
  public byte[] seal(SecretKey key, long counter, byte[] plaintext, byte[] aad) {
    byte[] out = new byte[plaintext.length + TAG_LENGTH];
    seal(key, counter, plaintext, 0, plaintext.length, out, 0, aad);
    return out;
  }

  /**
   * Encrypts {@code in[inOff..inOff+len)} into {@code out[outOff..]}.
   *
   * @return bytes written, always {@code len + 16}
   */
  public int seal(
      SecretKey key,
      long counter,
      byte[] in,
      int inOff,
      int len,
      byte[] out,
      int outOff,
      byte[] aad) {
    try {
      init(Cipher.ENCRYPT_MODE, key, counter, aad);
      return cipher.doFinal(in, inOff, len, out, outOff);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("ChaCha20-Poly1305 encryption failed", e);
    }
  }

  /**
   * Encrypts the remaining bytes of {@code in} into {@code out}, advancing both positions.
   *
   * @return bytes written, always {@code in.remaining() + 16}
   */
  public int seal(SecretKey key, long counter, ByteBuffer in, ByteBuffer out, byte[] aad) {
    try {
      init(Cipher.ENCRYPT_MODE, key, counter, aad);
      return cipher.doFinal(in, out);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("ChaCha20-Poly1305 encryption failed", e);
    }
  }

  /**
   * Decrypts and authenticates {@code ciphertext} (with tag appended).
   *
   * @throws AEADBadTagException if authentication fails
   */
  public byte[] open(byte[] key, long counter, byte[] ciphertext, byte[] aad)
      throws AEADBadTagException {
    return open(key(key), counter, ciphertext, aad);
  }

  /**
   * Decrypts and authenticates {@code ciphertext} (with tag appended).
   *
   * @throws AEADBadTagException if authentication fails
   */
  public byte[] open(SecretKey key, long counter, byte[] ciphertext, byte[] aad)
      throws AEADBadTagException {
    if (ciphertext.length < TAG_LENGTH) {
      throw new AEADBadTagException("ciphertext shorter than tag");
    }
    byte[] out = new byte[ciphertext.length - TAG_LENGTH];
    open(key, counter, ciphertext, 0, ciphertext.length, out, 0, aad);
    return out;
  }

  /**
   * Decrypts {@code in[inOff..inOff+len)} (ciphertext plus tag) into {@code out[outOff..]}.
   *
   * @return bytes written, always {@code len - 16}
   * @throws AEADBadTagException if authentication fails; {@code out} is then left untouched
   */
  public int open(
      SecretKey key,
      long counter,
      byte[] in,
      int inOff,
      int len,
      byte[] out,
      int outOff,
      byte[] aad)
      throws AEADBadTagException {
    if (len < TAG_LENGTH) {
      throw new AEADBadTagException("ciphertext shorter than tag");
    }
    try {
      init(Cipher.DECRYPT_MODE, key, counter, aad);
      return cipher.doFinal(in, inOff, len, out, outOff);
    } catch (AEADBadTagException e) {
      throw e;
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("ChaCha20-Poly1305 decryption failed", e);
    }
  }

  /**
   * Decrypts the remaining bytes of {@code in} (ciphertext plus tag) into {@code out}, advancing
   * both positions on success.
   *
   * @return bytes written, always {@code in.remaining() - 16}
   * @throws AEADBadTagException if authentication fails
   */
  public int open(SecretKey key, long counter, ByteBuffer in, ByteBuffer out, byte[] aad)
      throws AEADBadTagException {
    if (in.remaining() < TAG_LENGTH) {
      throw new AEADBadTagException("ciphertext shorter than tag");
    }
    try {
      init(Cipher.DECRYPT_MODE, key, counter, aad);
      return cipher.doFinal(in, out);
    } catch (AEADBadTagException e) {
      throw e;
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("ChaCha20-Poly1305 decryption failed", e);
    }
  }

  private void init(int mode, SecretKey key, long counter, byte[] aad)
      throws GeneralSecurityException {
    for (int i = 0; i < 8; i++) {
      nonce[4 + i] = (byte) (counter >>> (8 * i));
    }
    cipher.init(mode, key, new IvParameterSpec(nonce));
    if (aad != null && aad.length > 0) {
      cipher.updateAAD(aad);
    }
  }
}
