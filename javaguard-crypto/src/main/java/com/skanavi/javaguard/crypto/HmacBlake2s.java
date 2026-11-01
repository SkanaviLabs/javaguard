// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.crypto;

import java.util.Arrays;

/**
 * HMAC (RFC 2104) over BLAKE2s-256, as used by the WireGuard KDF. Note that this is HMAC
 * construction around unkeyed BLAKE2s, not BLAKE2s keyed mode.
 *
 * <p>Usage: {@link #init(byte[])}, any number of {@link #update(byte[])} calls, then {@link
 * #doFinal(byte[], int)}. Not thread-safe.
 */
public final class HmacBlake2s {
  /** Output length in bytes. */
  public static final int MAC_LENGTH = Blake2s.MAX_OUTPUT_LENGTH;

  private final Blake2s inner = new Blake2s(MAC_LENGTH);
  private final Blake2s outer = new Blake2s(MAC_LENGTH);
  private final byte[] pad = new byte[Blake2s.BLOCK_LENGTH];
  private final byte[] innerHash = new byte[MAC_LENGTH];
  private boolean initialized;

  /** Creates an uninitialized instance; call {@link #init(byte[])} before use. */
  public HmacBlake2s() {}

  /** Starts a new MAC computation with {@code key}. Keys longer than 64 bytes are hashed first. */
  public HmacBlake2s init(byte[] key) {
    byte[] k = key.length > Blake2s.BLOCK_LENGTH ? Blake2s.hash(key) : key;
    Arrays.fill(pad, (byte) 0);
    System.arraycopy(k, 0, pad, 0, k.length);
    inner.reset();
    outer.reset();
    for (int i = 0; i < pad.length; i++) {
      pad[i] ^= 0x36;
    }
    inner.update(pad);
    for (int i = 0; i < pad.length; i++) {
      pad[i] ^= 0x36 ^ 0x5c;
    }
    outer.update(pad);
    Arrays.fill(pad, (byte) 0);
    if (k != key) {
      Arrays.fill(k, (byte) 0);
    }
    initialized = true;
    return this;
  }

  /** Absorbs all of {@code in}. */
  public HmacBlake2s update(byte[] in) {
    return update(in, 0, in.length);
  }

  /** Absorbs {@code len} bytes of {@code in} starting at {@code off}. */
  public HmacBlake2s update(byte[] in, int off, int len) {
    checkInitialized();
    inner.update(in, off, len);
    return this;
  }

  /** Writes the 32-byte MAC to {@code out[off..]}. A new {@link #init(byte[])} is needed after. */
  public void doFinal(byte[] out, int off) {
    checkInitialized();
    inner.digest(innerHash, 0);
    outer.update(innerHash);
    outer.digest(out, off);
    Arrays.fill(innerHash, (byte) 0);
    inner.destroy();
    outer.destroy();
    initialized = false;
  }

  /** Returns the 32-byte MAC as a new array. A new {@link #init(byte[])} is needed after. */
  public byte[] doFinal() {
    byte[] out = new byte[MAC_LENGTH];
    doFinal(out, 0);
    return out;
  }

  /** One-shot {@code HMAC(key, inputs[0] || inputs[1] || ...)}. */
  public static byte[] hmac(byte[] key, byte[]... inputs) {
    HmacBlake2s mac = new HmacBlake2s().init(key);
    for (byte[] in : inputs) {
      mac.update(in);
    }
    return mac.doFinal();
  }

  private void checkInitialized() {
    if (!initialized) {
      throw new IllegalStateException("init(key) must be called first");
    }
  }
}
