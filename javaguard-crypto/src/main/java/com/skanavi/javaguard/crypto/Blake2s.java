// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.crypto;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Objects;

/**
 * BLAKE2s (RFC 7693), unkeyed or keyed, with 1 to 32 byte output. No salt or personalization, since
 * WireGuard does not use them.
 *
 * <p>Instances are reusable: {@link #digest(byte[], int)} resets the state, keeping the key. Not
 * thread-safe.
 */
public final class Blake2s {
  /** Block size in bytes. */
  public static final int BLOCK_LENGTH = 64;

  /** Maximum (and WireGuard {@code HASH}) output length in bytes. */
  public static final int MAX_OUTPUT_LENGTH = 32;

  /** Maximum key length in bytes. */
  public static final int MAX_KEY_LENGTH = 32;

  private static final VarHandle LE_INT =
      MethodHandles.byteArrayViewVarHandle(int[].class, ByteOrder.LITTLE_ENDIAN);

  private static final int[] IV = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
  };

  private static final byte[][] SIGMA = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}
  };

  private final int outLen;
  private final byte[] key;
  private final int[] h = new int[8];
  private final int[] m = new int[16];
  private final int[] v = new int[16];
  private final byte[] buf = new byte[BLOCK_LENGTH];
  private int bufLen;
  private long counter;

  /** Creates an unkeyed BLAKE2s with the given output length (1..32). */
  public Blake2s(int outLen) {
    this(outLen, null);
  }

  /**
   * Creates a keyed BLAKE2s.
   *
   * @param outLen output length in bytes, 1..32
   * @param key key of 0..32 bytes, or {@code null} for unkeyed; copied
   */
  public Blake2s(int outLen, byte[] key) {
    if (outLen < 1 || outLen > MAX_OUTPUT_LENGTH) {
      throw new IllegalArgumentException("output length must be 1.." + MAX_OUTPUT_LENGTH);
    }
    if (key != null && key.length > MAX_KEY_LENGTH) {
      throw new IllegalArgumentException("key length must be at most " + MAX_KEY_LENGTH);
    }
    this.outLen = outLen;
    this.key = key == null || key.length == 0 ? null : key.clone();
    reset();
  }

  /** Output length in bytes. */
  public int outputLength() {
    return outLen;
  }

  /** Discards any input absorbed so far. */
  public void reset() {
    System.arraycopy(IV, 0, h, 0, 8);
    int keyLen = key == null ? 0 : key.length;
    h[0] ^= 0x01010000 ^ (keyLen << 8) ^ outLen;
    counter = 0;
    Arrays.fill(buf, (byte) 0);
    bufLen = 0;
    if (key != null) {
      System.arraycopy(key, 0, buf, 0, key.length);
      bufLen = BLOCK_LENGTH;
    }
  }

  /** Absorbs one byte. */
  public Blake2s update(byte b) {
    if (bufLen == BLOCK_LENGTH) {
      counter += BLOCK_LENGTH;
      compress(buf, 0, false);
      bufLen = 0;
    }
    buf[bufLen++] = b;
    return this;
  }

  /** Absorbs all of {@code in}. */
  public Blake2s update(byte[] in) {
    return update(in, 0, in.length);
  }

  /** Absorbs {@code len} bytes of {@code in} starting at {@code off}. */
  public Blake2s update(byte[] in, int off, int len) {
    Objects.checkFromIndexSize(off, len, in.length);
    if (len == 0) {
      return this;
    }
    int fill = BLOCK_LENGTH - bufLen;
    if (len > fill) {
      System.arraycopy(in, off, buf, bufLen, fill);
      counter += BLOCK_LENGTH;
      compress(buf, 0, false);
      bufLen = 0;
      off += fill;
      len -= fill;
      // Keep the final (possibly full) block buffered: it must be compressed with the last flag.
      while (len > BLOCK_LENGTH) {
        counter += BLOCK_LENGTH;
        compress(in, off, false);
        off += BLOCK_LENGTH;
        len -= BLOCK_LENGTH;
      }
    }
    System.arraycopy(in, off, buf, bufLen, len);
    bufLen += len;
    return this;
  }

  /** Absorbs the remaining bytes of {@code in}, advancing its position to its limit. */
  public Blake2s update(ByteBuffer in) {
    if (in.hasArray()) {
      update(in.array(), in.arrayOffset() + in.position(), in.remaining());
      in.position(in.limit());
      return this;
    }
    byte[] chunk = new byte[Math.min(in.remaining(), 4 * BLOCK_LENGTH)];
    while (in.hasRemaining()) {
      int n = Math.min(chunk.length, in.remaining());
      in.get(chunk, 0, n);
      update(chunk, 0, n);
    }
    return this;
  }

  /** Finishes the hash and returns it as a new array, then resets. */
  public byte[] digest() {
    byte[] out = new byte[outLen];
    digest(out, 0);
    return out;
  }

  /** Finishes the hash, writes {@link #outputLength()} bytes to {@code out[off..]}, then resets. */
  public void digest(byte[] out, int off) {
    Objects.checkFromIndexSize(off, outLen, out.length);
    counter += bufLen;
    Arrays.fill(buf, bufLen, BLOCK_LENGTH, (byte) 0);
    compress(buf, 0, true);
    byte[] full = new byte[MAX_OUTPUT_LENGTH];
    for (int i = 0; i < 8; i++) {
      LE_INT.set(full, i * 4, h[i]);
    }
    System.arraycopy(full, 0, out, off, outLen);
    Arrays.fill(full, (byte) 0);
    reset();
  }

  /** Zeroes the internal state. The key copy is also wiped, so the instance is unusable after. */
  public void destroy() {
    Arrays.fill(h, 0);
    Arrays.fill(m, 0);
    Arrays.fill(v, 0);
    Arrays.fill(buf, (byte) 0);
    if (key != null) {
      Arrays.fill(key, (byte) 0);
    }
  }

  /** WireGuard {@code HASH(input)}: unkeyed BLAKE2s-256 over the concatenation of the inputs. */
  public static byte[] hash(byte[]... inputs) {
    Blake2s b = new Blake2s(MAX_OUTPUT_LENGTH);
    for (byte[] in : inputs) {
      b.update(in);
    }
    return b.digest();
  }

  /** WireGuard {@code MAC(key, input)}: keyed BLAKE2s with a 16-byte output. */
  public static byte[] mac(byte[] key, byte[]... inputs) {
    Blake2s b = new Blake2s(16, key);
    for (byte[] in : inputs) {
      b.update(in);
    }
    byte[] out = b.digest();
    b.destroy();
    return out;
  }

  private void compress(byte[] block, int off, boolean last) {
    int[] m = this.m;
    int[] v = this.v;
    for (int i = 0; i < 16; i++) {
      m[i] = (int) LE_INT.get(block, off + i * 4);
    }
    System.arraycopy(h, 0, v, 0, 8);
    System.arraycopy(IV, 0, v, 8, 8);
    v[12] ^= (int) counter;
    v[13] ^= (int) (counter >>> 32);
    if (last) {
      v[14] = ~v[14];
    }
    for (int r = 0; r < 10; r++) {
      byte[] s = SIGMA[r];
      g(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
      g(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
      g(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
      g(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
      g(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
      g(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
      g(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
      g(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for (int i = 0; i < 8; i++) {
      h[i] ^= v[i] ^ v[i + 8];
    }
  }

  private static void g(int[] v, int a, int b, int c, int d, int x, int y) {
    v[a] = v[a] + v[b] + x;
    v[d] = Integer.rotateRight(v[d] ^ v[a], 16);
    v[c] = v[c] + v[d];
    v[b] = Integer.rotateRight(v[b] ^ v[c], 12);
    v[a] = v[a] + v[b] + y;
    v[d] = Integer.rotateRight(v[d] ^ v[a], 8);
    v[c] = v[c] + v[d];
    v[b] = Integer.rotateRight(v[b] ^ v[c], 7);
  }
}
