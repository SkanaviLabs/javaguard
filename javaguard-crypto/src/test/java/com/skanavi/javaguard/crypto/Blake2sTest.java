// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.crypto;

import static com.skanavi.javaguard.crypto.Hex.bytes;
import static com.skanavi.javaguard.crypto.Hex.hex;
import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.assertj.core.api.Assertions.assertThat;

import java.nio.ByteBuffer;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.IntRange;
import net.jqwik.api.constraints.Size;
import org.bouncycastle.crypto.digests.Blake2sDigest;
import org.junit.jupiter.api.Test;

class Blake2sTest {
  @Test
  void rfc7693AppendixB() {
    assertThat(hex(Blake2s.hash("abc".getBytes(US_ASCII))))
        .isEqualTo("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
  }

  @Test
  void emptyInput() {
    assertThat(hex(Blake2s.hash()))
        .isEqualTo("69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9");
  }

  @Test
  void keyedEmptyInputMatchesReferenceKat() {
    byte[] key = bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    assertThat(hex(new Blake2s(32, key).digest()))
        .isEqualTo("48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49");
  }

  @Property(tries = 500)
  void matchesBouncyCastle(
      @ForAll @Size(max = 300) byte[] data,
      @ForAll @Size(max = 32) byte[] key,
      @ForAll @IntRange(min = 1, max = 32) int outLen) {
    byte[] expected = bouncyCastle(key, outLen, data);
    assertThat(new Blake2s(outLen, key).update(data).digest()).isEqualTo(expected);
  }

  @Property(tries = 300)
  void splitUpdatesMatchOneShot(
      @ForAll @Size(max = 400) byte[] data, @ForAll @IntRange(min = 1, max = 70) int chunk) {
    Blake2s b = new Blake2s(32);
    for (int off = 0; off < data.length; off += chunk) {
      b.update(data, off, Math.min(chunk, data.length - off));
    }
    assertThat(b.digest()).isEqualTo(Blake2s.hash(data));
  }

  @Property(tries = 100)
  void byteBufferUpdatesMatchArray(@ForAll @Size(max = 1000) byte[] data) {
    ByteBuffer direct = ByteBuffer.allocateDirect(data.length).put(data).flip();
    ByteBuffer heap = ByteBuffer.wrap(data);
    assertThat(new Blake2s(32).update(direct).digest()).isEqualTo(Blake2s.hash(data));
    assertThat(new Blake2s(32).update(heap).digest()).isEqualTo(Blake2s.hash(data));
    assertThat(direct.hasRemaining()).isFalse();
  }

  @Test
  void instanceIsReusableAfterDigestAndKeepsKey() {
    byte[] key = new byte[32];
    key[0] = 1;
    Blake2s b = new Blake2s(16, key);
    byte[] first = b.update(new byte[] {1, 2, 3}).digest();
    byte[] second = b.update(new byte[] {1, 2, 3}).digest();
    assertThat(second).isEqualTo(first).isEqualTo(Blake2s.mac(key, new byte[] {1, 2, 3}));
  }

  @Test
  void singleByteUpdatesMatch() {
    byte[] data = new byte[200];
    for (int i = 0; i < data.length; i++) {
      data[i] = (byte) i;
    }
    Blake2s b = new Blake2s(32);
    for (byte x : data) {
      b.update(x);
    }
    assertThat(b.digest()).isEqualTo(Blake2s.hash(data));
  }

  static byte[] bouncyCastle(byte[] key, int outLen, byte[] data) {
    Blake2sDigest d = new Blake2sDigest(key.length == 0 ? null : key, outLen, null, null);
    d.update(data, 0, data.length);
    byte[] out = new byte[outLen];
    d.doFinal(out, 0);
    return out;
  }
}
