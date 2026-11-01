// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.ByteBuffer;
import javax.crypto.AEADBadTagException;
import javax.crypto.SecretKey;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.Size;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.jupiter.api.Test;

class ChaCha20Poly1305Test {
  private final ChaCha20Poly1305 aead = new ChaCha20Poly1305();

  @Property(tries = 300)
  void matchesBouncyCastleWithWireGuardNonce(
      @ForAll @Size(32) byte[] key,
      @ForAll long counter,
      @ForAll @Size(max = 1500) byte[] plaintext,
      @ForAll @Size(max = 64) byte[] aad)
      throws Exception {
    byte[] expected = bouncyCastleSeal(key, counter, plaintext, aad);
    byte[] sealed = new ChaCha20Poly1305().seal(key, counter, plaintext, aad);
    assertThat(sealed).isEqualTo(expected);
    assertThat(aead.open(key, counter, sealed, aad)).isEqualTo(plaintext);
  }

  @Test
  void rejectsTamperedCiphertextTagAadAndCounter() throws Exception {
    byte[] key = new byte[32];
    byte[] sealed = aead.seal(key, 7, "hello".getBytes(), new byte[] {1});
    for (int i = 0; i < sealed.length; i++) {
      byte[] bad = sealed.clone();
      bad[i] ^= 1;
      assertThatThrownBy(() -> aead.open(key, 7, bad, new byte[] {1}))
          .isInstanceOf(AEADBadTagException.class);
    }
    assertThatThrownBy(() -> aead.open(key, 7, sealed, new byte[] {2}))
        .isInstanceOf(AEADBadTagException.class);
    assertThatThrownBy(() -> aead.open(key, 8, sealed, new byte[] {1}))
        .isInstanceOf(AEADBadTagException.class);
    assertThatThrownBy(() -> aead.open(key, 7, new byte[15], null))
        .isInstanceOf(AEADBadTagException.class);
  }

  @Test
  void emptyPlaintextProducesTagOnly() throws Exception {
    byte[] sealed = aead.seal(new byte[32], 0, new byte[0], null);
    assertThat(sealed).hasSize(ChaCha20Poly1305.TAG_LENGTH);
    assertThat(aead.open(new byte[32], 0, sealed, null)).isEmpty();
  }

  @Test
  void inPlaceArrayRoundTrip() throws Exception {
    SecretKey key = ChaCha20Poly1305.key(new byte[32]);
    byte[] plaintext = new byte[1420];
    for (int i = 0; i < plaintext.length; i++) {
      plaintext[i] = (byte) i;
    }
    // 16-byte header room in front, tag room behind, like a WireGuard transport packet.
    byte[] packet = new byte[16 + plaintext.length + 16];
    System.arraycopy(plaintext, 0, packet, 16, plaintext.length);
    int n = aead.seal(key, 42, packet, 16, plaintext.length, packet, 16, null);
    assertThat(n).isEqualTo(plaintext.length + 16);
    byte[] expected = aead.open(key, 42, java.util.Arrays.copyOfRange(packet, 16, 16 + n), null);
    assertThat(expected).isEqualTo(plaintext);
    int m = aead.open(key, 42, packet, 16, n, packet, 16, null);
    assertThat(m).isEqualTo(plaintext.length);
    assertThat(java.util.Arrays.copyOfRange(packet, 16, 16 + m)).isEqualTo(plaintext);
  }

  @Test
  void directByteBufferRoundTrip() throws Exception {
    SecretKey key = ChaCha20Poly1305.key(new byte[32]);
    ByteBuffer in = ByteBuffer.allocateDirect(100).put(new byte[100]).flip();
    ByteBuffer sealed = ByteBuffer.allocateDirect(116);
    assertThat(aead.seal(key, 1, in, sealed, null)).isEqualTo(116);
    sealed.flip();
    ByteBuffer opened = ByteBuffer.allocateDirect(100);
    assertThat(aead.open(key, 1, sealed, opened, null)).isEqualTo(100);
    assertThat(opened.position()).isEqualTo(100);
  }

  @Test
  void nonceUsesLittleEndianCounterAfterFourZeroBytes() throws Exception {
    byte[] key = new byte[32];
    long counter = 0x0102030405060708L;
    byte[] nonce = {0, 0, 0, 0, 8, 7, 6, 5, 4, 3, 2, 1};
    var bc = new org.bouncycastle.crypto.modes.ChaCha20Poly1305();
    bc.init(true, new AEADParameters(new KeyParameter(key), 128, nonce, null));
    byte[] expected = new byte[16];
    bc.doFinal(expected, bc.processBytes(new byte[0], 0, 0, expected, 0));
    assertThat(aead.seal(key, counter, new byte[0], null)).isEqualTo(expected);
  }

  static byte[] bouncyCastleSeal(byte[] key, long counter, byte[] plaintext, byte[] aad)
      throws Exception {
    byte[] nonce = new byte[12];
    for (int i = 0; i < 8; i++) {
      nonce[4 + i] = (byte) (counter >>> (8 * i));
    }
    var bc = new org.bouncycastle.crypto.modes.ChaCha20Poly1305();
    bc.init(true, new AEADParameters(new KeyParameter(key), 128, nonce, aad));
    byte[] out = new byte[bc.getOutputSize(plaintext.length)];
    int n = bc.processBytes(plaintext, 0, plaintext.length, out, 0);
    bc.doFinal(out, n);
    return out;
  }
}
