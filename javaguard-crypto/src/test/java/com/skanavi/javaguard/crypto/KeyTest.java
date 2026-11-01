// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class KeyTest {
  @Test
  void base64AndHexRoundTrip() {
    PrivateKey k = PrivateKey.generate();
    assertThat(PrivateKey.fromBase64(k.toBase64())).isEqualTo(k);
    assertThat(PrivateKey.fromHex(k.toHex())).isEqualTo(k);
    assertThat(k.toBase64()).hasSize(44);
    assertThat(k.toHex()).hasSize(64);
  }

  @Test
  void keysOfDifferentKindsAreNeverEqual() {
    byte[] b = new byte[32];
    assertThat(PublicKey.fromBytes(b)).isNotEqualTo(PresharedKey.fromBytes(b));
    assertThat(PresharedKey.fromBytes(b)).isEqualTo(PresharedKey.NONE);
  }

  @Test
  void secretsAreRedacted() {
    PrivateKey k = PrivateKey.generate();
    assertThat(k.toString()).doesNotContain(k.toBase64()).contains("redacted");
    assertThat(PresharedKey.generate().toString()).contains("redacted");
    assertThat(k.publicKey().toString()).contains(k.publicKey().toBase64());
  }

  @Test
  void rejectsMalformedInput() {
    assertThatThrownBy(() -> PublicKey.fromBase64("AAAA"))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> PublicKey.fromBase64("not base64!"))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> PublicKey.fromHex("zz".repeat(32)))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> PublicKey.fromBytes(new byte[31]))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void bytesAreDefensivelyCopied() {
    byte[] b = new byte[32];
    PublicKey k = PublicKey.fromBytes(b);
    b[0] = 1;
    k.toBytes()[1] = 1;
    assertThat(k.isZero()).isTrue();
  }

  @Test
  void bothSidesDeriveTheSameSharedSecret() throws Exception {
    PrivateKey a = PrivateKey.generate();
    PrivateKey b = PrivateKey.generate();
    assertThat(a.sharedSecret(b.publicKey())).isEqualTo(b.sharedSecret(a.publicKey()));
  }
}
