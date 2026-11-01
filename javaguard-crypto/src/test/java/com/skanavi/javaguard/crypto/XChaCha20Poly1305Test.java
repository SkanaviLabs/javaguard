// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.crypto;

import static com.skanavi.javaguard.crypto.Hex.bytes;
import static com.skanavi.javaguard.crypto.Hex.hex;
import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import javax.crypto.AEADBadTagException;
import org.junit.jupiter.api.Test;

class XChaCha20Poly1305Test {
  private static final byte[] SUNSCREEN =
      ("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the"
              + " future, sunscreen would be it.")
          .getBytes(US_ASCII);

  /** draft-irtf-cfrg-xchacha-03, section 2.2.1. */
  @Test
  void hChaCha20Vector() {
    byte[] key = bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    byte[] nonce = bytes("000000090000004a0000000031415927");
    assertThat(hex(XChaCha20Poly1305.hChaCha20(key, nonce)))
        .isEqualTo("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc");
  }

  /** draft-irtf-cfrg-xchacha-03, appendix A.3.1. */
  @Test
  void aeadVector() throws Exception {
    byte[] key = bytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    byte[] nonce = bytes("404142434445464748494a4b4c4d4e4f5051525354555657");
    byte[] aad = bytes("50515253c0c1c2c3c4c5c6c7");
    String expected =
        "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb"
            + "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452"
            + "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9"
            + "21f9664c97637da9768812f615c68b13b52e"
            + "c0875924c1c7987947deafd8780acf49";
    XChaCha20Poly1305 aead = new XChaCha20Poly1305();
    byte[] sealed = aead.seal(key, nonce, SUNSCREEN, aad);
    assertThat(hex(sealed)).isEqualTo(expected);
    assertThat(aead.open(key, nonce, sealed, aad)).isEqualTo(SUNSCREEN);
  }

  @Test
  void rejectsTampering() {
    XChaCha20Poly1305 aead = new XChaCha20Poly1305();
    byte[] key = new byte[32];
    byte[] nonce = new byte[24];
    byte[] sealed = aead.seal(key, nonce, new byte[16], null);
    sealed[3] ^= 1;
    assertThatThrownBy(() -> aead.open(key, nonce, sealed, null))
        .isInstanceOf(AEADBadTagException.class);
  }
}
