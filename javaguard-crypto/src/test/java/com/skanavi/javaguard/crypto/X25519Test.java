// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.crypto;

import static com.skanavi.javaguard.crypto.Hex.bytes;
import static com.skanavi.javaguard.crypto.Hex.hex;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.InvalidKeyException;
import java.security.SecureRandom;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.Size;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

class X25519Test {
  @Test
  void rfc7748Section5_2() throws Exception {
    byte[] out =
        X25519.sharedSecret(
            bytes("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
            bytes("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"));
    assertThat(hex(out))
        .isEqualTo("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
  }

  @Test
  void rfc7748Section6_1() throws Exception {
    byte[] alice = bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    byte[] bob = bytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    assertThat(hex(X25519.publicKey(alice)))
        .isEqualTo("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    assertThat(hex(X25519.publicKey(bob)))
        .isEqualTo("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    String shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
    assertThat(hex(X25519.sharedSecret(alice, X25519.publicKey(bob)))).isEqualTo(shared);
    assertThat(hex(X25519.sharedSecret(bob, X25519.publicKey(alice)))).isEqualTo(shared);
  }

  /** Vectors from {@code wg genkey | wg pubkey}, including unclamped private keys. */
  @ParameterizedTest
  @CsvSource({
    "mAIjPGdAYMP6dA+q07O8WfStvd6NZcRN+eCgiwpgiVA=, I/+hdvOCCORVcQDMxNvNSJ6x4YlQU39yykcuVIBF+Co=",
    "6J+GK8CD+as/tlEboozGBSsx4JC2Av82NY8lDvgr5VM=, zJt6ZYtdRG8ooOSzfkBDYR5je3MHxTeMZFI2iJrRyhw=",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=, L+V9o0fNYkMVKNqsX7spBzD/9oSvxM/C7ZCZX1jLO3Q=",
    "//////////////////////////////////////////8=, hHwNLDdSNPNl5mCVUYejc1oPdhPRYJ06ak2MU66qWiI="
  })
  void matchesWgPubkey(String privateKey, String publicKey) {
    assertThat(PrivateKey.fromBase64(privateKey).publicKey().toBase64()).isEqualTo(publicKey);
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
      })
  void rejectsSmallOrderPoints(String point) {
    byte[] priv = X25519.generatePrivateKey(new SecureRandom());
    assertThatThrownBy(() -> X25519.sharedSecret(priv, bytes(point)))
        .isInstanceOf(InvalidKeyException.class);
  }

  @Property(tries = 100)
  void matchesBouncyCastle(@ForAll @Size(32) byte[] scalar, @ForAll @Size(32) byte[] u) {
    byte[] expected = new byte[32];
    boolean ok =
        org.bouncycastle.math.ec.rfc7748.X25519.calculateAgreement(scalar, 0, u, 0, expected, 0);
    if (ok) {
      try {
        assertThat(X25519.sharedSecret(scalar, u)).isEqualTo(expected);
      } catch (InvalidKeyException e) {
        throw new AssertionError("JDK rejected a point Bouncy Castle accepted", e);
      }
    } else {
      assertThatThrownBy(() -> X25519.sharedSecret(scalar, u))
          .isInstanceOf(InvalidKeyException.class);
    }
  }

  @Test
  void generatedKeysAreClamped() {
    byte[] k = X25519.generatePrivateKey(new SecureRandom());
    assertThat(k[0] & 7).isZero();
    assertThat(k[31] & 0x80).isZero();
    assertThat(k[31] & 0x40).isEqualTo(0x40);
  }
}
