// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.crypto;

import static com.skanavi.javaguard.crypto.Hex.hex;
import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.assertj.core.api.Assertions.assertThat;

import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.Size;
import org.bouncycastle.crypto.digests.Blake2sDigest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.jupiter.api.Test;

class KdfTest {
  @Property(tries = 300)
  void hmacMatchesBouncyCastle(
      @ForAll @Size(max = 100) byte[] key, @ForAll @Size(max = 300) byte[] data) {
    HMac bc = new HMac(new Blake2sDigest(256));
    bc.init(new KeyParameter(key));
    bc.update(data, 0, data.length);
    byte[] expected = new byte[32];
    bc.doFinal(expected, 0);
    assertThat(HmacBlake2s.hmac(key, data)).isEqualTo(expected);
  }

  @Property(tries = 200)
  void kdfFollowsHkdfDefinition(@ForAll @Size(32) byte[] key, @ForAll @Size(max = 64) byte[] in) {
    byte[] prk = HmacBlake2s.hmac(key, in);
    byte[] t1 = HmacBlake2s.hmac(prk, new byte[] {1});
    byte[] t2 = HmacBlake2s.hmac(prk, t1, new byte[] {2});
    byte[] t3 = HmacBlake2s.hmac(prk, t2, new byte[] {3});
    byte[][] out = Kdf.kdf3(key, in);
    assertThat(out).isDeepEqualTo(new byte[][] {t1, t2, t3});
    assertThat(Kdf.kdf2(key, in)).isDeepEqualTo(new byte[][] {t1, t2});
    assertThat(Kdf.kdf1(key, in)).isEqualTo(t1);
  }

  /** The handshake's initial chaining key and hash, as hard-coded in boringtun and others. */
  @Test
  void wireGuardInitialChainingKeyAndHash() {
    byte[] ck = Blake2s.hash("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".getBytes(US_ASCII));
    byte[] h = Blake2s.hash(ck, "WireGuard v1 zx2c4 Jason@zx2c4.com".getBytes(US_ASCII));
    assertThat(hex(ck))
        .isEqualTo("60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36");
    assertThat(hex(h))
        .isEqualTo("2211b361081ac566691243db458ad5322d9c6c662293e8b70ee19c65ba079ef3");
  }

  @Test
  void hmacInstanceRequiresInit() {
    HmacBlake2s mac = new HmacBlake2s();
    org.assertj.core.api.Assertions.assertThatThrownBy(() -> mac.update(new byte[1]))
        .isInstanceOf(IllegalStateException.class);
    mac.init(new byte[32]).update(new byte[1]).doFinal();
    org.assertj.core.api.Assertions.assertThatThrownBy(mac::doFinal)
        .isInstanceOf(IllegalStateException.class);
  }
}
