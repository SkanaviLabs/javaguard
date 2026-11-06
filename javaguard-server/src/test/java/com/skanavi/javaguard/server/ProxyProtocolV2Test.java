// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.server;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.skanavi.javaguard.crypto.PrivateKey;
import com.skanavi.javaguard.crypto.PublicKey;
import java.io.ByteArrayOutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

class ProxyProtocolV2Test {
  private static final PublicKey KEY = PrivateKey.generate().publicKey();

  private static InetSocketAddress at(String ip, int port) {
    return new InetSocketAddress(InetAddress.ofLiteral(ip), port);
  }

  private static byte[] hex(String s) {
    return HexFormat.of().parseHex(s.replace(" ", ""));
  }

  @Test
  void encodesIpv4() {
    ByteArrayOutputStream want = new ByteArrayOutputStream();
    want.writeBytes(hex("0D0A0D0A000D0A515549540A 21 11 002F"));
    want.writeBytes(hex("0A000002 0A000001 C000 01BB"));
    want.writeBytes(hex("E0 0020"));
    want.writeBytes(KEY.toBytes());

    assertThat(ProxyProtocolV2.encode(at("10.0.0.2", 49152), at("10.0.0.1", 443), KEY))
        .isEqualTo(want.toByteArray());
  }

  @Test
  void encodesIpv6() {
    byte[] header = ProxyProtocolV2.encode(at("fd00::2", 65535), at("fd00::1", 1), KEY);

    assertThat(header).hasSize(16 + 36 + 35);
    assertThat(header[13]).isEqualTo((byte) 0x21);
    assertThat(header[14]).isZero();
    assertThat(header[15]).isEqualTo((byte) (36 + 35));
    assertThat(header[16 + 32]).isEqualTo((byte) 0xFF);
    assertThat(header[16 + 33]).isEqualTo((byte) 0xFF);
  }

  @Test
  void refusesMixedFamilies() {
    assertThatThrownBy(() -> ProxyProtocolV2.encode(at("10.0.0.2", 1), at("fd00::1", 1), KEY))
        .isInstanceOf(IllegalArgumentException.class);
  }
}
