// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class AddressesTest {
  @ParameterizedTest
  @CsvSource({
    "::, ::",
    "::1, ::1",
    "2001:db8:0:0:0:0:2:1, 2001:db8::2:1",
    "2001:db8:0:1:1:1:1:1, 2001:db8:0:1:1:1:1:1",
    "2001:0:0:1:0:0:0:1, 2001:0:0:1::1",
    "fe80::, fe80::",
    "1:0:0:2:0:0:0:3, 1:0:0:2::3",
    "10.1.2.3, 10.1.2.3"
  })
  void formatsCompressed(String in, String out) {
    assertThat(Addresses.format(InetAddress.ofLiteral(in))).isEqualTo(out);
  }

  @Test
  void endpointsRoundTrip() {
    for (String s : new String[] {"192.0.2.1:51820", "[2001:db8::1]:443"}) {
      InetSocketAddress e = Addresses.parseEndpoint(s);
      assertThat(Addresses.format(e)).isEqualTo(s);
    }
  }

  @Test
  void rejectsMalformedEndpoints() {
    for (String s :
        new String[] {
          "192.0.2.1", "2001:db8::1:80", "[::1]80", "host.example:1", "1.2.3.4:0", "1.2.3.4:x"
        }) {
      assertThatThrownBy(() -> Addresses.parseEndpoint(s))
          .as(s)
          .isInstanceOf(IllegalArgumentException.class);
    }
  }
}
