// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class IpPrefixTest {
  @Test
  void parsesAndCanonicalizes() {
    assertThat(IpPrefix.parse("10.0.0.7/24")).hasToString("10.0.0.0/24");
    assertThat(IpPrefix.parse("10.1.2.3")).hasToString("10.1.2.3/32");
    assertThat(IpPrefix.parse("10.255.255.255/9")).hasToString("10.128.0.0/9");
    assertThat(IpPrefix.parse("::/0")).hasToString("::/0");
    assertThat(IpPrefix.parse("fd00:0:0:1::7/64")).hasToString("fd00:0:0:1::/64");
    assertThat(IpPrefix.parse("fd00::1/64").isIpv4()).isFalse();
    assertThat(IpPrefix.parse("10.0.0.7/24")).isEqualTo(IpPrefix.parse("10.0.0.0/24"));
  }

  @Test
  void hostAddressesKeepHostBits() {
    HostAddress h = HostAddress.parse("10.0.0.7/24");
    assertThat(h).hasToString("10.0.0.7/24");
    assertThat(h.network()).isEqualTo(IpPrefix.parse("10.0.0.0/24"));
    assertThat(HostAddress.parse("fd00::5")).hasToString("fd00::5/128");
    assertThatThrownBy(() -> HostAddress.parse("10.0.0.1/33"))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void rejectsInvalidInput() {
    assertThatThrownBy(() -> IpPrefix.parse("10.0.0.0/33"))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> IpPrefix.parse("example.com/8"))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> IpPrefix.parse("10.0.0.0/x"))
        .isInstanceOf(IllegalArgumentException.class);
  }
}
