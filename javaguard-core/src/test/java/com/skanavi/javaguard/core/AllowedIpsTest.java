// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.Test;

class AllowedIpsTest {
  @Test
  void longestPrefixWins() {
    AllowedIps<String> t = new AllowedIps<>();
    t.insert(IpPrefix.parse("0.0.0.0/0"), "default");
    t.insert(IpPrefix.parse("10.0.0.0/8"), "ten");
    t.insert(IpPrefix.parse("10.1.0.0/16"), "ten-one");
    t.insert(IpPrefix.parse("10.1.2.3/32"), "host");
    assertThat(lookup(t, "10.1.2.3")).isEqualTo("host");
    assertThat(lookup(t, "10.1.2.4")).isEqualTo("ten-one");
    assertThat(lookup(t, "10.2.0.1")).isEqualTo("ten");
    assertThat(lookup(t, "192.168.0.1")).isEqualTo("default");
    assertThat(lookup(t, "::1")).isNull();
  }

  @Test
  void ipv6() {
    AllowedIps<String> t = new AllowedIps<>();
    t.insert(IpPrefix.parse("fd00::/8"), "ula");
    t.insert(IpPrefix.parse("fd00:1::/32"), "site");
    assertThat(lookup(t, "fd00:1::5")).isEqualTo("site");
    assertThat(lookup(t, "fd99::5")).isEqualTo("ula");
    assertThat(lookup(t, "2001:db8::1")).isNull();
  }

  @Test
  void reinsertingMovesOwnershipAndRemoveAllPrunes() {
    AllowedIps<String> t = new AllowedIps<>();
    t.insert(IpPrefix.parse("10.0.0.0/24"), "a");
    t.insert(IpPrefix.parse("10.0.1.0/24"), "a");
    t.insert(IpPrefix.parse("10.0.0.0/24"), "b");
    assertThat(t.prefixes("a")).containsExactly(IpPrefix.parse("10.0.1.0/24"));
    assertThat(t.prefixes("b")).containsExactly(IpPrefix.parse("10.0.0.0/24"));
    t.removeAll("b");
    assertThat(lookup(t, "10.0.0.1")).isNull();
    assertThat(lookup(t, "10.0.1.1")).isEqualTo("a");
  }

  @Test
  void matchesNaiveReferenceOnRandomData() {
    Random r = new Random(7);
    AllowedIps<Integer> t = new AllowedIps<>();
    List<IpPrefix> prefixes = new ArrayList<>();
    List<Integer> owners = new ArrayList<>();
    for (int i = 0; i < 500; i++) {
      byte[] addr = new byte[4];
      r.nextBytes(addr);
      IpPrefix p = new IpPrefix(address(addr), r.nextInt(33));
      int owner = r.nextInt(20);
      t.insert(p, owner);
      int existing = prefixes.indexOf(p);
      if (existing >= 0) {
        prefixes.remove(existing);
        owners.remove(existing);
      }
      prefixes.add(p);
      owners.add(owner);
    }
    for (int i = 0; i < 20_000; i++) {
      byte[] addr = new byte[4];
      r.nextBytes(addr);
      Integer expected = null;
      int bestLen = -1;
      for (int j = 0; j < prefixes.size(); j++) {
        IpPrefix p = prefixes.get(j);
        if (p.length() > bestLen && p.equals(new IpPrefix(address(addr), p.length()))) {
          bestLen = p.length();
          expected = owners.get(j);
        }
      }
      assertThat(t.lookup(addr, 0, 4)).isEqualTo(expected);
    }
  }

  private static String lookup(AllowedIps<String> t, String ip) {
    byte[] a = InetAddress.ofLiteral(ip).getAddress();
    return t.lookup(a, 0, a.length);
  }

  private static InetAddress address(byte[] b) {
    try {
      return InetAddress.getByAddress(b);
    } catch (java.net.UnknownHostException e) {
      throw new AssertionError(e);
    }
  }
}
