// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * An IPv4 or IPv6 network prefix such as {@code 10.0.0.0/24} or {@code ::/0}. Host bits are cleared
 * on construction, so {@code 10.0.0.7/24} equals {@code 10.0.0.0/24}.
 *
 * @param address the network address, host bits zero
 * @param length the prefix length in bits
 */
public record IpPrefix(InetAddress address, int length) {
  /** Validates the length and clears host bits. */
  public IpPrefix {
    int max = address.getAddress().length * 8;
    if (length < 0 || length > max) {
      throw new IllegalArgumentException("prefix length " + length + " out of range 0.." + max);
    }
    byte[] b = address.getAddress();
    for (int i = 0; i < b.length; i++) {
      int keep = Math.max(0, Math.min(8, length - i * 8));
      b[i] &= (byte) (0xff00 >>> keep);
    }
    try {
      address = InetAddress.getByAddress(b);
    } catch (UnknownHostException e) {
      throw new AssertionError(e);
    }
  }

  /**
   * Parses {@code address/length}, or a bare address meaning a single host. Only literal addresses
   * are accepted; no name resolution happens.
   */
  public static IpPrefix parse(String text) {
    String s = text.strip();
    int slash = s.indexOf('/');
    InetAddress address;
    try {
      address = InetAddress.ofLiteral(slash < 0 ? s : s.substring(0, slash));
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("invalid IP prefix: " + text, e);
    }
    int max = address.getAddress().length * 8;
    int length;
    try {
      length = slash < 0 ? max : Integer.parseInt(s.substring(slash + 1));
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException("invalid IP prefix length: " + text, e);
    }
    return new IpPrefix(address, length);
  }

  /** Whether this is an IPv4 prefix. */
  public boolean isIpv4() {
    return address instanceof Inet4Address;
  }

  @Override
  public String toString() {
    return Addresses.format(address) + "/" + length;
  }
}
