// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core;

import java.net.Inet4Address;
import java.net.InetAddress;

/**
 * An interface address with its prefix length, such as {@code 10.0.0.2/24}, as in a wg-quick {@code
 * Address} line. Unlike {@link IpPrefix}, the host bits are kept.
 *
 * @param address the host address
 * @param prefixLength the length of the on-link prefix
 */
public record HostAddress(InetAddress address, int prefixLength) {
  /** Validates the prefix length. */
  public HostAddress {
    int max = address.getAddress().length * 8;
    if (prefixLength < 0 || prefixLength > max) {
      throw new IllegalArgumentException(
          "prefix length " + prefixLength + " out of range 0.." + max);
    }
  }

  /** Parses {@code address/length}, or a bare address meaning a full-length prefix. */
  public static HostAddress parse(String text) {
    IpPrefix network = IpPrefix.parse(text); // validates syntax and length
    String s = text.strip();
    int slash = s.indexOf('/');
    return new HostAddress(
        InetAddress.ofLiteral(slash < 0 ? s : s.substring(0, slash)), network.length());
  }

  /** Whether this is an IPv4 address. */
  public boolean isIpv4() {
    return address instanceof Inet4Address;
  }

  /** The network this address is on. */
  public IpPrefix network() {
    return new IpPrefix(address, prefixLength);
  }

  @Override
  public String toString() {
    return Addresses.format(address) + "/" + prefixLength;
  }
}
