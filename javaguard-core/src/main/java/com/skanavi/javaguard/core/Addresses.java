// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;

/** Text forms of addresses: IPv6 compressed per RFC 5952, endpoints as {@code [v6]:port}. */
public final class Addresses {
  private Addresses() {}

  /** Formats an IP address without name lookup; IPv6 in compressed lowercase form. */
  public static String format(InetAddress address) {
    if (!(address instanceof Inet6Address v6)) {
      return address.getHostAddress();
    }
    byte[] b = v6.getAddress();
    int[] groups = new int[8];
    for (int i = 0; i < 8; i++) {
      groups[i] = ((b[2 * i] & 0xff) << 8) | (b[2 * i + 1] & 0xff);
    }
    int bestStart = -1;
    int bestLen = 1; // only runs of two or more zero groups are compressed
    for (int i = 0; i < 8; ) {
      if (groups[i] != 0) {
        i++;
        continue;
      }
      int j = i;
      while (j < 8 && groups[j] == 0) {
        j++;
      }
      if (j - i > bestLen) {
        bestStart = i;
        bestLen = j - i;
      }
      i = j;
    }
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < 8; i++) {
      if (i == bestStart) {
        sb.append(i == 0 ? "::" : ":");
        i += bestLen - 1;
        continue;
      }
      sb.append(Integer.toHexString(groups[i]));
      if (i < 7) {
        sb.append(':');
      }
    }
    if (v6.getScopeId() != 0) {
      sb.append('%').append(v6.getScopeId());
    }
    return sb.toString();
  }

  /** Formats an endpoint as {@code a.b.c.d:port} or {@code [v6]:port}. */
  public static String format(InetSocketAddress endpoint) {
    InetAddress a = endpoint.getAddress();
    String host = format(a);
    return (a instanceof Inet6Address ? "[" + host + "]" : host) + ":" + endpoint.getPort();
  }

  /**
   * Parses {@code a.b.c.d:port} or {@code [v6]:port} with a literal address (no name lookup).
   *
   * @throws IllegalArgumentException if malformed
   */
  public static InetSocketAddress parseEndpoint(String text) {
    String s = text.strip();
    String host;
    String port;
    if (s.startsWith("[")) {
      int close = s.indexOf(']');
      if (close < 0 || close + 1 >= s.length() || s.charAt(close + 1) != ':') {
        throw new IllegalArgumentException("invalid endpoint: " + text);
      }
      host = s.substring(1, close);
      port = s.substring(close + 2);
    } else {
      int colon = s.lastIndexOf(':');
      if (colon < 0 || s.indexOf(':') != colon) {
        throw new IllegalArgumentException("invalid endpoint: " + text);
      }
      host = s.substring(0, colon);
      port = s.substring(colon + 1);
    }
    try {
      int p = Integer.parseInt(port);
      if (p < 1 || p > 65535) {
        throw new IllegalArgumentException("endpoint port out of range: " + text);
      }
      return new InetSocketAddress(InetAddress.ofLiteral(host), p);
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException("invalid endpoint port: " + text, e);
    }
  }
}
