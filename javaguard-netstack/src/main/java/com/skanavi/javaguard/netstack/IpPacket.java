// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.netstack;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;

/**
 * A parsed IPv4 or IPv6 packet: addresses, transport protocol and payload bounds within the
 * original buffer. Also builds outgoing packets.
 *
 * @param version 4 or 6
 * @param src source address bytes
 * @param dst destination address bytes
 * @param protocol transport protocol (IPv4 protocol / IPv6 next header)
 * @param data the packet buffer
 * @param payloadOffset start of the transport payload in {@code data}
 * @param payloadLength length of the transport payload
 */
record IpPacket(
    int version,
    byte[] src,
    byte[] dst,
    int protocol,
    byte[] data,
    int payloadOffset,
    int payloadLength) {
  static final int ICMP = 1;
  static final int TCP = 6;
  static final int UDP = 17;
  static final int ICMPV6 = 58;
  static final int IPV4_HEADER = 20;
  static final int IPV6_HEADER = 40;
  private static final int TTL = 64;

  /**
   * Parses and validates {@code p[0..len)}. Returns {@code null} for anything malformed, IPv4
   * fragments, packets with a bad IPv4 header checksum, and IPv6 packets with extension headers.
   */
  static IpPacket parse(byte[] p, int len) {
    if (len < 1) {
      return null;
    }
    int version = (p[0] & 0xff) >>> 4;
    if (version == 4) {
      if (len < IPV4_HEADER) {
        return null;
      }
      int ihl = (p[0] & 0x0f) * 4;
      int total = u16(p, 2);
      if (ihl < IPV4_HEADER || total < ihl || total > len || Checksum.of(p, 0, ihl) != 0) {
        return null;
      }
      if ((u16(p, 6) & 0x3fff) != 0) {
        return null; // fragment (MF set or non-zero offset): reassembly not supported yet
      }
      return new IpPacket(
          4,
          Arrays.copyOfRange(p, 12, 16),
          Arrays.copyOfRange(p, 16, 20),
          p[9] & 0xff,
          p,
          ihl,
          total - ihl);
    }
    if (version == 6) {
      if (len < IPV6_HEADER) {
        return null;
      }
      int payload = u16(p, 4);
      int next = p[6] & 0xff;
      if (IPV6_HEADER + payload > len || (next != UDP && next != ICMPV6 && next != TCP)) {
        return null;
      }
      return new IpPacket(
          6,
          Arrays.copyOfRange(p, 8, 24),
          Arrays.copyOfRange(p, 24, 40),
          next,
          p,
          IPV6_HEADER,
          payload);
    }
    return null;
  }

  InetAddress srcAddress() {
    return address(src);
  }

  InetAddress dstAddress() {
    return address(dst);
  }

  /** Header length for an IP version. */
  static int headerLength(int version) {
    return version == 4 ? IPV4_HEADER : IPV6_HEADER;
  }

  /**
   * Builds a packet with room for a {@code payloadLength}-byte transport payload, which the caller
   * writes at {@link #headerLength(int)} and checksums. The IPv4 header checksum is filled in.
   */
  static byte[] build(byte[] src, byte[] dst, int protocol, int payloadLength, int ipv4Id) {
    if (src.length == 4) {
      int total = IPV4_HEADER + payloadLength;
      byte[] p = new byte[total];
      p[0] = 0x45;
      put16(p, 2, total);
      put16(p, 4, ipv4Id);
      put16(p, 6, 0x4000); // don't fragment
      p[8] = (byte) TTL;
      p[9] = (byte) protocol;
      System.arraycopy(src, 0, p, 12, 4);
      System.arraycopy(dst, 0, p, 16, 4);
      put16(p, 10, Checksum.of(p, 0, IPV4_HEADER));
      return p;
    }
    byte[] p = new byte[IPV6_HEADER + payloadLength];
    p[0] = 0x60;
    put16(p, 4, payloadLength);
    p[6] = (byte) protocol;
    p[7] = (byte) TTL;
    System.arraycopy(src, 0, p, 8, 16);
    System.arraycopy(dst, 0, p, 24, 16);
    return p;
  }

  static int u16(byte[] b, int off) {
    return ((b[off] & 0xff) << 8) | (b[off + 1] & 0xff);
  }

  static void put16(byte[] b, int off, int v) {
    b[off] = (byte) (v >>> 8);
    b[off + 1] = (byte) v;
  }

  static InetAddress address(byte[] b) {
    try {
      return InetAddress.getByAddress(b);
    } catch (UnknownHostException e) {
      throw new AssertionError(e);
    }
  }
}
