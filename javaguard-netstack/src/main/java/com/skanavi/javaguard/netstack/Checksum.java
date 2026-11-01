// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.netstack;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;

/** The Internet checksum (RFC 1071) and transport pseudo-headers. */
final class Checksum {
  private static final VarHandle BE_INT =
      MethodHandles.byteArrayViewVarHandle(int[].class, ByteOrder.BIG_ENDIAN);

  private Checksum() {}

  /**
   * Adds {@code b[off..off+len)} as big-endian 16-bit words to {@code sum}. Words are summed 32
   * bits at a time into a 64-bit accumulator; one's-complement addition makes that equivalent.
   */
  static long add(long sum, byte[] b, int off, int len) {
    int i = off;
    int end4 = off + (len & ~3);
    long wide = 0;
    for (; i < end4; i += 4) {
      wide += Integer.toUnsignedLong((int) BE_INT.get(b, i));
    }
    sum += (wide >>> 32) + ((wide >>> 16) & 0xffff) + (wide & 0xffff);
    int end = off + len - 1;
    for (; i < end; i += 2) {
      sum += ((b[i] & 0xff) << 8) | (b[i + 1] & 0xff);
    }
    if (i == end) {
      sum += (b[i] & 0xff) << 8;
    }
    return sum;
  }

  /** Folds and complements a running sum into the 16-bit checksum value. */
  static int finish(long sum) {
    while ((sum >>> 16) != 0) {
      sum = (sum & 0xffff) + (sum >>> 16);
    }
    return (int) (~sum & 0xffff);
  }

  /** Checksum of {@code b[off..off+len)} alone, as for IPv4 headers and ICMPv4. */
  static int of(byte[] b, int off, int len) {
    return finish(add(0, b, off, len));
  }

  /** Initial sum for a transport checksum: the IPv4 or IPv6 pseudo-header. */
  static long pseudoHeader(byte[] src, byte[] dst, int protocol, int length) {
    long sum = add(add(0, src, 0, src.length), dst, 0, dst.length);
    return sum + protocol + length;
  }
}
