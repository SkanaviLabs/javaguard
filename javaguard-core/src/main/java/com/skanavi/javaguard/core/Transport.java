// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core;

import com.skanavi.javaguard.core.noise.Protocol;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;

/**
 * Transport data message layout ({@code type || receiver || counter || ciphertext}) and the IP
 * header fields the data path inspects.
 */
final class Transport {
  /** Header length: type, receiver index, 64-bit counter. */
  static final int HEADER_LENGTH = 16;

  /** Smallest valid message: header plus tag of an empty (keepalive) payload. */
  static final int MIN_LENGTH = HEADER_LENGTH + 16;

  private static final VarHandle LE_INT =
      MethodHandles.byteArrayViewVarHandle(int[].class, ByteOrder.LITTLE_ENDIAN);
  private static final VarHandle LE_LONG =
      MethodHandles.byteArrayViewVarHandle(long[].class, ByteOrder.LITTLE_ENDIAN);

  private Transport() {}

  static void putHeader(byte[] b, int receiver, long counter) {
    LE_INT.set(b, 0, Protocol.TYPE_TRANSPORT);
    LE_INT.set(b, 4, receiver);
    LE_LONG.set(b, 8, counter);
  }

  static int receiver(byte[] b, int off) {
    return (int) LE_INT.get(b, off + 4);
  }

  static long counter(byte[] b, int off) {
    return (long) LE_LONG.get(b, off + 8);
  }

  /** Plaintext length after zero-padding {@code len} to a multiple of 16, capped at the MTU. */
  static int paddedLength(int len, int mtu) {
    int padded = (len + 15) & ~15;
    return padded > mtu ? Math.max(len, mtu) : padded;
  }

  /** IP version of a packet (4 or 6), or 0 if too short to tell. */
  static int ipVersion(byte[] p, int off, int len) {
    return len < 1 ? 0 : (p[off] & 0xff) >>> 4;
  }

  /**
   * Length the IP header claims for the packet in {@code p} (which may carry trailing padding), or
   * {@code -1} if it is not a plausible IPv4 or IPv6 packet.
   */
  static int ipLength(byte[] p) {
    int total;
    switch (ipVersion(p, 0, p.length)) {
      case 4 -> {
        if (p.length < 20) {
          return -1;
        }
        total = ((p[2] & 0xff) << 8) | (p[3] & 0xff);
        if (total < 20) {
          return -1;
        }
      }
      case 6 -> {
        if (p.length < 40) {
          return -1;
        }
        total = 40 + (((p[4] & 0xff) << 8) | (p[5] & 0xff));
      }
      default -> {
        return -1;
      }
    }
    return total <= p.length ? total : -1;
  }

  /** Offset of the source address in an IPv4 (12) or IPv6 (8) header. */
  static int sourceOffset(int version) {
    return version == 4 ? 12 : 8;
  }

  /** Offset of the destination address in an IPv4 (16) or IPv6 (24) header. */
  static int destinationOffset(int version) {
    return version == 4 ? 16 : 24;
  }

  /** Address length for an IP version. */
  static int addressLength(int version) {
    return version == 4 ? 4 : 16;
  }
}
