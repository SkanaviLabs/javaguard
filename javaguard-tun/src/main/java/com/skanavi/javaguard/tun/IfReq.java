// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.tun;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_SHORT;

import java.lang.foreign.Arena;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.StructLayout;
import java.lang.invoke.VarHandle;
import java.nio.charset.StandardCharsets;

/**
 * Linux {@code struct ifreq} on 64-bit targets, as far as TUNSETIFF uses it: a 16-byte name and a
 * {@code short} of flags at the start of a 24-byte union. 40 bytes in all.
 */
final class IfReq {
  static final int IFNAMSIZ = 16;

  static final StructLayout LAYOUT =
      MemoryLayout.structLayout(
              MemoryLayout.sequenceLayout(IFNAMSIZ, JAVA_BYTE).withName("ifr_name"),
              JAVA_SHORT.withName("ifr_flags"),
              MemoryLayout.paddingLayout(22))
          .withByteAlignment(8);

  private static final long NAME_OFFSET =
      LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("ifr_name"));
  private static final VarHandle FLAGS =
      LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("ifr_flags"));

  private IfReq() {}

  /**
   * Allocates a request for interface {@code name} (empty to let the kernel choose) with {@code
   * flags}.
   */
  static MemorySegment allocate(Arena arena, String name, short flags) {
    byte[] bytes = encodeName(name);
    MemorySegment s = arena.allocate(LAYOUT);
    MemorySegment.copy(bytes, 0, s, JAVA_BYTE, NAME_OFFSET, bytes.length);
    FLAGS.set(s, 0L, flags);
    return s;
  }

  /** The interface name stored in {@code s}. */
  static String name(MemorySegment s) {
    byte[] raw = new byte[IFNAMSIZ];
    MemorySegment.copy(s, JAVA_BYTE, NAME_OFFSET, raw, 0, IFNAMSIZ);
    int n = 0;
    while (n < IFNAMSIZ && raw[n] != 0) {
      n++;
    }
    return new String(raw, 0, n, StandardCharsets.US_ASCII);
  }

  /** The flags stored in {@code s}. */
  static short flags(MemorySegment s) {
    return (short) FLAGS.get(s, 0L);
  }

  /**
   * Validates an interface name the way the kernel does (at most 15 bytes, no slash, colon or
   * whitespace, not "." or ".."). A {@code %d} is allowed and filled in by the kernel.
   */
  static byte[] encodeName(String name) {
    if (name.length() >= IFNAMSIZ
        || !name.matches("[A-Za-z0-9_.=+%-]*")
        || name.equals(".")
        || name.equals("..")) {
      throw new IllegalArgumentException("invalid interface name '" + name + "'");
    }
    return name.getBytes(StandardCharsets.US_ASCII);
  }
}
