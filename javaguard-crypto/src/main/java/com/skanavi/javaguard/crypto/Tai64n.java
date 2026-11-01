// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.crypto;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;

/**
 * TAI64N timestamps as carried in WireGuard handshake initiations: 8 bytes of big-endian seconds
 * offset by {@code 2^62 + 10}, then 4 bytes of big-endian nanoseconds.
 *
 * <p>{@link #now(Clock)} rounds the nanoseconds down to a multiple of {@code 2^24} (about 16.8 ms),
 * like wireguard-go, so the timestamp does not leak a precise clock reading. Responders only need
 * timestamps to increase per peer.
 */
public final class Tai64n {
  /** Encoded length in bytes. */
  public static final int LENGTH = 12;

  private static final long BASE = 0x400000000000000aL;
  private static final int WHITENER_MASK = 0x1000000 - 1;
  private static final VarHandle BE_LONG =
      MethodHandles.byteArrayViewVarHandle(long[].class, ByteOrder.BIG_ENDIAN);
  private static final VarHandle BE_INT =
      MethodHandles.byteArrayViewVarHandle(int[].class, ByteOrder.BIG_ENDIAN);

  private Tai64n() {}

  /** Returns the current time from {@code clock}, encoded and whitened. */
  public static byte[] now(Clock clock) {
    return encodeWhitened(clock.instant());
  }

  /** Encodes {@code instant} with the nanoseconds rounded down to a multiple of {@code 2^24}. */
  public static byte[] encodeWhitened(Instant instant) {
    return encode(instant.getEpochSecond(), instant.getNano() & ~WHITENER_MASK);
  }

  /** Encodes {@code instant} exactly (no whitening). */
  public static byte[] encode(Instant instant) {
    return encode(instant.getEpochSecond(), instant.getNano());
  }

  /** Decodes a 12-byte timestamp. */
  public static Instant decode(byte[] stamp) {
    checkLength(stamp);
    long seconds = (long) BE_LONG.get(stamp, 0) - BASE;
    int nanos = (int) BE_INT.get(stamp, 8);
    return Instant.ofEpochSecond(seconds, Integer.toUnsignedLong(nanos));
  }

  /** Returns whether {@code a} is strictly later than {@code b}. */
  public static boolean isAfter(byte[] a, byte[] b) {
    checkLength(a);
    checkLength(b);
    return Arrays.compareUnsigned(a, b) > 0;
  }

  private static byte[] encode(long epochSecond, int nanos) {
    byte[] out = new byte[LENGTH];
    BE_LONG.set(out, 0, BASE + epochSecond);
    BE_INT.set(out, 8, nanos);
    return out;
  }

  private static void checkLength(byte[] stamp) {
    if (stamp.length != LENGTH) {
      throw new IllegalArgumentException("TAI64N timestamps are " + LENGTH + " bytes");
    }
  }
}
