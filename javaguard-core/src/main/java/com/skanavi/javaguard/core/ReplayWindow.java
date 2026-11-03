// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core;

// Portions derived from wireguard-go (https://git.zx2c4.com/wireguard-go/),
// Copyright (C) 2017-2025 WireGuard LLC. MIT.

/**
 * Sliding-window replay filter for transport counters (RFC 6479 bitmap), sized like the Linux
 * implementation: a ring of 128 64-bit blocks tracking the last 8128 counters. Counters are
 * unsigned. Thread-safe.
 */
final class ReplayWindow {
  private static final int RING_BLOCKS = 128;
  private static final int BLOCK_BITS_LOG = 6;
  private static final long WINDOW_SIZE = (RING_BLOCKS - 1) * 64L;

  private final long[] ring = new long[RING_BLOCKS];
  private long last;

  /** Window size: counters more than this far behind the highest one seen are rejected. */
  static long windowSize() {
    return WINDOW_SIZE;
  }

  /**
   * Records {@code counter} and returns whether it is acceptable: below {@code limit} (unsigned),
   * not too old, and not seen before. Call only after the packet authenticated.
   */
  synchronized boolean accept(long counter, long limit) {
    if (Long.compareUnsigned(counter, limit) >= 0) {
      return false;
    }
    long blockIndex = counter >>> BLOCK_BITS_LOG;
    if (Long.compareUnsigned(counter, last) > 0) {
      long current = last >>> BLOCK_BITS_LOG;
      long diff = Math.min(blockIndex - current, RING_BLOCKS);
      for (long i = current + 1; i <= current + diff; i++) {
        ring[(int) (i & (RING_BLOCKS - 1))] = 0;
      }
      last = counter;
    } else if (Long.compareUnsigned(last - counter, WINDOW_SIZE) > 0) {
      return false;
    }
    int block = (int) (blockIndex & (RING_BLOCKS - 1));
    long bit = 1L << (counter & 63);
    long old = ring[block];
    ring[block] = old | bit;
    return (old & bit) == 0;
  }
}
