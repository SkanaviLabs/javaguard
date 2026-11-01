// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core;

import com.skanavi.javaguard.core.noise.TimeSource;
import java.net.InetAddress;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Per-source-address token bucket for handshake messages while under load: 20 per second with a
 * burst of 5, as in the reference implementations. Thread-safe.
 */
final class RateLimiter {
  private static final long PACKET_COST = 1_000_000_000L / 20;
  private static final long MAX_TOKENS = PACKET_COST * 5;
  private static final long IDLE_NANOS = 1_000_000_000L;
  private static final int CLEANUP_THRESHOLD = 4096;

  private static final class Bucket {
    long tokens = MAX_TOKENS;
    long lastNanos;
  }

  private final TimeSource time;
  private final ConcurrentHashMap<InetAddress, Bucket> buckets = new ConcurrentHashMap<>();

  RateLimiter(TimeSource time) {
    this.time = time;
  }

  boolean allow(InetAddress source) {
    long now = time.nanoTime();
    if (buckets.size() > CLEANUP_THRESHOLD) {
      buckets.values().removeIf(b -> now - b.lastNanos > IDLE_NANOS);
    }
    Bucket b =
        buckets.computeIfAbsent(
            source,
            k -> {
              Bucket nb = new Bucket();
              nb.lastNanos = now;
              return nb;
            });
    synchronized (b) {
      b.tokens = Math.min(MAX_TOKENS, b.tokens + (now - b.lastNanos));
      b.lastNanos = now;
      if (b.tokens >= PACKET_COST) {
        b.tokens -= PACKET_COST;
        return true;
      }
      return false;
    }
  }
}
