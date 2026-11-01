// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core.noise;

import java.time.Instant;

/**
 * Time for the protocol: a monotonic clock for intervals and a wall clock for TAI64N timestamps.
 * Tests substitute a manual implementation.
 */
public interface TimeSource {
  /** Monotonic time in nanoseconds, as {@link System#nanoTime()}. */
  long nanoTime();

  /** Wall-clock time. */
  Instant now();

  /** The system clocks. */
  static TimeSource system() {
    return SystemTimeSource.INSTANCE;
  }
}

enum SystemTimeSource implements TimeSource {
  INSTANCE;

  @Override
  public long nanoTime() {
    return System.nanoTime();
  }

  @Override
  public Instant now() {
    return Instant.now();
  }
}
