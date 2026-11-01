// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core.noise;

import java.time.Duration;
import java.time.Instant;

/** A clock that only moves when told to. */
final class ManualTimeSource implements TimeSource {
  private long nanos = 1_000_000_000L;
  private Instant wall = Instant.parse("2026-11-01T00:00:00Z");

  @Override
  public synchronized long nanoTime() {
    return nanos;
  }

  @Override
  public synchronized Instant now() {
    return wall;
  }

  synchronized void advance(Duration d) {
    nanos += d.toNanos();
    wall = wall.plus(d);
  }
}
