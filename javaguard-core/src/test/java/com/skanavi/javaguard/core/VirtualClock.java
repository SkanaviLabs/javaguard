// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core;

import com.skanavi.javaguard.core.noise.TimeSource;
import java.time.Duration;
import java.time.Instant;
import java.util.PriorityQueue;

/** Virtual time: a {@link TimeSource} and {@link Scheduler} that advance only when told. */
final class VirtualClock implements TimeSource, Scheduler {
  private static final class Entry implements Task {
    final long due;
    final long seq;
    final Runnable action;
    boolean cancelled;

    Entry(long due, long seq, Runnable action) {
      this.due = due;
      this.seq = seq;
      this.action = action;
    }

    @Override
    public void cancel() {
      cancelled = true;
    }
  }

  private static final Instant EPOCH = Instant.parse("2026-11-01T00:00:00Z");
  private final PriorityQueue<Entry> queue =
      new PriorityQueue<>(
          (a, b) -> a.due != b.due ? Long.compare(a.due, b.due) : Long.compare(a.seq, b.seq));
  private long nanos = 1_000_000_000L;
  private long seq;

  @Override
  public long nanoTime() {
    return nanos;
  }

  @Override
  public Instant now() {
    return EPOCH.plusNanos(nanos);
  }

  @Override
  public Task schedule(Runnable action, long delayNanos) {
    Entry e = new Entry(nanos + delayNanos, seq++, action);
    queue.add(e);
    return e;
  }

  @Override
  public void close() {}

  /** Runs the earliest task due at or before {@code until}; returns false if there is none. */
  boolean runNext(long until) {
    while (!queue.isEmpty() && queue.peek().cancelled) {
      queue.poll();
    }
    Entry e = queue.peek();
    if (e == null || e.due > until) {
      return false;
    }
    queue.poll();
    nanos = Math.max(nanos, e.due);
    e.action.run();
    return true;
  }

  void setNanos(long value) {
    nanos = Math.max(nanos, value);
  }

  long elapsedSince(long start) {
    return nanos - start;
  }

  static long toNanos(Duration d) {
    return d.toNanos();
  }
}
