// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core;

import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * Runs delayed actions for protocol timers. The default is a single daemon thread; simulations
 * substitute a virtual-time implementation. Delays are measured against the same monotonic clock as
 * the device's {@link com.skanavi.javaguard.core.noise.TimeSource}.
 */
public interface Scheduler extends AutoCloseable {
  /** A scheduled action. */
  interface Task {
    /** Prevents the action from running, if it has not started. */
    void cancel();
  }

  /** Runs {@code action} once after {@code delayNanos}. */
  Task schedule(Runnable action, long delayNanos);

  /** Stops the scheduler and discards pending actions. */
  @Override
  void close();

  /** A scheduler backed by one daemon thread. */
  static Scheduler newDefault() {
    ScheduledThreadPoolExecutor executor =
        new ScheduledThreadPoolExecutor(
            1,
            r -> {
              Thread t = new Thread(r, "javaguard-timers");
              t.setDaemon(true);
              return t;
            });
    executor.setRemoveOnCancelPolicy(true);
    return new Scheduler() {
      @Override
      public Task schedule(Runnable action, long delayNanos) {
        var future = executor.schedule(action, delayNanos, TimeUnit.NANOSECONDS);
        return () -> future.cancel(false);
      }

      @Override
      public void close() {
        executor.shutdownNow();
      }
    };
  }
}
