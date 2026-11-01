// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.netstack;

import com.skanavi.javaguard.core.Scheduler;

/** A restartable one-shot timer; stale firings are suppressed by a generation check. */
final class TcpTimer {
  private final Scheduler scheduler;
  private final Runnable action;
  private Scheduler.Task task;
  private long generation;
  private boolean pending;

  TcpTimer(Scheduler scheduler, Runnable action) {
    this.scheduler = scheduler;
    this.action = action;
  }

  synchronized void start(long delayNanos) {
    if (task != null) {
      task.cancel();
    }
    long gen = ++generation;
    pending = true;
    task = scheduler.schedule(() -> fire(gen), Math.max(0, delayNanos));
  }

  synchronized void startIfIdle(long delayNanos) {
    if (!pending) {
      start(delayNanos);
    }
  }

  synchronized void stop() {
    if (task != null) {
      task.cancel();
      task = null;
    }
    generation++;
    pending = false;
  }

  synchronized boolean isPending() {
    return pending;
  }

  private void fire(long gen) {
    synchronized (this) {
      if (!pending || gen != generation) {
        return;
      }
      pending = false;
      task = null;
    }
    action.run();
  }
}
