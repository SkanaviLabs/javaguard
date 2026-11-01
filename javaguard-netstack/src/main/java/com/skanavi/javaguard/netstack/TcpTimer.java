// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.netstack;

import com.skanavi.javaguard.core.Scheduler;

/**
 * A restartable one-shot timer that tolerates being restarted on every packet. It keeps a deadline
 * and only touches the scheduler when no task is queued or the deadline moves earlier; a task that
 * fires before the deadline reschedules itself for the remainder.
 */
final class TcpTimer {
  private final Scheduler scheduler;
  private final Runnable action;
  private Scheduler.Task task;
  private long taskDue;
  private long deadline;
  private boolean pending;

  TcpTimer(Scheduler scheduler, Runnable action) {
    this.scheduler = scheduler;
    this.action = action;
  }

  synchronized void start(long delayNanos) {
    long now = System.nanoTime();
    deadline = now + Math.max(0, delayNanos);
    pending = true;
    if (task == null || taskDue - deadline > 0) {
      schedule(now);
    }
  }

  synchronized void startIfIdle(long delayNanos) {
    if (!pending) {
      start(delayNanos);
    }
  }

  synchronized void stop() {
    pending = false; // a queued task finds nothing to do; cancelling it every time is costly
  }

  synchronized boolean isPending() {
    return pending;
  }

  private void schedule(long now) {
    if (task != null) {
      task.cancel();
    }
    taskDue = deadline;
    Scheduler.Task[] holder = new Scheduler.Task[1];
    holder[0] = scheduler.schedule(() -> fire(holder), deadline - now);
    task = holder[0];
  }

  private void fire(Scheduler.Task[] self) {
    synchronized (this) {
      if (task != self[0]) {
        return; // superseded
      }
      task = null;
      if (!pending) {
        return;
      }
      long now = System.nanoTime();
      if (deadline - now > 0) {
        schedule(now); // restarted since this task was queued
        return;
      }
      pending = false;
    }
    action.run();
  }
}
