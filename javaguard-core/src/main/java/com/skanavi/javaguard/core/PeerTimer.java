// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core;

import com.skanavi.javaguard.core.noise.TimeSource;

/**
 * A restartable one-shot timer that tolerates being re-armed and disarmed on every packet. It keeps
 * a deadline and only touches the scheduler when no task is queued or the deadline moves earlier; a
 * task that fires before the deadline reschedules itself for the remainder.
 */
final class PeerTimer {
  private final Scheduler scheduler;
  private final TimeSource time;
  private final Runnable action;
  private Scheduler.Task task;
  private long taskDue;
  private long deadline;
  private boolean pending;

  PeerTimer(Scheduler scheduler, TimeSource time, Runnable action) {
    this.scheduler = scheduler;
    this.time = time;
    this.action = action;
  }

  synchronized void mod(long delayNanos) {
    long now = time.nanoTime();
    deadline = now + Math.max(0, delayNanos);
    pending = true;
    if (task == null || taskDue - deadline > 0) {
      schedule(now);
    }
  }

  synchronized void del() {
    pending = false; // a queued task finds nothing to do
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
      long now = time.nanoTime();
      if (deadline - now > 0) {
        schedule(now); // re-armed since this task was queued
        return;
      }
      pending = false;
    }
    action.run();
  }
}
