// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.netstack;

import com.skanavi.javaguard.core.Tun;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Connects two tuns through an impaired link: random loss, reordering, duplication and an optional
 * one-way delay.
 */
final class LossyWire {
  final AtomicLong dropped = new AtomicLong();
  final AtomicLong delivered = new AtomicLong();
  private final double loss;
  private final double reorder;
  private final double duplicate;
  private final long delayNanos;

  LossyWire(double loss, double reorder, double duplicate) {
    this(loss, reorder, duplicate, java.time.Duration.ZERO);
  }

  LossyWire(double loss, double reorder, double duplicate, java.time.Duration delay) {
    this.loss = loss;
    this.reorder = reorder;
    this.duplicate = duplicate;
    this.delayNanos = delay.toNanos();
  }

  LossyWire connect(Tun a, Tun b, long seed) {
    pump(a, b, new Random(seed));
    pump(b, a, new Random(seed + 1));
    return this;
  }

  private record Delayed(long due, byte[] packet) {}

  private void pump(Tun from, Tun to, Random random) {
    java.util.concurrent.BlockingQueue<Delayed> line =
        new java.util.concurrent.LinkedBlockingQueue<>();
    if (delayNanos > 0) {
      Thread.ofVirtual()
          .start(
              () -> {
                try {
                  while (true) {
                    Delayed d = line.take();
                    long wait = d.due() - System.nanoTime();
                    if (wait > 0) {
                      java.util.concurrent.locks.LockSupport.parkNanos(wait);
                    }
                    to.write(d.packet(), 0, d.packet().length);
                  }
                } catch (InterruptedException | java.io.IOException e) {
                  // closed
                }
              });
    }
    Thread.ofVirtual()
        .start(
            () -> {
              byte[] buf = new byte[65536];
              byte[] held = null;
              try {
                int n;
                while ((n = from.read(buf, 0, buf.length)) >= 0) {
                  byte[] p = Arrays.copyOf(buf, n);
                  synchronized (random) {
                    if (random.nextDouble() < loss) {
                      dropped.incrementAndGet();
                      continue;
                    }
                    if (held == null && random.nextDouble() < reorder) {
                      held = p; // send after the next packet
                      continue;
                    }
                  }
                  send(line, to, p);
                  if (random.nextDouble() < duplicate) {
                    send(line, to, p);
                  }
                  if (held != null) {
                    send(line, to, held);
                    held = null;
                  }
                }
              } catch (java.io.IOException e) {
                // closed
              }
            });
  }

  private void send(java.util.concurrent.BlockingQueue<Delayed> line, Tun to, byte[] p)
      throws java.io.IOException {
    if (delayNanos > 0) {
      delivered.incrementAndGet();
      line.add(new Delayed(System.nanoTime() + delayNanos, p));
    } else {
      deliver(to, p);
    }
  }

  private void deliver(Tun to, byte[] p) throws java.io.IOException {
    delivered.incrementAndGet();
    to.write(p, 0, p.length);
  }
}
