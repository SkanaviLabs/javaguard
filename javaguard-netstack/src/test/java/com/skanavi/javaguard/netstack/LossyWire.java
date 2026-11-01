// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.netstack;

import com.skanavi.javaguard.core.Tun;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.atomic.AtomicLong;

/** Connects two tuns through an impaired link: random loss, reordering and duplication. */
final class LossyWire {
  final AtomicLong dropped = new AtomicLong();
  final AtomicLong delivered = new AtomicLong();
  private final double loss;
  private final double reorder;
  private final double duplicate;

  LossyWire(double loss, double reorder, double duplicate) {
    this.loss = loss;
    this.reorder = reorder;
    this.duplicate = duplicate;
  }

  LossyWire connect(Tun a, Tun b, long seed) {
    pump(a, b, new Random(seed));
    pump(b, a, new Random(seed + 1));
    return this;
  }

  private void pump(Tun from, Tun to, Random random) {
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
                  deliver(to, p);
                  if (random.nextDouble() < duplicate) {
                    deliver(to, p);
                  }
                  if (held != null) {
                    deliver(to, held);
                    held = null;
                  }
                }
              } catch (java.io.IOException e) {
                // closed
              }
            });
  }

  private void deliver(Tun to, byte[] p) throws java.io.IOException {
    delivered.incrementAndGet();
    to.write(p, 0, p.length);
  }
}
