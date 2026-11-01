// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.netstack;

import com.skanavi.javaguard.core.Tun;
import java.io.IOException;
import java.util.Random;

/** Wraps a tun and drops a fraction of packets in each direction, to inject loss. */
final class ImpairedTun implements Tun {
  private final Tun inner;
  private final double loss;
  private final Random random = new Random(7);

  ImpairedTun(Tun inner, double loss) {
    this.inner = inner;
    this.loss = loss;
  }

  private synchronized boolean drop() {
    return random.nextDouble() < loss;
  }

  @Override
  public int mtu() {
    return inner.mtu();
  }

  @Override
  public int read(byte[] buf, int off, int len) throws IOException {
    while (true) {
      int n = inner.read(buf, off, len);
      if (n < 0 || !drop()) {
        return n;
      }
    }
  }

  @Override
  public void write(byte[] buf, int off, int len) throws IOException {
    if (!drop()) {
      inner.write(buf, off, len);
    }
  }

  @Override
  public void close() throws IOException {
    inner.close();
  }
}
