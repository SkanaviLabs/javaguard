// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.netstack;

import com.skanavi.javaguard.core.Tun;

/** Connects two tuns back to back, like a perfect tunnel, until either closes. */
final class Wire {
  private Wire() {}

  static void connect(Tun a, Tun b) {
    pump(a, b);
    pump(b, a);
  }

  private static void pump(Tun from, Tun to) {
    Thread.ofVirtual()
        .start(
            () -> {
              byte[] buf = new byte[65536];
              try {
                int n;
                while ((n = from.read(buf, 0, buf.length)) >= 0) {
                  to.write(buf, 0, n);
                }
              } catch (java.io.IOException e) {
                // closed
              }
            });
  }
}
