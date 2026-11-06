// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

/** Serving WireGuard peers from inside a JVM, with no forwarding beyond it. */
module com.skanavi.javaguard.server {
  requires transitive com.skanavi.javaguard.config;
  requires transitive com.skanavi.javaguard.netstack;

  exports com.skanavi.javaguard.server;
}
