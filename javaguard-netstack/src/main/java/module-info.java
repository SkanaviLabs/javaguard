// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

/** A userspace IP stack that terminates a javaguard tunnel inside the application. */
module com.skanavi.javaguard.netstack {
  requires transitive com.skanavi.javaguard.core;

  exports com.skanavi.javaguard.netstack;
}
