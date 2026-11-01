// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

/** The WireGuard protocol core: wire messages, the Noise IKpsk2 handshake, and cookies. */
module com.skanavi.javaguard.core {
  requires transitive com.skanavi.javaguard.crypto;

  exports com.skanavi.javaguard.core.noise;
}
