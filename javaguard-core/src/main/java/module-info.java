// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

/**
 * The WireGuard protocol core: the {@code Device} and its peers, transport and timers, and the
 * Noise IKpsk2 handshake layer underneath.
 */
module com.skanavi.javaguard.core {
  requires transitive com.skanavi.javaguard.crypto;

  exports com.skanavi.javaguard.core;
  exports com.skanavi.javaguard.core.noise;
}
