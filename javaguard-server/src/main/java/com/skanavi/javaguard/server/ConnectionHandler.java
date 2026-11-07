// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.server;

/** Serves one connection from a peer, on its own virtual thread. */
@FunctionalInterface
public interface ConnectionHandler {
  /**
   * Serves {@code connection}. The socket is closed when this returns, and reset if it throws.
   *
   * @throws Exception on any failure
   */
  void handle(TunnelConnection connection) throws Exception;
}
