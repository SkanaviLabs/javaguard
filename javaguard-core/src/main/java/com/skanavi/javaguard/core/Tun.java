// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core;

import java.io.Closeable;
import java.io.IOException;

/**
 * The inner side of the tunnel: a source of outgoing IP packets and a sink for incoming ones.
 * Implementations: {@link PacketPipe}, and the userspace network stack.
 */
public interface Tun extends Closeable {
  /** The largest IP packet the tunnel carries. */
  int mtu();

  /**
   * Blocks until an outgoing IP packet is available and copies it into {@code buf[off..]}.
   *
   * @return the packet length, or {@code -1} once the tun is closed
   */
  int read(byte[] buf, int off, int len) throws IOException;

  /** Delivers an incoming IP packet. Must not block for long; may drop when congested. */
  void write(byte[] buf, int off, int len) throws IOException;
}
