// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetSocketAddress;

/** The outer side of the tunnel: the UDP socket carrying WireGuard messages. */
public interface Bind extends Closeable {
  /** A received datagram's length and source. */
  record Datagram(int length, InetSocketAddress source) {}

  /**
   * Blocks until a datagram arrives and copies it into {@code buf}.
   *
   * @throws java.nio.channels.ClosedChannelException once closed
   */
  Datagram receive(byte[] buf) throws IOException;

  /** Sends {@code buf[off..off+len)} to {@code target}. Thread-safe. */
  void send(byte[] buf, int off, int len, InetSocketAddress target) throws IOException;

  /** The local UDP port. */
  int localPort();
}
