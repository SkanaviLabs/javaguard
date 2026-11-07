// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.server;

import java.nio.file.Path;
import java.util.Objects;

/**
 * A listener on this host that a tunnel port is relayed to. There is deliberately no target for
 * another host: peers reach local services and nothing beyond them.
 */
public sealed interface Target {
  /** A TCP port on the loopback interface. */
  static Target loopback(int port) {
    return new Loopback(port);
  }

  /**
   * A Unix domain socket. Prefer this to {@link #loopback(int)}: file permissions decide who else
   * on the host can connect, which also keeps others from forging a {@link ProxyHeader#V2} header.
   */
  static Target unixSocket(Path path) {
    return new UnixSocket(path);
  }

  /**
   * A TCP port on the loopback interface.
   *
   * @param port the port
   */
  record Loopback(int port) implements Target {
    /** Validates the port. */
    public Loopback {
      if (port < 1 || port > 65535) {
        throw new IllegalArgumentException("port out of range: " + port);
      }
    }
  }

  /**
   * A Unix domain socket.
   *
   * @param path the socket file
   */
  record UnixSocket(Path path) implements Target {
    /** Validates the path. */
    public UnixSocket {
      Objects.requireNonNull(path, "path");
    }
  }
}
