// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.proxy;

import com.skanavi.javaguard.netstack.Netstack;
import com.skanavi.javaguard.netstack.TcpSocket;
import java.io.IOException;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.List;

/** Resolves names through the tunnel and opens tunnel connections, trying each address. */
final class Dialer {
  private final Netstack stack;
  private final boolean systemDnsFallback;
  private final Duration connectTimeout;

  Dialer(Netstack stack, boolean systemDnsFallback, Duration connectTimeout) {
    this.stack = stack;
    this.systemDnsFallback = systemDnsFallback;
    this.connectTimeout = connectTimeout;
  }

  /** Resolves {@code host} with the tunnel's DNS (and the system resolver only if allowed). */
  List<InetAddress> resolve(String host) throws UnknownHostException {
    try {
      return stack.dns().resolve(host);
    } catch (UnknownHostException e) {
      if (!systemDnsFallback) {
        throw e;
      }
      return List.of(InetAddress.getAllByName(host));
    }
  }

  /** Connects to {@code host:port}, trying resolved addresses in order. */
  TcpSocket connect(String host, int port) throws IOException {
    IOException last = null;
    for (InetAddress address : resolve(host)) {
      try {
        return stack.connectTcp(new InetSocketAddress(address, port), connectTimeout);
      } catch (IllegalArgumentException e) {
        last = new ConnectException("no tunnel address for " + address.getHostAddress());
      } catch (IOException e) {
        last = e;
      }
    }
    throw last != null ? last : new UnknownHostException(host);
  }

  Netstack stack() {
    return stack;
  }
}
