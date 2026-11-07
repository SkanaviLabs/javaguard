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

/**
 * Resolves names through the tunnel and opens tunnel connections, trying each address. With an
 * upstream, every connection goes through it instead, and targets are not resolved here.
 */
final class Dialer {
  /** A SOCKS5 proxy reached through the tunnel; {@code credentials} may be null. */
  record Upstream(String host, int port, Socks5Session.Credentials credentials) {}

  private final Netstack stack;
  private final boolean systemDnsFallback;
  private final Duration connectTimeout;
  private final Upstream upstream;

  Dialer(Netstack stack, boolean systemDnsFallback, Duration connectTimeout, Upstream upstream) {
    this.stack = stack;
    this.systemDnsFallback = systemDnsFallback;
    this.connectTimeout = connectTimeout;
    this.upstream = upstream;
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

  /**
   * Connects to {@code host:port}, through the upstream if there is one. A failure of the upstream
   * is an error, never a reason to dial the target directly.
   */
  TcpSocket connect(String host, int port) throws IOException {
    if (upstream == null) {
      return dialDirect(host, port);
    }
    TcpSocket socket = dialDirect(upstream.host(), upstream.port());
    boolean connected = false;
    try {
      Socks5Client.connect(socket, upstream.credentials(), host, port, connectTimeout);
      connected = true;
      return socket;
    } finally {
      if (!connected) {
        socket.close();
      }
    }
  }

  /** Connects to {@code host:port} in the tunnel, trying resolved addresses in order. */
  private TcpSocket dialDirect(String host, int port) throws IOException {
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

  boolean hasUpstream() {
    return upstream != null;
  }

  Netstack stack() {
    return stack;
  }
}
