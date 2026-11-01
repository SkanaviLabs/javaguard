// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.proxy;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;
import javax.net.SocketFactory;

/**
 * Creates {@link Socket}s that connect through a {@link LocalProxy} over SOCKS5. Host names are
 * passed to the proxy unresolved, so they are looked up through the tunnel.
 */
final class TunnelSocketFactory extends SocketFactory {
  private final Proxy proxy;

  TunnelSocketFactory(Proxy proxy) {
    this.proxy = proxy;
  }

  @Override
  public Socket createSocket() {
    return new Socket(proxy);
  }

  @Override
  public Socket createSocket(String host, int port) throws IOException {
    Socket s = new Socket(proxy);
    s.connect(InetSocketAddress.createUnresolved(host, port));
    return s;
  }

  @Override
  public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
      throws IOException {
    return createSocket(host, port); // the local end is the proxy connection; ignore the binding
  }

  @Override
  public Socket createSocket(InetAddress host, int port) throws IOException {
    Socket s = new Socket(proxy);
    s.connect(new InetSocketAddress(host, port));
    return s;
  }

  @Override
  public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort)
      throws IOException {
    return createSocket(address, port);
  }
}
