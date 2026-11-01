// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.proxy;

import com.skanavi.javaguard.netstack.Netstack;
import java.io.Closeable;
import java.io.IOException;
import java.io.PushbackInputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.Semaphore;
import javax.net.SocketFactory;

/**
 * A proxy on a host socket that carries connections through a {@link Netstack}. One port speaks
 * SOCKS5 (CONNECT and UDP ASSOCIATE) and HTTP (CONNECT tunnels and plain {@code http://} requests);
 * the protocol is recognized from the first byte.
 *
 * <p>Host names are resolved with the tunnel's DNS, never the host's, unless {@link
 * Builder#systemDnsFallback(boolean)} allows it. By default the proxy binds to loopback without
 * authentication; set {@link Builder#credentials(String, String)} before binding anywhere else.
 *
 * <pre>{@code
 * LocalProxy proxy = LocalProxy.builder(netstack).build();   // 127.0.0.1, random port
 * HttpClient client = proxy.httpClientBuilder().build();
 * client.send(HttpRequest.newBuilder(URI.create("http://intranet.example/")).build(), ofString());
 * }</pre>
 */
public final class LocalProxy implements Closeable {
  private static final System.Logger LOG = System.getLogger(LocalProxy.class.getName());

  private final ServerSocket server;
  private final Dialer dialer;
  private final Socks5Session.Credentials credentials;
  private final Semaphore slots;
  private final Thread acceptor;
  private volatile boolean closed;

  private LocalProxy(Builder b) throws IOException {
    this.dialer = new Dialer(b.stack, b.systemDnsFallback, b.connectTimeout);
    this.credentials =
        b.user == null
            ? null
            : new Socks5Session.Credentials(
                b.user.getBytes(StandardCharsets.UTF_8),
                b.password.getBytes(StandardCharsets.UTF_8));
    this.slots = new Semaphore(b.maxConnections);
    this.server = new ServerSocket();
    server.setReuseAddress(true);
    server.bind(b.bind, 128);
    this.acceptor = new Thread(this::acceptLoop, "javaguard-proxy");
    acceptor.setDaemon(true);
    acceptor.start();
  }

  /** Starts building a proxy for {@code stack}. */
  public static Builder builder(Netstack stack) {
    return new Builder(stack);
  }

  /** The address the proxy listens on. */
  public InetSocketAddress address() {
    return (InetSocketAddress) server.getLocalSocketAddress();
  }

  /** A {@link java.net.Proxy} of type SOCKS for this proxy. */
  public Proxy socksProxy() {
    return new Proxy(Proxy.Type.SOCKS, address());
  }

  /** A {@link ProxySelector} that sends every request through this proxy's HTTP side. */
  public ProxySelector proxySelector() {
    return ProxySelector.of(address());
  }

  /**
   * A {@link SocketFactory} whose sockets connect through the tunnel via SOCKS5. Connecting by host
   * name resolves the name through the tunnel.
   */
  public SocketFactory socketFactory() {
    return new TunnelSocketFactory(socksProxy());
  }

  /** An {@link HttpClient} builder preconfigured to use this proxy. */
  public HttpClient.Builder httpClientBuilder() {
    return HttpClient.newBuilder().proxy(proxySelector());
  }

  private void acceptLoop() {
    while (!closed) {
      try {
        Socket client = server.accept();
        if (!slots.tryAcquire()) {
          Relay.closeQuietly(client); // over the connection limit
          continue;
        }
        Thread.ofVirtual()
            .name("javaguard-proxy-session")
            .start(
                () -> {
                  try {
                    handle(client);
                  } finally {
                    slots.release();
                  }
                });
      } catch (SocketException e) {
        if (closed) {
          return;
        }
        LOG.log(System.Logger.Level.WARNING, "proxy accept failed", e);
      } catch (IOException e) {
        LOG.log(System.Logger.Level.WARNING, "proxy accept failed", e);
      }
    }
  }

  private void handle(Socket client) {
    try {
      client.setTcpNoDelay(true);
      PushbackInputStream in = new PushbackInputStream(client.getInputStream(), 1);
      int first = in.read();
      if (first < 0) {
        return;
      }
      if (first == Socks5Session.VERSION) {
        new Socks5Session(client, dialer, credentials).run(in);
      } else if (first >= 'A' && first <= 'Z') {
        in.unread(first);
        new HttpProxySession(client, dialer, credentials).run(in);
      }
    } catch (IOException e) {
      LOG.log(System.Logger.Level.DEBUG, "proxy session failed", e);
    } finally {
      Relay.closeQuietly(client);
    }
  }

  /** Stops accepting connections. Sessions in progress run to completion. */
  @Override
  public void close() throws IOException {
    closed = true;
    server.close();
  }

  /** Builder for {@link LocalProxy}. */
  public static final class Builder {
    private final Netstack stack;
    private InetSocketAddress bind = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
    private String user;
    private String password;
    private boolean systemDnsFallback;
    private Duration connectTimeout = Duration.ofSeconds(10);
    private int maxConnections = 1024;

    private Builder(Netstack stack) {
      this.stack = Objects.requireNonNull(stack);
    }

    /** The host address to listen on (default: loopback, random port). */
    public Builder bind(InetSocketAddress address) {
      this.bind = address;
      return this;
    }

    /** Requires SOCKS5 username/password or HTTP Basic proxy authentication. */
    public Builder credentials(String user, String password) {
      this.user = Objects.requireNonNull(user);
      this.password = Objects.requireNonNull(password);
      return this;
    }

    /**
     * Whether names the tunnel's DNS cannot resolve may fall back to the host's resolver (default
     * false, which keeps lookups from leaking outside the tunnel).
     */
    public Builder systemDnsFallback(boolean allow) {
      this.systemDnsFallback = allow;
      return this;
    }

    /** How long to wait for tunnel connections (default 10 s). */
    public Builder connectTimeout(Duration timeout) {
      this.connectTimeout = timeout;
      return this;
    }

    /** Maximum concurrent proxied connections (default 1024). */
    public Builder maxConnections(int max) {
      this.maxConnections = max;
      return this;
    }

    /** Binds and starts the proxy. */
    public LocalProxy build() throws IOException {
      return new LocalProxy(this);
    }
  }
}
