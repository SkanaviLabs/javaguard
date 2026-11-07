// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.server;

import com.skanavi.javaguard.config.ConfigException;
import com.skanavi.javaguard.config.WgQuickConfig;
import com.skanavi.javaguard.core.Device;
import com.skanavi.javaguard.core.IpPrefix;
import com.skanavi.javaguard.core.Peer;
import com.skanavi.javaguard.core.PeerConfig;
import com.skanavi.javaguard.core.UdpBind;
import com.skanavi.javaguard.crypto.PublicKey;
import com.skanavi.javaguard.netstack.Netstack;
import com.skanavi.javaguard.netstack.TcpListener;
import com.skanavi.javaguard.netstack.TcpSocket;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.file.Path;
import java.time.Duration;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;

/**
 * A WireGuard server inside this JVM. Peers connect to it as to any WireGuard server, but they can
 * reach only the ports opened here: the network stack ends their traffic instead of routing it, so
 * they cannot reach each other or anything beyond this host's own listeners.
 *
 * <pre>{@code
 * try (TunnelHost host = TunnelHost.start(Path.of("server.conf"))) {
 *   host.serveTcp(7000, c -> handle(c.peer(), c.socket()));
 *   host.expose(443, Target.unixSocket(Path.of("/run/app/web.sock")), ProxyHeader.V2);
 *   host.awaitClose();
 * }
 * }</pre>
 *
 * <p>Each address belongs to exactly one peer, so {@link TunnelConnection#peer()} is an
 * authenticated identity: configurations must give every peer its own {@code /32} or {@code /128}
 * addresses. A connection is reset as soon as its address stops belonging to the peer that opened
 * it, whether the peer was removed or its address changed hands. Thread-safe.
 */
public final class TunnelHost implements AutoCloseable {
  private static final System.Logger LOG = System.getLogger(TunnelHost.class.getName());

  private final Device device;
  private final Netstack stack;
  private final Duration keepAlive;
  private final List<TcpListener> listeners = new CopyOnWriteArrayList<>();
  private final Set<Active> active = ConcurrentHashMap.newKeySet();
  private final CountDownLatch closedLatch = new CountDownLatch(1);
  private volatile boolean closed;

  private record Active(TcpSocket socket, Peer peer) {}

  private TunnelHost(Device device, Netstack stack, Duration keepAlive) {
    this.device = device;
    this.stack = stack;
    this.keepAlive = keepAlive;
    device.onRoutesChanged(this::dropDisowned);
  }

  /** Starts a host with default limits from a configuration file. */
  public static TunnelHost start(Path config) throws IOException, ConfigException {
    return builder().start(WgQuickConfig.parse(config));
  }

  /** Starts building a host. */
  public static Builder builder() {
    return new Builder();
  }

  /**
   * Serves a tunnel port with {@code handler}, giving each connection its own virtual thread.
   *
   * @throws java.net.BindException if the port is in use
   */
  public void serveTcp(int port, ConnectionHandler handler) throws IOException {
    Objects.requireNonNull(handler, "handler");
    if (closed) {
      throw new IOException("host is closed");
    }
    TcpListener listener = stack.listenTcp(port);
    listeners.add(listener);
    Thread.ofVirtual()
        .name("javaguard-host-accept-" + port)
        .start(() -> acceptLoop(listener, handler));
  }

  /** Relays a tunnel port to a local listener, telling it nothing about the peer. */
  public void expose(int port, Target target) throws IOException {
    expose(port, target, ProxyHeader.NONE);
  }

  /**
   * Relays a tunnel port to a local listener. The listener sees every peer as a local client unless
   * {@code header} says otherwise, so with {@link ProxyHeader#NONE} it must not trust local
   * clients.
   */
  public void expose(int port, Target target, ProxyHeader header) throws IOException {
    Objects.requireNonNull(target, "target");
    Objects.requireNonNull(header, "header");
    serveTcp(port, new LocalRelay(target, header));
  }

  /**
   * Adds a peer at runtime.
   *
   * @throws IllegalArgumentException if it has no addresses, an address is not a single host, or an
   *     address belongs to this host or another peer
   */
  public Peer addPeer(PeerConfig config) {
    if (config.allowedIps().isEmpty()) {
      throw new IllegalArgumentException("a peer needs AllowedIPs");
    }
    for (IpPrefix prefix : config.allowedIps()) {
      if (!isHost(prefix)) {
        throw new IllegalArgumentException(notHost(prefix));
      }
      if (stack.addresses().contains(prefix.address())) {
        throw new IllegalArgumentException(prefix + " is this host's own address");
      }
      if (device.peerFor(prefix.address()).isPresent()) {
        throw new IllegalArgumentException(prefix + " already belongs to a peer");
      }
    }
    return device.addPeer(config);
  }

  /** Removes a peer and resets its connections; returns whether it existed. */
  public boolean removePeer(PublicKey publicKey) {
    return device.removePeer(publicKey);
  }

  /** The WireGuard device. Changes made to it directly skip the checks of this class. */
  public Device device() {
    return device;
  }

  /** The network stack, for UDP sockets and counters. */
  public Netstack stack() {
    return stack;
  }

  /** Waits until this host is closed. */
  public void awaitClose() throws InterruptedException {
    closedLatch.await();
  }

  /** Stops listening, resets every connection and closes the device. */
  @Override
  public void close() throws IOException {
    if (closed) {
      return;
    }
    closed = true;
    listeners.forEach(TcpListener::close);
    active.forEach(a -> a.socket().abort());
    try {
      device.close();
    } finally {
      closedLatch.countDown();
    }
  }

  private void acceptLoop(TcpListener listener, ConnectionHandler handler) {
    while (true) {
      TcpSocket socket;
      try {
        socket = listener.accept();
      } catch (IOException e) {
        return; // the listener closed
      }
      Thread.ofVirtual().name("javaguard-host-conn").start(() -> serve(socket, handler));
    }
  }

  private void serve(TcpSocket socket, ConnectionHandler handler) {
    Peer peer = device.peerFor(socket.remoteAddress().getAddress()).orElse(null);
    if (peer == null) {
      socket.abort(); // removed while the connection waited to be accepted
      return;
    }
    Active entry = new Active(socket, peer);
    active.add(entry);
    try {
      if (closed || !owned(entry)) { // changed before dropDisowned could see the entry
        socket.abort();
        return;
      }
      socket.keepAlive(keepAlive);
      handler.handle(new TunnelConnection(peer.publicKey(), socket));
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      socket.abort();
    } catch (Exception e) {
      LOG.log(System.Logger.Level.DEBUG, "connection from {0} failed: {1}", peer, e);
      socket.abort();
    } finally {
      active.remove(entry);
      socket.close();
    }
  }

  private void dropDisowned() {
    for (Active a : active) {
      if (!owned(a)) {
        a.socket().abort();
      }
    }
  }

  private boolean owned(Active a) {
    InetAddress address = a.socket().remoteAddress().getAddress();
    return device.peerFor(address).orElse(null) == a.peer();
  }

  private static boolean isHost(IpPrefix prefix) {
    return prefix.length() == (prefix.isIpv4() ? 32 : 128);
  }

  private static String notHost(IpPrefix prefix) {
    return "AllowedIPs "
        + prefix
        + " is not a single address: a host peer needs its own /32 or /128";
  }

  private static void validate(WgQuickConfig config) throws ConfigException {
    if (config.iface().addresses().isEmpty()) {
      throw new ConfigException(0, "[Interface] needs an Address for peers to connect to");
    }
    if (config.iface().listenPort() == null) {
      throw new ConfigException(0, "[Interface] needs a ListenPort for peers to connect to");
    }
    Set<InetAddress> own = new HashSet<>();
    config.iface().addresses().forEach(a -> own.add(a.address()));
    Set<IpPrefix> seen = new HashSet<>();
    for (WgQuickConfig.PeerSection peer : config.peers()) {
      if (peer.allowedIps().isEmpty()) {
        throw new ConfigException(0, "peer " + peer.publicKey() + " needs AllowedIPs");
      }
      for (IpPrefix prefix : peer.allowedIps()) {
        if (!isHost(prefix)) {
          throw new ConfigException(0, notHost(prefix));
        }
        if (own.contains(prefix.address())) {
          throw new ConfigException(0, "AllowedIPs " + prefix + " is this host's own address");
        }
        if (!seen.add(prefix)) {
          throw new ConfigException(0, "AllowedIPs " + prefix + " is given to two peers");
        }
      }
    }
  }

  /** Builder for {@link TunnelHost}. */
  public static final class Builder {
    private int maxConnections = 1024;
    private int maxConnectionsPerPeer = 64;
    private Duration keepAlive = Duration.ofSeconds(60);

    private Builder() {}

    /** Maximum inbound TCP connections from all peers (default 1024, about 512 MiB of buffers). */
    public Builder maxConnections(int max) {
      this.maxConnections = max;
      return this;
    }

    /** Maximum inbound TCP connections per peer address (default 64). */
    public Builder maxConnectionsPerPeer(int max) {
      this.maxConnectionsPerPeer = max;
      return this;
    }

    /** Idle time before probing whether a peer is still there (default 60 s); zero for never. */
    public Builder keepAlive(Duration idle) {
      this.keepAlive = Objects.requireNonNull(idle, "idle");
      return this;
    }

    /**
     * Validates {@code config} and starts the host.
     *
     * @throws ConfigException if it lacks an Address or ListenPort, or a peer does not have
     *     addresses of its own
     */
    public TunnelHost start(WgQuickConfig config) throws IOException, ConfigException {
      validate(config);
      List<PeerConfig> peers = config.resolvePeers();
      Netstack stack =
          Netstack.builder()
              .addresses(config.iface().addresses())
              .mtu(config.iface().mtu() != null ? config.iface().mtu() : 1420)
              .tcpMaxInbound(maxConnections)
              .tcpMaxInboundPerRemote(maxConnectionsPerPeer)
              .build();
      Device device;
      try {
        device =
            Device.builder()
                .privateKey(config.iface().privateKey())
                .bind(UdpBind.open(config.iface().listenPort()))
                .tun(stack)
                .build();
      } catch (IOException | RuntimeException e) {
        stack.close();
        throw e;
      }
      TunnelHost host = new TunnelHost(device, stack, keepAlive);
      try {
        peers.forEach(device::addPeer);
        device.start();
      } catch (RuntimeException e) {
        host.close();
        throw e;
      }
      return host;
    }
  }
}
