// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.netstack;

import com.skanavi.javaguard.core.HostAddress;
import com.skanavi.javaguard.core.Scheduler;
import com.skanavi.javaguard.core.Tun;
import java.io.IOException;
import java.net.BindException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * A userspace IP host on the inner side of a tunnel. As a {@link Tun} it is handed to a {@link
 * com.skanavi.javaguard.core.Device}; the application then uses {@link #openUdp()}, {@link
 * #ping(InetAddress, Duration)} and {@link #dns()} to talk to hosts reachable through the tunnel.
 *
 * <pre>{@code
 * Netstack stack = Netstack.builder().address("10.0.0.2/32").dns("10.0.0.1").build();
 * Device device = Device.builder().privateKey(key).bind(UdpBind.open(0)).tun(stack).build();
 * ...
 * List<InetAddress> addrs = stack.dns().resolve("intranet.example");
 * }</pre>
 *
 * <p>Answers ICMP and ICMPv6 echo requests to its addresses. IP fragments and IPv6 extension
 * headers are dropped. Thread-safe.
 */
public final class Netstack implements Tun {
  private static final byte[] CLOSED = new byte[0];
  private static final int EPHEMERAL_FIRST = 49152;
  private static final int EPHEMERAL_COUNT = 65536 - EPHEMERAL_FIRST;
  private static final byte[] PING_PAYLOAD = "javaguard netstack ping 0123456789".getBytes();

  private final int mtu;
  private final List<InetAddress> addresses;
  private final byte[] ipv4;
  private final byte[] ipv6;
  private final BlockingQueue<byte[]> outbound;
  private final ConcurrentHashMap<Integer, UdpSocket> udp = new ConcurrentHashMap<>();
  private final ConcurrentHashMap<Long, PendingPing> pings = new ConcurrentHashMap<>();
  private final SecureRandom random = new SecureRandom();
  private final AtomicInteger ipv4Id = new AtomicInteger();
  private final AtomicInteger pingSequence = new AtomicInteger();
  private final int pingId = random.nextInt(0x10000);
  private final AtomicLong dropped = new AtomicLong();
  private final DnsResolver dns;
  private final ConcurrentHashMap<TcpKey, TcpConnection> tcp = new ConcurrentHashMap<>();
  private final ConcurrentHashMap<Integer, TcpListener> listeners = new ConcurrentHashMap<>();
  private final Scheduler scheduler;
  private final boolean ownsScheduler;
  private final long minRtoNanos;
  private final long timeWaitNanos;
  private final boolean tcpSack;
  private final BlockingQueue<byte[]> inbound;
  private final Thread inboundThread;
  private volatile boolean closed;

  private record PendingPing(byte[] from, CompletableFuture<Long> reply) {}

  private Netstack(Builder b) {
    if (b.addresses.isEmpty()) {
      throw new IllegalArgumentException("a netstack needs at least one address");
    }
    this.mtu = b.mtu;
    List<InetAddress> addrs = new ArrayList<>();
    byte[] v4 = null;
    byte[] v6 = null;
    for (HostAddress p : b.addresses) {
      addrs.add(p.address());
      if (p.isIpv4() && v4 == null) {
        v4 = p.address().getAddress();
      } else if (!p.isIpv4() && v6 == null) {
        v6 = p.address().getAddress();
      }
    }
    this.addresses = List.copyOf(addrs);
    this.ipv4 = v4;
    this.ipv6 = v6;
    this.outbound = new ArrayBlockingQueue<>(b.queueCapacity + 1);
    this.dns = new DnsResolver(this, b.dnsServers, b.searchDomains);
    this.scheduler = b.scheduler != null ? b.scheduler : Scheduler.newDefault();
    this.ownsScheduler = b.scheduler == null;
    this.minRtoNanos = b.minRto.toNanos();
    this.timeWaitNanos = b.timeWait.toNanos();
    this.tcpSack = b.tcpSack;
    // Inbound packets are processed on their own thread, so the device's receive thread can go
    // back to decrypting while TCP processing runs on another core.
    this.inbound = new ArrayBlockingQueue<>(b.queueCapacity + 1);
    this.inboundThread = new Thread(this::inboundLoop, "javaguard-netstack-rx");
    inboundThread.setDaemon(true);
    inboundThread.start();
  }

  /** Starts building a netstack. */
  public static Builder builder() {
    return new Builder();
  }

  /** This host's addresses inside the tunnel. */
  public List<InetAddress> addresses() {
    return addresses;
  }

  /** The DNS resolver using the configured servers through the tunnel. */
  public DnsResolver dns() {
    return dns;
  }

  /** Packets dropped because the inbound or outbound queue was full. */
  public long droppedPackets() {
    return dropped.get();
  }

  // ---------------------------------------------------------------- application API

  /** Opens a UDP socket on a random ephemeral port. */
  public UdpSocket openUdp() throws IOException {
    for (int i = 0; i < EPHEMERAL_COUNT; i++) {
      int port = EPHEMERAL_FIRST + random.nextInt(EPHEMERAL_COUNT);
      UdpSocket s = new UdpSocket(this, port);
      if (udp.putIfAbsent(port, s) == null) {
        return s;
      }
    }
    throw new BindException("no free ephemeral UDP port");
  }

  /** Opens a UDP socket on {@code port}. */
  public UdpSocket openUdp(int port) throws IOException {
    if (port < 1 || port > 65535) {
      throw new IllegalArgumentException("port out of range: " + port);
    }
    UdpSocket s = new UdpSocket(this, port);
    if (udp.putIfAbsent(port, s) != null) {
      throw new BindException("UDP port " + port + " is in use");
    }
    return s;
  }

  /**
   * Sends one ICMP (or ICMPv6) echo request and waits for the reply.
   *
   * @return the round-trip time, or empty on timeout
   */
  public Optional<Duration> ping(InetAddress target, Duration timeout) throws InterruptedException {
    byte[] dst = target.getAddress();
    byte[] src = sourceFor(target);
    int seq = pingSequence.incrementAndGet() & 0xffff;
    boolean v4 = dst.length == 4;
    long key = pingKey(v4 ? 4 : 6, pingId, seq);
    PendingPing pending = new PendingPing(dst, new CompletableFuture<>());
    pings.put(key, pending);
    try {
      int icmpLength = 8 + PING_PAYLOAD.length;
      byte[] p =
          IpPacket.build(src, dst, v4 ? IpPacket.ICMP : IpPacket.ICMPV6, icmpLength, nextId());
      int off = IpPacket.headerLength(v4 ? 4 : 6);
      p[off] = (byte) (v4 ? 8 : 128);
      IpPacket.put16(p, off + 4, pingId);
      IpPacket.put16(p, off + 6, seq);
      System.arraycopy(PING_PAYLOAD, 0, p, off + 8, PING_PAYLOAD.length);
      IpPacket.put16(p, off + 2, icmpChecksum(v4, src, dst, p, off, icmpLength));
      long start = System.nanoTime();
      send(p);
      long end = pending.reply().get(timeout.toNanos(), TimeUnit.NANOSECONDS);
      return Optional.of(Duration.ofNanos(end - start));
    } catch (TimeoutException e) {
      return Optional.empty();
    } catch (ExecutionException e) {
      throw new IllegalStateException(e);
    } finally {
      pings.remove(key);
    }
  }

  /**
   * Opens a TCP connection, waiting up to {@code timeout} for the handshake.
   *
   * @throws java.net.ConnectException if the peer refuses
   * @throws java.net.SocketTimeoutException on timeout
   */
  public TcpSocket connectTcp(InetSocketAddress remote, Duration timeout) throws IOException {
    if (remote.isUnresolved()) {
      throw new IllegalArgumentException("remote must be resolved: " + remote);
    }
    if (closed) {
      throw new IOException("netstack is closed");
    }
    InetAddress local = IpPacket.address(sourceFor(remote.getAddress()));
    for (int i = 0; i < EPHEMERAL_COUNT; i++) {
      int port = EPHEMERAL_FIRST + random.nextInt(EPHEMERAL_COUNT);
      if (listeners.containsKey(port)) {
        continue;
      }
      TcpKey key = new TcpKey(local, port, remote.getAddress(), remote.getPort());
      TcpConnection c = new TcpConnection(this, key);
      if (tcp.putIfAbsent(key, c) == null) {
        c.connect(timeout.toNanos());
        return new TcpSocket(c);
      }
    }
    throw new BindException("no free ephemeral TCP port");
  }

  /** Listens for TCP connections on {@code port} with a backlog of 128. */
  public TcpListener listenTcp(int port) throws IOException {
    return listenTcp(port, 128);
  }

  /** Listens for TCP connections on {@code port}. */
  public TcpListener listenTcp(int port, int backlog) throws IOException {
    if (port < 1 || port > 65535) {
      throw new IllegalArgumentException("port out of range: " + port);
    }
    TcpListener l = new TcpListener(this, port, backlog);
    if (listeners.putIfAbsent(port, l) != null) {
      throw new BindException("TCP port " + port + " is in use");
    }
    return l;
  }

  // ---------------------------------------------------------------- Tun

  @Override
  public int mtu() {
    return mtu;
  }

  @Override
  public int read(byte[] buf, int off, int len) {
    try {
      byte[] p = outbound.take();
      if (p == CLOSED) {
        outbound.offer(CLOSED);
        return -1;
      }
      int n = Math.min(p.length, len);
      System.arraycopy(p, 0, buf, off, n);
      return n;
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      return -1;
    }
  }

  /** Queues an incoming packet for processing; drops it if the inbound queue is full. */
  @Override
  public void write(byte[] buf, int off, int len) {
    if (!closed && !inbound.offer(Arrays.copyOfRange(buf, off, off + len))) {
      dropped.incrementAndGet();
    }
  }

  private void inboundLoop() {
    try {
      while (true) {
        byte[] p = inbound.take();
        if (p == CLOSED) {
          return;
        }
        receive(p, p.length);
      }
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }

  /** Processes one incoming packet on the calling thread. */
  void receive(byte[] p, int len) {
    if (closed) {
      return;
    }
    IpPacket ip = IpPacket.parse(p, len);
    if (ip == null || !isLocal(ip.dst())) {
      return;
    }
    switch (ip.protocol()) {
      case IpPacket.ICMP -> {
        if (ip.version() == 4) {
          icmp(ip);
        }
      }
      case IpPacket.ICMPV6 -> {
        if (ip.version() == 6) {
          icmp(ip);
        }
      }
      case IpPacket.UDP -> udp(ip);
      case IpPacket.TCP -> tcp(ip);
      default -> {}
    }
  }

  @Override
  public void close() {
    closed = true;
    for (UdpSocket s : List.copyOf(udp.values())) {
      s.close();
    }
    for (TcpListener l : List.copyOf(listeners.values())) {
      l.close();
    }
    for (TcpConnection c : List.copyOf(tcp.values())) {
      c.abort();
    }
    if (ownsScheduler) {
      scheduler.close();
    }
    inbound.clear();
    inbound.offer(CLOSED);
    outbound.clear();
    outbound.offer(CLOSED);
  }

  // ---------------------------------------------------------------- internals

  private void icmp(IpPacket ip) {
    boolean v4 = ip.version() == 4;
    int off = ip.payloadOffset();
    int len = ip.payloadLength();
    byte[] p = ip.data();
    if (len < 8 || icmpChecksum(v4, ip.src(), ip.dst(), p, off, len) != 0) {
      return;
    }
    int type = p[off] & 0xff;
    int code = p[off + 1] & 0xff;
    if (code != 0) {
      return;
    }
    if (type == (v4 ? 8 : 128)) {
      byte[] reply = IpPacket.build(ip.dst(), ip.src(), ip.protocol(), len, nextId());
      int r = IpPacket.headerLength(ip.version());
      System.arraycopy(p, off, reply, r, len);
      reply[r] = (byte) (v4 ? 0 : 129);
      IpPacket.put16(reply, r + 2, 0);
      IpPacket.put16(reply, r + 2, icmpChecksum(v4, ip.dst(), ip.src(), reply, r, len));
      send(reply);
    } else if (type == (v4 ? 0 : 129)) {
      long key = pingKey(ip.version(), IpPacket.u16(p, off + 4), IpPacket.u16(p, off + 6));
      PendingPing pending = pings.get(key);
      if (pending != null && Arrays.equals(pending.from(), ip.src())) {
        pending.reply().complete(System.nanoTime());
      }
    }
  }

  private void udp(IpPacket ip) {
    byte[] p = ip.data();
    int off = ip.payloadOffset();
    if (ip.payloadLength() < 8) {
      return;
    }
    int length = IpPacket.u16(p, off + 4);
    int checksum = IpPacket.u16(p, off + 6);
    if (length < 8 || length > ip.payloadLength()) {
      return;
    }
    if (checksum != 0 || ip.version() == 6) {
      long sum = Checksum.pseudoHeader(ip.src(), ip.dst(), IpPacket.UDP, length);
      if (checksum == 0 || Checksum.finish(Checksum.add(sum, p, off, length)) != 0) {
        return;
      }
    }
    UdpSocket socket = udp.get(IpPacket.u16(p, off + 2));
    if (socket != null) {
      InetSocketAddress source = new InetSocketAddress(ip.srcAddress(), IpPacket.u16(p, off));
      socket.deliver(new UdpSocket.Datagram(source, Arrays.copyOfRange(p, off + 8, off + length)));
    }
  }

  private void tcp(IpPacket ip) {
    TcpSegment seg = TcpSegment.parse(ip);
    if (seg == null) {
      return;
    }
    InetAddress local = ip.dstAddress();
    InetAddress remote = ip.srcAddress();
    TcpConnection c = tcp.get(new TcpKey(local, seg.dstPort(), remote, seg.srcPort()));
    TcpListener l = listeners.get(seg.dstPort());
    if (c != null && (l == null || !c.yieldToNewConnection(seg))) {
      c.onSegment(seg);
      return;
    }
    if (l != null
        && seg.has(TcpSegment.SYN)
        && !seg.has(TcpSegment.ACK)
        && !seg.has(TcpSegment.RST)) {
      l.onSyn(local, remote, seg);
      return;
    }
    if (!seg.has(TcpSegment.RST)) {
      // No such connection (RFC 9293 3.10.7.1): reset.
      if (seg.has(TcpSegment.ACK)) {
        sendTcp(
            ip.dst(),
            ip.src(),
            seg.dstPort(),
            seg.srcPort(),
            seg.ack(),
            0,
            TcpSegment.RST,
            0,
            -1,
            -1,
            null,
            0,
            0);
      } else {
        sendTcp(
            ip.dst(),
            ip.src(),
            seg.dstPort(),
            seg.srcPort(),
            0,
            seg.seq() + seg.sequenceLength(),
            TcpSegment.RST | TcpSegment.ACK,
            0,
            -1,
            -1,
            null,
            0,
            0);
      }
    }
  }

  void sendTcp(
      byte[] src,
      byte[] dst,
      int srcPort,
      int dstPort,
      int seq,
      int ack,
      int flags,
      int window,
      int mss,
      int windowScale,
      byte[] data,
      int off,
      int len) {
    sendTcp(
        src,
        dst,
        srcPort,
        dstPort,
        seq,
        ack,
        flags,
        window,
        mss,
        windowScale,
        false,
        null,
        data,
        off,
        len);
  }

  void sendTcp(
      byte[] src,
      byte[] dst,
      int srcPort,
      int dstPort,
      int seq,
      int ack,
      int flags,
      int window,
      int mss,
      int windowScale,
      boolean sackPermitted,
      int[] sackBlocks,
      byte[] data,
      int off,
      int len) {
    send(
        TcpSegment.build(
            src,
            dst,
            srcPort,
            dstPort,
            seq,
            ack,
            flags,
            window,
            mss,
            windowScale,
            sackPermitted,
            sackBlocks,
            data,
            off,
            len,
            nextId()));
  }

  void registerTcp(TcpKey key, TcpConnection c) {
    if (tcp.putIfAbsent(key, c) != null) {
      c.abort();
    }
  }

  void removeTcp(TcpKey key, TcpConnection c) {
    tcp.remove(key, c);
  }

  void removeListener(int port, TcpListener l) {
    listeners.remove(port, l);
  }

  Scheduler scheduler() {
    return scheduler;
  }

  long minRtoNanos() {
    return minRtoNanos;
  }

  long timeWaitNanos() {
    return timeWaitNanos;
  }

  boolean tcpSack() {
    return tcpSack;
  }

  int randomInt() {
    return random.nextInt();
  }

  /** Descriptions of all TCP connections, for diagnostics. */
  List<String> tcpDiagnostics() {
    return tcp.values().stream().map(TcpConnection::toString).toList();
  }

  /** Number of TCP connections in any state, for tests. */
  int tcpConnectionCount() {
    return tcp.size();
  }

  /** Largest UDP payload that fits in one packet to a destination of this family. */
  int maxUdpPayload(InetAddress to) {
    return mtu - IpPacket.headerLength(to instanceof Inet4Address ? 4 : 6) - 8;
  }

  void sendUdp(int srcPort, InetSocketAddress to, byte[] data, int off, int len) {
    byte[] dst = to.getAddress().getAddress();
    byte[] src = sourceFor(to.getAddress());
    int udpLength = 8 + len;
    byte[] p = IpPacket.build(src, dst, IpPacket.UDP, udpLength, nextId());
    int u = IpPacket.headerLength(dst.length == 4 ? 4 : 6);
    IpPacket.put16(p, u, srcPort);
    IpPacket.put16(p, u + 2, to.getPort());
    IpPacket.put16(p, u + 4, udpLength);
    System.arraycopy(data, off, p, u + 8, len);
    long sum = Checksum.pseudoHeader(src, dst, IpPacket.UDP, udpLength);
    int checksum = Checksum.finish(Checksum.add(sum, p, u, udpLength));
    IpPacket.put16(p, u + 6, checksum == 0 ? 0xffff : checksum);
    send(p);
  }

  void release(UdpSocket socket) {
    udp.remove(socket.localPort(), socket);
  }

  boolean isClosed() {
    return closed;
  }

  private void send(byte[] packet) {
    if (!closed && !outbound.offer(packet)) {
      dropped.incrementAndGet();
    }
  }

  private byte[] sourceFor(InetAddress destination) {
    byte[] src = destination instanceof Inet4Address ? ipv4 : ipv6;
    if (src == null) {
      throw new IllegalArgumentException(
          "no " + (destination instanceof Inet4Address ? "IPv4" : "IPv6") + " address configured");
    }
    return src;
  }

  private boolean isLocal(byte[] dst) {
    return Arrays.equals(dst, dst.length == 4 ? ipv4 : ipv6) || addressesContain(dst);
  }

  private boolean addressesContain(byte[] dst) {
    for (InetAddress a : addresses) {
      if (Arrays.equals(a.getAddress(), dst)) {
        return true;
      }
    }
    return false;
  }

  private int nextId() {
    return ipv4Id.incrementAndGet() & 0xffff;
  }

  private static int icmpChecksum(boolean v4, byte[] src, byte[] dst, byte[] p, int off, int len) {
    long sum = v4 ? 0 : Checksum.pseudoHeader(src, dst, IpPacket.ICMPV6, len);
    return Checksum.finish(Checksum.add(sum, p, off, len));
  }

  private static long pingKey(int version, int id, int seq) {
    return ((long) version << 32) | ((long) id << 16) | seq;
  }

  /** Builder for {@link Netstack}. */
  public static final class Builder {
    private final List<HostAddress> addresses = new ArrayList<>();
    private final List<InetAddress> dnsServers = new ArrayList<>();
    private final List<String> searchDomains = new ArrayList<>();
    private int mtu = 1420;
    private int queueCapacity = 4096;
    private Scheduler scheduler;
    private Duration minRto = Duration.ofMillis(200);
    private Duration timeWait = Duration.ofSeconds(60);
    private boolean tcpSack = true;

    private Builder() {}

    /** Adds an address in {@code address/length} form; the first of each family is the source. */
    public Builder address(String address) {
      return address(HostAddress.parse(address));
    }

    /** Adds an address. */
    public Builder address(HostAddress address) {
      addresses.add(address);
      return this;
    }

    /** Adds addresses, as from a wg-quick {@code Address} line. */
    public Builder addresses(List<HostAddress> list) {
      addresses.addAll(list);
      return this;
    }

    /** Adds a DNS server by literal address. */
    public Builder dns(String server) {
      return dns(InetAddress.ofLiteral(server));
    }

    /** Adds a DNS server. */
    public Builder dns(InetAddress server) {
      dnsServers.add(server);
      return this;
    }

    /** Adds DNS servers. */
    public Builder dnsServers(List<InetAddress> servers) {
      dnsServers.addAll(servers);
      return this;
    }

    /** Adds DNS search domains. */
    public Builder searchDomains(List<String> domains) {
      searchDomains.addAll(domains);
      return this;
    }

    /** Sets the MTU (default 1420). */
    public Builder mtu(int mtu) {
      if (mtu < 1280 || mtu > 65535) {
        throw new IllegalArgumentException("MTU must be 1280..65535 (IPv6 minimum is 1280)");
      }
      this.mtu = mtu;
      return this;
    }

    /**
     * Timer scheduler for TCP; defaults to a private daemon thread. A supplied one is not closed.
     */
    public Builder scheduler(Scheduler scheduler) {
      this.scheduler = scheduler;
      return this;
    }

    /** Minimum TCP retransmission timeout (default 200 ms, as in Linux). */
    public Builder tcpMinRto(Duration minRto) {
      this.minRto = minRto;
      return this;
    }

    /** How long closed TCP connections linger in TIME_WAIT (default 60 s). */
    public Builder tcpTimeWait(Duration timeWait) {
      this.timeWait = timeWait;
      return this;
    }

    /** Whether TCP offers and uses SACK (default true); off falls back to NewReno recovery. */
    public Builder tcpSack(boolean enabled) {
      this.tcpSack = enabled;
      return this;
    }

    /** Builds the netstack. */
    public Netstack build() {
      return new Netstack(this);
    }
  }
}
