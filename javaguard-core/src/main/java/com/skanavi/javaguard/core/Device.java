// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core;

// Portions derived from wireguard-go (https://git.zx2c4.com/wireguard-go/),
// Copyright (C) 2017-2025 WireGuard LLC. MIT.

import com.skanavi.javaguard.core.noise.CookieChecker;
import com.skanavi.javaguard.core.noise.CookieReply;
import com.skanavi.javaguard.core.noise.Handshake;
import com.skanavi.javaguard.core.noise.HandshakeInitiation;
import com.skanavi.javaguard.core.noise.HandshakeMessage;
import com.skanavi.javaguard.core.noise.HandshakeResponse;
import com.skanavi.javaguard.core.noise.IndexTable;
import com.skanavi.javaguard.core.noise.Keypair;
import com.skanavi.javaguard.core.noise.Messages;
import com.skanavi.javaguard.core.noise.Noise;
import com.skanavi.javaguard.core.noise.Protocol;
import com.skanavi.javaguard.core.noise.StaticIdentity;
import com.skanavi.javaguard.core.noise.TimeSource;
import com.skanavi.javaguard.crypto.ChaCha20Poly1305;
import com.skanavi.javaguard.crypto.PrivateKey;
import com.skanavi.javaguard.crypto.PublicKey;
import java.io.Closeable;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.channels.ClosedChannelException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.random.RandomGenerator;
import javax.crypto.AEADBadTagException;

/**
 * A WireGuard interface: one static key pair, a set of {@link Peer}s, a {@link Bind} carrying
 * encrypted UDP traffic and a {@link Tun} carrying plaintext IP packets.
 *
 * <pre>{@code
 * Device device = Device.builder()
 *     .privateKey(PrivateKey.fromBase64("..."))
 *     .bind(UdpBind.open(51820))
 *     .tun(new PacketPipe(1420))
 *     .build();
 * device.addPeer(PeerConfig.builder(PublicKey.fromBase64("..."))
 *     .endpoint(new InetSocketAddress("192.0.2.1", 51820))
 *     .allowedIp("10.0.0.0/24")
 *     .build());
 * device.start();
 * }</pre>
 *
 * <p>Threads: one reads the bind, one reads the tun, one processes handshake messages, and one runs
 * timers. Transport encryption and decryption run on a pool of crypto workers (see {@link
 * Builder#cryptoThreads(int)}), with packets completed in their original order.
 */
public final class Device implements Closeable {
  private static final System.Logger LOG = System.getLogger(Device.class.getName());
  private static final ThreadLocal<ChaCha20Poly1305> AEAD =
      ThreadLocal.withInitial(ChaCha20Poly1305::new);
  private static final int HANDSHAKE_QUEUE_SIZE = 1024;
  private static final int UNDER_LOAD_QUEUE_SIZE = HANDSHAKE_QUEUE_SIZE / 8;
  private static final long UNDER_LOAD_AFTER_NANOS = TimeUnit.SECONDS.toNanos(1);
  private static final long MAX_JITTER_NANOS = TimeUnit.MILLISECONDS.toNanos(333);

  final TimeSource time;
  final Scheduler scheduler;
  private final boolean ownsScheduler;
  private final SecureRandom random;
  private final RandomGenerator jitter;
  private volatile Bind bind;
  private final Tun tun;
  final int mtu;

  final IndexTable indices = new IndexTable();
  final AllowedIps<Peer> allowedIps = new AllowedIps<>();
  private final List<Runnable> routeListeners = new CopyOnWriteArrayList<>();
  private final ConcurrentHashMap<PublicKey, Peer> peers = new ConcurrentHashMap<>();
  private final RateLimiter rateLimiter;

  /** Readers: anything using {@link #noise} or {@link #cookieChecker}; writer: key changes. */
  final ReadWriteLock identityLock = new ReentrantReadWriteLock();

  volatile Noise noise;
  private volatile CookieChecker cookieChecker;

  private final ExecutorService cryptoWorkers;
  final CryptoPipeline encryptPipeline;
  private final CryptoPipeline decryptPipeline;
  private final Executor handshakeExecutor;
  private final ThreadPoolExecutor handshakePool;
  private final boolean manual;
  private volatile long underLoadUntilNanos;
  volatile boolean forceUnderLoad;

  private final Object lifecycleLock = new Object();
  private final List<Thread> threads = new ArrayList<>();
  private volatile boolean up;
  private volatile boolean closed;

  private Device(Builder b) {
    this.time = b.time;
    this.scheduler = b.scheduler != null ? b.scheduler : Scheduler.newDefault();
    this.ownsScheduler = b.scheduler == null;
    this.random = b.random;
    this.jitter = b.jitter;
    this.bind = b.bind;
    this.tun = b.tun;
    this.mtu = b.tun.mtu();
    this.rateLimiter = new RateLimiter(time);
    this.manual = b.handshakeExecutor != null;
    if (manual) {
      this.handshakeExecutor = b.handshakeExecutor;
      this.handshakePool = null;
    } else {
      this.handshakePool =
          new ThreadPoolExecutor(
              1,
              1,
              0,
              TimeUnit.SECONDS,
              new ArrayBlockingQueue<>(HANDSHAKE_QUEUE_SIZE),
              r -> daemon(r, "javaguard-handshake"),
              new ThreadPoolExecutor.DiscardPolicy());
      this.handshakeExecutor = handshakePool;
    }
    int cryptoThreads = manual ? 0 : b.cryptoThreads;
    if (cryptoThreads > 0) {
      this.cryptoWorkers =
          Executors.newFixedThreadPool(cryptoThreads, r -> daemon(r, "javaguard-crypto"));
      this.encryptPipeline = new CryptoPipeline(cryptoWorkers, 4096, "javaguard-encrypt");
      this.decryptPipeline = new CryptoPipeline(cryptoWorkers, 4096, "javaguard-decrypt");
    } else {
      this.cryptoWorkers = null;
      this.encryptPipeline = null;
      this.decryptPipeline = null;
    }
    StaticIdentity identity = new StaticIdentity(b.privateKey);
    this.noise = new Noise(identity, indices, time, random);
    this.cookieChecker = new CookieChecker(identity, time, random);
  }

  /** Starts building a device. */
  public static Builder builder() {
    return new Builder();
  }

  // ---------------------------------------------------------------- configuration

  /** The local public key. */
  public PublicKey publicKey() {
    return noise.identity().publicKey();
  }

  /** The local private key. */
  public PrivateKey privateKey() {
    return noise.identity().privateKey();
  }

  /**
   * Changes the local private key. All sessions are dropped and peers re-handshake on demand. A
   * peer whose public key equals the new local public key is removed.
   */
  public void privateKey(PrivateKey key) {
    if (key.equals(privateKey())) {
      return;
    }
    StaticIdentity identity = new StaticIdentity(key);
    removePeer(identity.publicKey());
    identityLock.writeLock().lock();
    try {
      Noise newNoise = new Noise(identity, indices, time, random);
      for (Peer peer : peers.values()) {
        peer.expireSessions();
        Handshake hs;
        try {
          hs = newNoise.newHandshake(peer.publicKey(), peer.presharedKey());
        } catch (InvalidKeyException e) {
          throw new IllegalStateException("peer key was validated when added", e);
        }
        hs.attach(peer);
        peer.handshake = hs;
      }
      noise = newNoise;
      cookieChecker = new CookieChecker(identity, time, random);
    } finally {
      identityLock.writeLock().unlock();
    }
  }

  /** The UDP port of the bind. */
  public int listenPort() {
    return bind.localPort();
  }

  /**
   * Replaces the UDP bind, for example to change the listen port. The old bind is closed. Peers
   * keep their sessions and endpoints.
   */
  public void bind(Bind newBind) throws IOException {
    Objects.requireNonNull(newBind, "bind");
    Bind old;
    synchronized (lifecycleLock) {
      if (closed) {
        newBind.close();
        throw new IllegalStateException("device is closed");
      }
      old = bind;
      bind = newBind;
    }
    old.close();
  }

  /** The tun this device reads from and writes to. */
  public Tun tun() {
    return tun;
  }

  /**
   * Adds a peer.
   *
   * @throws IllegalArgumentException if a peer with that key exists, the key is the device's own,
   *     or the key is not a valid Curve25519 point
   */
  public Peer addPeer(PeerConfig config) {
    Peer peer;
    identityLock.readLock().lock();
    try {
      Handshake hs;
      try {
        hs = noise.newHandshake(config.publicKey(), config.presharedKey());
      } catch (InvalidKeyException e) {
        throw new IllegalArgumentException("invalid peer public key", e);
      }
      peer = new Peer(this, config.publicKey(), hs);
      hs.attach(peer);
      if (peers.putIfAbsent(config.publicKey(), peer) != null) {
        throw new IllegalArgumentException("peer already exists: " + config.publicKey());
      }
      peer.endpoint(config.endpoint());
      peer.initPersistentKeepalive(config.persistentKeepalive());
      for (IpPrefix prefix : config.allowedIps()) {
        allowedIps.insert(prefix, peer);
      }
    } finally {
      identityLock.readLock().unlock();
    }
    if (up && !config.persistentKeepalive().isZero()) {
      peer.sendKeepalive(); // outside the identity lock (see Peer lock order)
    }
    routesChanged();
    return peer;
  }

  /** Removes a peer, erasing its sessions. Returns whether it existed. */
  public boolean removePeer(PublicKey publicKey) {
    Peer peer = peers.remove(publicKey);
    if (peer == null) {
      return false;
    }
    allowedIps.removeAll(peer);
    peer.stop();
    routesChanged();
    return true;
  }

  /** The peer that {@code address} is routed to, which is the one allowed to send from it. */
  public Optional<Peer> peerFor(InetAddress address) {
    byte[] bytes = address.getAddress();
    return Optional.ofNullable(allowedIps.lookup(bytes, 0, bytes.length));
  }

  /**
   * Calls {@code listener} after a peer is added or removed or its allowed IPs change, however the
   * change was made, including through UAPI. It runs on the thread making the change, so it must be
   * quick; use {@link #peerFor(InetAddress)} to see the result.
   */
  public void onRoutesChanged(Runnable listener) {
    routeListeners.add(Objects.requireNonNull(listener, "listener"));
  }

  void routesChanged() {
    for (Runnable listener : routeListeners) {
      try {
        listener.run();
      } catch (RuntimeException e) {
        LOG.log(System.Logger.Level.WARNING, "route listener failed", e);
      }
    }
  }

  /** The peer with {@code publicKey}, or {@code null}. */
  public Peer peer(PublicKey publicKey) {
    return peers.get(publicKey);
  }

  /** All peers. */
  public Collection<Peer> peers() {
    return List.copyOf(peers.values());
  }

  // ---------------------------------------------------------------- lifecycle

  /** Brings the device up: starts I/O threads and sends initial persistent keepalives. */
  public void start() {
    synchronized (lifecycleLock) {
      if (closed) {
        throw new IllegalStateException("device is closed");
      }
      if (up) {
        return;
      }
      up = true;
      if (!manual) {
        threads.add(daemon(this::bindLoop, "javaguard-rx"));
        threads.add(daemon(this::tunLoop, "javaguard-tun"));
        threads.forEach(Thread::start);
      }
    }
    for (Peer peer : peers.values()) {
      if (!peer.persistentKeepalive().isZero()) {
        peer.sendKeepalive();
      }
    }
  }

  /** Whether {@link #start()} was called and the device is not closed. */
  public boolean isUp() {
    return up;
  }

  /** Stops all threads, closes the bind and tun, and erases all keys. */
  @Override
  public void close() throws IOException {
    synchronized (lifecycleLock) {
      if (closed) {
        return;
      }
      closed = true;
      up = false;
    }
    IOException failure = null;
    for (Closeable c : List.of(bind, tun)) {
      try {
        c.close();
      } catch (IOException e) {
        failure = e;
      }
    }
    threads.forEach(Thread::interrupt);
    if (handshakePool != null) {
      handshakePool.shutdownNow();
    }
    if (cryptoWorkers != null) {
      encryptPipeline.close();
      decryptPipeline.close();
      cryptoWorkers.shutdownNow();
    }
    for (Peer peer : peers.values()) {
      peer.stop();
    }
    if (ownsScheduler) {
      scheduler.close();
    }
    if (failure != null) {
      throw failure;
    }
  }

  private void bindLoop() {
    byte[] buf = new byte[65536];
    while (!closed) {
      Bind current = bind;
      try {
        Bind.Datagram d = current.receive(buf);
        processDatagram(buf, 0, d.length(), d.source());
      } catch (ClosedChannelException e) {
        if (closed || current == bind) {
          return; // closed for good, not swapped by bind(Bind)
        }
      } catch (IOException | RuntimeException e) {
        if (closed) {
          return;
        }
        LOG.log(System.Logger.Level.WARNING, "error handling received datagram", e);
      }
    }
  }

  private void tunLoop() {
    byte[] buf = new byte[65536];
    while (!closed) {
      try {
        int n = tun.read(buf, 0, buf.length);
        if (n < 0) {
          return;
        }
        processOutbound(buf, 0, n);
      } catch (IOException | RuntimeException e) {
        if (closed) {
          return;
        }
        LOG.log(System.Logger.Level.WARNING, "error handling outbound packet", e);
      }
    }
  }

  // ---------------------------------------------------------------- data path

  /** Routes an outgoing IP packet to its peer by destination address. */
  void processOutbound(byte[] packet, int off, int len) {
    int version = Transport.ipVersion(packet, off, len);
    if ((version == 4 && len < 20)
        || (version == 6 && len < 40)
        || (version != 4 && version != 6)) {
      return;
    }
    Peer peer =
        allowedIps.lookup(
            packet, off + Transport.destinationOffset(version), Transport.addressLength(version));
    if (peer == null) {
      return;
    }
    byte[] copy = new byte[len];
    System.arraycopy(packet, off, copy, 0, len);
    peer.queueOutbound(copy);
  }

  /** Dispatches a received UDP datagram. {@code buf} may be reused once this returns. */
  void processDatagram(byte[] buf, int off, int len, InetSocketAddress from) {
    int type = Messages.type(buf, off, len);
    switch (type) {
      case Protocol.TYPE_TRANSPORT -> receiveTransport(buf, off, len, from);
      case Protocol.TYPE_INITIATION, Protocol.TYPE_RESPONSE, Protocol.TYPE_COOKIE_REPLY -> {
        int expected =
            switch (type) {
              case Protocol.TYPE_INITIATION -> HandshakeInitiation.LENGTH;
              case Protocol.TYPE_RESPONSE -> HandshakeResponse.LENGTH;
              default -> CookieReply.LENGTH;
            };
        if (len != expected) {
          return;
        }
        byte[] copy = new byte[len];
        System.arraycopy(buf, off, copy, 0, len);
        handshakeExecutor.execute(() -> processHandshake(copy, type, from));
      }
      default -> {}
    }
  }

  private void receiveTransport(byte[] buf, int off, int len, InetSocketAddress from) {
    if (len < Transport.MIN_LENGTH) {
      return;
    }
    if (!(indices.get(Transport.receiver(buf, off)) instanceof Keypair keypair)
        || !(keypair.attachment() instanceof Session session)) {
      return;
    }
    if (session.discarded || session.expired(time.nanoTime())) {
      return;
    }
    long counter = Transport.counter(buf, off);
    byte[] plaintext = new byte[len - Transport.MIN_LENGTH];
    if (decryptPipeline == null) {
      if (open(keypair, counter, buf, off, len, plaintext)) {
        deliverTransport(session, counter, from, plaintext, len);
      }
      return;
    }
    byte[] copy = Arrays.copyOfRange(buf, off, off + len); // buf is reused by the receive loop
    boolean[] ok = new boolean[1];
    decryptPipeline.submit(
        () -> ok[0] = open(keypair, counter, copy, 0, len, plaintext),
        () -> {
          if (ok[0]) {
            deliverTransport(session, counter, from, plaintext, len);
          }
        });
  }

  private boolean open(
      Keypair keypair, long counter, byte[] buf, int off, int len, byte[] plaintext) {
    try {
      aead()
          .open(
              keypair.receiveKey(),
              counter,
              buf,
              off + Transport.HEADER_LENGTH,
              len - Transport.HEADER_LENGTH,
              plaintext,
              0,
              null);
      return true;
    } catch (AEADBadTagException e) {
      return false;
    }
  }

  /** In order, after decryption: replay check, then hand to the peer. */
  private void deliverTransport(
      Session session, long counter, InetSocketAddress from, byte[] plaintext, int len) {
    if (session.replay.accept(counter, Protocol.REJECT_AFTER_MESSAGES)) {
      session.peer.receiveTransport(session, from, plaintext, len);
    }
  }

  private void processHandshake(byte[] packet, int type, InetSocketAddress from) {
    Peer confirm = null;
    identityLock.readLock().lock();
    try {
      if (type == Protocol.TYPE_COOKIE_REPLY) {
        CookieReply reply = CookieReply.parse(packet);
        Peer peer = reply == null ? null : peerForIndex(reply.receiver());
        if (peer != null) {
          peer.handshake.cookieGenerator().consumeReply(reply);
        }
        return;
      }
      HandshakeMessage msg =
          type == Protocol.TYPE_INITIATION
              ? HandshakeInitiation.parse(packet)
              : HandshakeResponse.parse(packet);
      CookieChecker checker = cookieChecker;
      if (msg == null || !checker.checkMac1(msg)) {
        return;
      }
      if (isUnderLoad()) {
        byte[] source = CookieChecker.sourceBytes(from);
        if (!checker.checkMac2(msg, source)) {
          sendDatagram(checker.createReply(msg, source).bytes(), from);
          return;
        }
        if (!rateLimiter.allow(from.getAddress())) {
          return;
        }
      }
      Noise n = noise;
      if (msg instanceof HandshakeInitiation init) {
        Handshake hs =
            n.consumeInitiation(
                init,
                key -> {
                  Peer p = peers.get(key);
                  return p == null ? null : p.handshake;
                });
        if (hs != null && hs.attachment() instanceof Peer peer) {
          peer.onInitiationConsumed(n, hs, from, packet.length);
        }
      } else {
        Handshake hs = n.consumeResponse((HandshakeResponse) msg);
        if (hs != null
            && hs.attachment() instanceof Peer peer
            && peer.onResponseConsumed(n, hs, from, packet.length)) {
          confirm = peer;
        }
      }
    } catch (RuntimeException e) {
      LOG.log(System.Logger.Level.WARNING, "error processing handshake message", e);
    } finally {
      identityLock.readLock().unlock();
    }
    if (confirm != null) {
      confirm.sendKeepalive(); // confirms the new session to the responder; flushes staged data
    }
  }

  private Peer peerForIndex(int index) {
    return switch (indices.get(index)) {
      case Handshake hs when hs.attachment() instanceof Peer p -> p;
      case Keypair kp when kp.attachment() instanceof Session s -> s.peer;
      case null, default -> null;
    };
  }

  private boolean isUnderLoad() {
    if (forceUnderLoad) {
      return true;
    }
    long now = time.nanoTime();
    if (handshakePool != null && handshakePool.getQueue().size() >= UNDER_LOAD_QUEUE_SIZE) {
      underLoadUntilNanos = now + UNDER_LOAD_AFTER_NANOS;
      return true;
    }
    return now - underLoadUntilNanos < 0;
  }

  void sendDatagram(byte[] message, InetSocketAddress to) {
    try {
      bind.send(message, 0, message.length, to);
    } catch (IOException e) {
      LOG.log(System.Logger.Level.DEBUG, "send to " + to + " failed", e);
    }
  }

  void deliver(byte[] packet, int length) {
    try {
      tun.write(packet, 0, length);
    } catch (IOException e) {
      LOG.log(System.Logger.Level.DEBUG, "tun write failed", e);
    }
  }

  ChaCha20Poly1305 aead() {
    return AEAD.get();
  }

  long jitterNanos() {
    return jitter.nextLong(MAX_JITTER_NANOS);
  }

  private static Thread daemon(Runnable r, String name) {
    Thread t = new Thread(r, name);
    t.setDaemon(true);
    return t;
  }

  /** Builder for {@link Device}. */
  public static final class Builder {
    private PrivateKey privateKey;
    private Bind bind;
    private Tun tun;
    private TimeSource time = TimeSource.system();
    private Scheduler scheduler;
    private SecureRandom random = new SecureRandom();
    private RandomGenerator jitter = RandomGenerator.getDefault();
    private Executor handshakeExecutor;
    private int cryptoThreads =
        Math.max(1, Math.min(4, Runtime.getRuntime().availableProcessors() / 2));

    private Builder() {}

    /**
     * Number of threads encrypting and decrypting transport packets (default: half the processors,
     * 1..4). Zero runs crypto inline on the I/O threads.
     */
    public Builder cryptoThreads(int threads) {
      if (threads < 0) {
        throw new IllegalArgumentException("cryptoThreads must be >= 0");
      }
      this.cryptoThreads = threads;
      return this;
    }

    /** The local private key (required). */
    public Builder privateKey(PrivateKey key) {
      this.privateKey = key;
      return this;
    }

    /** The UDP bind (required). The device closes it. */
    public Builder bind(Bind bind) {
      this.bind = bind;
      return this;
    }

    /** The tun (required). The device closes it. */
    public Builder tun(Tun tun) {
      this.tun = tun;
      return this;
    }

    /** Clocks; defaults to the system clocks. Must agree with the scheduler. */
    public Builder timeSource(TimeSource time) {
      this.time = time;
      return this;
    }

    /** Timer scheduler; defaults to a private daemon thread. A supplied one is not closed. */
    public Builder scheduler(Scheduler scheduler) {
      this.scheduler = scheduler;
      return this;
    }

    /** Randomness for keys, indices and cookies. */
    public Builder random(SecureRandom random) {
      this.random = random;
      return this;
    }

    /**
     * Drives the device from the caller: handshake messages run on {@code executor} and {@link
     * #start()} spawns no I/O threads. For deterministic simulation.
     */
    Builder manual(Executor executor) {
      this.handshakeExecutor = executor;
      return this;
    }

    /** Builds the device. It is idle until {@link Device#start()}. */
    public Device build() {
      Objects.requireNonNull(privateKey, "privateKey");
      Objects.requireNonNull(bind, "bind");
      Objects.requireNonNull(tun, "tun");
      return new Device(this);
    }
  }
}
