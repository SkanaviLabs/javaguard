// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core;

import static com.skanavi.javaguard.core.noise.Protocol.KEEPALIVE_TIMEOUT;
import static com.skanavi.javaguard.core.noise.Protocol.REJECT_AFTER_MESSAGES;
import static com.skanavi.javaguard.core.noise.Protocol.REJECT_AFTER_TIME;
import static com.skanavi.javaguard.core.noise.Protocol.REKEY_AFTER_MESSAGES;
import static com.skanavi.javaguard.core.noise.Protocol.REKEY_AFTER_TIME;
import static com.skanavi.javaguard.core.noise.Protocol.REKEY_ATTEMPT_TIME;
import static com.skanavi.javaguard.core.noise.Protocol.REKEY_TIMEOUT;

import com.skanavi.javaguard.core.noise.Handshake;
import com.skanavi.javaguard.core.noise.HandshakeInitiation;
import com.skanavi.javaguard.core.noise.HandshakeResponse;
import com.skanavi.javaguard.core.noise.Keypair;
import com.skanavi.javaguard.core.noise.Noise;
import com.skanavi.javaguard.crypto.PresharedKey;
import com.skanavi.javaguard.crypto.PublicKey;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;

/**
 * A remote WireGuard peer of a {@link Device}: its keys and sessions, endpoint, allowed IPs,
 * statistics and protocol timers (whitepaper section 6). Obtained from {@link
 * Device#addPeer(PeerConfig)}. Thread-safe.
 *
 * <p>Lock order: {@code sendLock}, then the device's identity lock, then the noise handshake lock,
 * then {@code keypairLock}. Never acquire {@code sendLock} while holding the identity lock.
 */
public final class Peer {
  private static final System.Logger LOG = System.getLogger(Peer.class.getName());
  private static final int MAX_STAGED_PACKETS = 128;
  private static final long MAX_HANDSHAKE_ATTEMPTS =
      REKEY_ATTEMPT_TIME.toNanos() / REKEY_TIMEOUT.toNanos();
  private static final byte[] KEEPALIVE = new byte[0];

  private final Device device;
  private final PublicKey publicKey;
  volatile Handshake handshake;
  private volatile InetSocketAddress endpoint;
  private volatile long persistentKeepaliveNanos;
  private volatile boolean removed;

  private final Object keypairLock = new Object();
  private Session previous;
  private Session next;
  private volatile Session current;

  private final ReentrantLock sendLock = new ReentrantLock();
  private final ArrayDeque<byte[]> staged = new ArrayDeque<>();

  private final Object handshakeSendLock = new Object();
  private boolean sentAnyHandshake;
  private long lastSentHandshakeNanos;
  private final AtomicInteger handshakeAttempts = new AtomicInteger();
  private volatile boolean needAnotherKeepalive;
  private volatile boolean sentLastMinuteHandshake;

  private final AtomicLong rxBytes = new AtomicLong();
  private final AtomicLong txBytes = new AtomicLong();
  private volatile Instant lastHandshake;

  private final PeerTimer retransmitHandshake;
  private final PeerTimer sendKeepaliveTimer;
  private final PeerTimer newHandshake;
  private final PeerTimer zeroKeyMaterial;
  private final PeerTimer persistentKeepalive;

  Peer(Device device, PublicKey publicKey, Handshake handshake) {
    this.device = device;
    this.publicKey = publicKey;
    this.handshake = handshake;
    Scheduler s = device.scheduler;
    this.retransmitHandshake = new PeerTimer(s, this::onRetransmitHandshake);
    this.sendKeepaliveTimer = new PeerTimer(s, this::onSendKeepalive);
    this.newHandshake = new PeerTimer(s, this::onNewHandshake);
    this.zeroKeyMaterial = new PeerTimer(s, this::zeroKeys);
    this.persistentKeepalive = new PeerTimer(s, this::onPersistentKeepalive);
  }

  // ---------------------------------------------------------------- public API

  /** The peer's public key. */
  public PublicKey publicKey() {
    return publicKey;
  }

  /** Where packets to this peer go: the configured endpoint, or where it last sent from. */
  public Optional<InetSocketAddress> endpoint() {
    return Optional.ofNullable(endpoint);
  }

  /** Sets the endpoint. It changes again whenever the peer roams. */
  public void endpoint(InetSocketAddress endpoint) {
    if (endpoint != null && endpoint.isUnresolved()) {
      throw new IllegalArgumentException("endpoint must be resolved: " + endpoint);
    }
    this.endpoint = endpoint;
  }

  /** The prefixes routed to this peer. */
  public List<IpPrefix> allowedIps() {
    return device.allowedIps.prefixes(this);
  }

  /** Replaces the prefixes routed to this peer. A prefix owned by another peer moves here. */
  public void allowedIps(Collection<IpPrefix> prefixes) {
    device.allowedIps.removeAll(this);
    for (IpPrefix p : prefixes) {
      device.allowedIps.insert(p, this);
    }
  }

  /** The pre-shared key. */
  public PresharedKey presharedKey() {
    return handshake.presharedKey();
  }

  /** Sets the pre-shared key for future handshakes. */
  public void presharedKey(PresharedKey key) {
    handshake.presharedKey(key);
  }

  /** The persistent keepalive interval, zero if off. */
  public Duration persistentKeepalive() {
    return Duration.ofNanos(persistentKeepaliveNanos);
  }

  /** Sets the persistent keepalive interval; zero turns it off. */
  public void persistentKeepalive(Duration interval) {
    if (interval.isNegative() || interval.toSeconds() > 65535) {
      throw new IllegalArgumentException("persistent keepalive must be 0..65535 seconds");
    }
    this.persistentKeepaliveNanos = interval.toNanos();
    if (interval.isZero()) {
      persistentKeepalive.del();
    }
  }

  /** Bytes received from this peer, including handshake messages. */
  public long rxBytes() {
    return rxBytes.get();
  }

  /** Bytes sent to this peer, including handshake messages. */
  public long txBytes() {
    return txBytes.get();
  }

  /** When the last handshake with this peer completed. */
  public Optional<Instant> lastHandshake() {
    return Optional.ofNullable(lastHandshake);
  }

  @Override
  public String toString() {
    return "Peer[" + publicKey.toBase64() + "]";
  }

  // ---------------------------------------------------------------- send path

  /** Queues an outgoing IP packet (owned by the callee) and sends what can be sent. */
  void queueOutbound(byte[] packet) {
    sendLock.lock();
    try {
      if (staged.size() >= MAX_STAGED_PACKETS) {
        staged.pollFirst();
      }
      staged.addLast(packet);
      sendStaged();
    } finally {
      sendLock.unlock();
    }
  }

  /** Sends a keepalive, after any staged packets (which make it redundant). */
  void sendKeepalive() {
    sendLock.lock();
    try {
      if (staged.isEmpty()) {
        staged.addLast(KEEPALIVE);
      }
      sendStaged();
    } finally {
      sendLock.unlock();
    }
  }

  /** Encrypts and sends staged packets with the current session, or starts a handshake. */
  void sendStaged() {
    sendLock.lock();
    try {
      if (staged.isEmpty() || removed) {
        return;
      }
      InetSocketAddress ep = endpoint;
      if (ep == null) {
        return;
      }
      Session s = current;
      long now = device.time.nanoTime();
      if (s == null || !s.canSend(now)) {
        sendHandshakeInitiation(false);
        return;
      }
      byte[] packet;
      while ((packet = staged.pollFirst()) != null) {
        long counter = s.sendCounter.getAndIncrement();
        if (Long.compareUnsigned(counter, REJECT_AFTER_MESSAGES) >= 0) {
          staged.addFirst(packet);
          sendHandshakeInitiation(false);
          return;
        }
        byte[] msg = seal(s, packet, counter);
        device.sendDatagram(msg, ep);
        txBytes.addAndGet(msg.length);
        timersAnyAuthenticatedPacketTraversal();
        timersAnyAuthenticatedPacketSent();
        if (packet.length > 0) {
          timersDataSent();
        }
      }
      keepKeyFreshSending(s, now);
    } finally {
      sendLock.unlock();
    }
  }

  private byte[] seal(Session s, byte[] plaintext, long counter) {
    int padded = Transport.paddedLength(plaintext.length, device.mtu);
    byte[] out = new byte[Transport.HEADER_LENGTH + padded + 16];
    Transport.putHeader(out, s.keypair.remoteIndex(), counter);
    System.arraycopy(plaintext, 0, out, Transport.HEADER_LENGTH, plaintext.length);
    device
        .aead()
        .seal(
            s.keypair.sendKey(),
            counter,
            out,
            Transport.HEADER_LENGTH,
            padded,
            out,
            Transport.HEADER_LENGTH,
            null);
    return out;
  }

  private void keepKeyFreshSending(Session s, long now) {
    if (Long.compareUnsigned(s.sendCounter.get(), REKEY_AFTER_MESSAGES) > 0
        || (s.keypair.isInitiator()
            && now - s.keypair.createdNanos() > REKEY_AFTER_TIME.toNanos())) {
      sendHandshakeInitiation(false);
    }
  }

  private void flushStaged() {
    sendLock.lock();
    try {
      staged.clear();
    } finally {
      sendLock.unlock();
    }
  }

  // ---------------------------------------------------------------- handshakes

  /** Sends a handshake initiation unless one went out less than REKEY_TIMEOUT ago. */
  void sendHandshakeInitiation(boolean retry) {
    if (!retry) {
      handshakeAttempts.set(0);
    }
    InetSocketAddress ep = endpoint;
    if (ep == null || removed) {
      return;
    }
    long now = device.time.nanoTime();
    synchronized (handshakeSendLock) {
      if (sentAnyHandshake && now - lastSentHandshakeNanos < REKEY_TIMEOUT.toNanos()) {
        return;
      }
      sentAnyHandshake = true;
      lastSentHandshakeNanos = now;
    }
    HandshakeInitiation msg;
    device.identityLock.readLock().lock();
    try {
      Handshake hs = handshake;
      msg = device.noise.createInitiation(hs);
      hs.cookieGenerator().addMacs(msg);
    } finally {
      device.identityLock.readLock().unlock();
    }
    LOG.log(System.Logger.Level.DEBUG, "{0}: sending handshake initiation", this);
    timersAnyAuthenticatedPacketTraversal();
    timersAnyAuthenticatedPacketSent();
    device.sendDatagram(msg.bytes(), ep);
    txBytes.addAndGet(msg.bytes().length);
    timersHandshakeInitiated();
  }

  /** Called with the identity read lock held, after {@code hs} consumed an initiation. */
  void onInitiationConsumed(Noise noise, Handshake hs, InetSocketAddress from, int length) {
    endpoint = from;
    rxBytes.addAndGet(length);
    timersAnyAuthenticatedPacketTraversal();
    timersAnyAuthenticatedPacketReceived();
    HandshakeResponse response = noise.createResponse(hs);
    if (response == null) {
      return;
    }
    hs.cookieGenerator().addMacs(response);
    Keypair keypair = noise.beginSession(hs);
    if (keypair == null) {
      return;
    }
    addSession(keypair);
    timersSessionDerived();
    timersAnyAuthenticatedPacketTraversal();
    timersAnyAuthenticatedPacketSent();
    LOG.log(System.Logger.Level.DEBUG, "{0}: sending handshake response", this);
    device.sendDatagram(response.bytes(), from);
    txBytes.addAndGet(response.bytes().length);
  }

  /**
   * Called with the identity read lock held, after {@code hs} consumed a response. Returns whether
   * a session was established, in which case the caller must {@link #sendKeepalive()} after
   * releasing the lock.
   */
  boolean onResponseConsumed(Noise noise, Handshake hs, InetSocketAddress from, int length) {
    endpoint = from;
    rxBytes.addAndGet(length);
    timersAnyAuthenticatedPacketTraversal();
    timersAnyAuthenticatedPacketReceived();
    Keypair keypair = noise.beginSession(hs);
    if (keypair == null) {
      return false;
    }
    addSession(keypair);
    timersSessionDerived();
    timersHandshakeComplete();
    return true;
  }

  /** Installs a new session, rotating the previous/current/next slots. */
  private void addSession(Keypair keypair) {
    Session s = new Session(keypair, this);
    keypair.attach(s);
    synchronized (keypairLock) {
      if (keypair.isInitiator()) {
        Session oldPrevious = previous;
        if (next != null) {
          previous = next;
          next = null;
          discard(current);
        } else {
          previous = current;
        }
        discard(oldPrevious);
        current = s;
      } else {
        discard(next);
        next = s;
        discard(previous);
        previous = null;
      }
    }
  }

  /**
   * Notes authenticated data on {@code s}. If {@code s} is the unconfirmed responder session, it
   * becomes current. Returns whether that happened.
   */
  private boolean confirmSession(Session s) {
    synchronized (keypairLock) {
      if (next != s) {
        return false;
      }
      discard(previous);
      previous = current;
      current = next;
      next = null;
      return true;
    }
  }

  private void discard(Session s) {
    if (s != null) {
      s.discarded = true;
      device.indices.remove(s.keypair.localIndex(), s.keypair);
    }
  }

  /** Erases all sessions and handshake state, and drops staged packets. */
  void zeroKeys() {
    clearSessions();
    flushStaged();
  }

  /** Erases all sessions and handshake state. Safe under the identity write lock. */
  private void clearSessions() {
    synchronized (keypairLock) {
      discard(previous);
      discard(current);
      discard(next);
      previous = null;
      current = null;
      next = null;
    }
    handshake.clear();
  }

  /**
   * Erases sessions and lifts the handshake rate limit, so a new handshake can start at once.
   * Staged packets are kept. Safe under the identity write lock.
   */
  void expireSessions() {
    clearSessions();
    synchronized (handshakeSendLock) {
      sentAnyHandshake = false;
    }
  }

  /** Permanently stops the peer. */
  void stop() {
    removed = true;
    retransmitHandshake.del();
    sendKeepaliveTimer.del();
    newHandshake.del();
    zeroKeyMaterial.del();
    persistentKeepalive.del();
    zeroKeys();
  }

  // ---------------------------------------------------------------- receive path

  /** Handles a decrypted, replay-checked transport message on session {@code s}. */
  void receiveTransport(Session s, InetSocketAddress from, byte[] plaintext, int wireLength) {
    if (confirmSession(s)) {
      timersHandshakeComplete();
      sendStaged();
    }
    keepKeyFreshReceiving();
    timersAnyAuthenticatedPacketTraversal();
    timersAnyAuthenticatedPacketReceived();
    endpoint = from;
    rxBytes.addAndGet(wireLength);
    if (plaintext.length == 0) {
      return; // keepalive
    }
    timersDataReceived();
    int length = Transport.ipLength(plaintext);
    if (length < 0) {
      return;
    }
    int version = Transport.ipVersion(plaintext, 0, length);
    Peer owner =
        device.allowedIps.lookup(
            plaintext, Transport.sourceOffset(version), Transport.addressLength(version));
    if (owner != this) {
      LOG.log(System.Logger.Level.DEBUG, "{0}: dropping packet from disallowed source", this);
      return;
    }
    device.deliver(plaintext, length);
  }

  private void keepKeyFreshReceiving() {
    if (sentLastMinuteHandshake) {
      return;
    }
    Session s = current;
    long threshold =
        REJECT_AFTER_TIME.toNanos() - KEEPALIVE_TIMEOUT.toNanos() - REKEY_TIMEOUT.toNanos();
    if (s != null
        && s.keypair.isInitiator()
        && device.time.nanoTime() - s.keypair.createdNanos() > threshold) {
      sentLastMinuteHandshake = true;
      sendHandshakeInitiation(false);
    }
  }

  // ---------------------------------------------------------------- timers

  private long rekeyTimeoutWithJitter() {
    return REKEY_TIMEOUT.toNanos() + device.jitterNanos();
  }

  private void timersDataSent() {
    if (!newHandshake.isPending()) {
      newHandshake.mod(KEEPALIVE_TIMEOUT.toNanos() + rekeyTimeoutWithJitter());
    }
  }

  private void timersDataReceived() {
    if (!sendKeepaliveTimer.isPending()) {
      sendKeepaliveTimer.mod(KEEPALIVE_TIMEOUT.toNanos());
    } else {
      needAnotherKeepalive = true;
    }
  }

  private void timersAnyAuthenticatedPacketSent() {
    sendKeepaliveTimer.del();
  }

  private void timersAnyAuthenticatedPacketReceived() {
    newHandshake.del();
  }

  private void timersHandshakeInitiated() {
    sendKeepaliveTimer.del();
    retransmitHandshake.mod(rekeyTimeoutWithJitter());
  }

  private void timersHandshakeComplete() {
    retransmitHandshake.del();
    handshakeAttempts.set(0);
    sentLastMinuteHandshake = false;
    lastHandshake = device.time.now();
    LOG.log(System.Logger.Level.DEBUG, "{0}: handshake complete", this);
  }

  private void timersSessionDerived() {
    zeroKeyMaterial.mod(REJECT_AFTER_TIME.toNanos() * 3);
  }

  private void timersAnyAuthenticatedPacketTraversal() {
    long interval = persistentKeepaliveNanos;
    if (interval > 0) {
      persistentKeepalive.mod(interval);
    }
  }

  private void onRetransmitHandshake() {
    if (handshakeAttempts.get() > MAX_HANDSHAKE_ATTEMPTS) {
      LOG.log(System.Logger.Level.DEBUG, "{0}: handshake did not complete, giving up", this);
      sendKeepaliveTimer.del();
      flushStaged();
      if (!zeroKeyMaterial.isPending()) {
        zeroKeyMaterial.mod(REJECT_AFTER_TIME.toNanos() * 3);
      }
      return;
    }
    handshakeAttempts.incrementAndGet();
    sendHandshakeInitiation(true);
  }

  private void onSendKeepalive() {
    sendKeepalive();
    if (needAnotherKeepalive) {
      needAnotherKeepalive = false;
      sendKeepaliveTimer.mod(KEEPALIVE_TIMEOUT.toNanos());
    }
  }

  private void onNewHandshake() {
    LOG.log(System.Logger.Level.DEBUG, "{0}: no reply to sent data, re-handshaking", this);
    sendHandshakeInitiation(false);
  }

  private void onPersistentKeepalive() {
    if (persistentKeepaliveNanos > 0) {
      sendKeepalive();
    }
  }

  // ---------------------------------------------------------------- test hooks

  /** The current session's keypair, for tests. */
  Keypair currentKeypair() {
    Session s = current;
    return s == null ? null : s.keypair;
  }

  /** Forces the current session's send counter, for exhaustion tests. */
  void setSendCounter(long counter) {
    Session s = current;
    if (s != null) {
      s.sendCounter.set(counter);
    }
  }
}
