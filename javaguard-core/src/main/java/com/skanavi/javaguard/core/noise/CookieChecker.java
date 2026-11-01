// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core.noise;

import com.skanavi.javaguard.crypto.Blake2s;
import com.skanavi.javaguard.crypto.ConstantTime;
import com.skanavi.javaguard.crypto.XChaCha20Poly1305;
import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Verifies mac1 and mac2 on incoming handshake messages and creates cookie replies. One per device.
 * Thread-safe.
 *
 * <p>Every handshake message must pass {@link #checkMac1} before any public-key work. When the
 * device is under load it additionally requires {@link #checkMac2} and answers messages that fail
 * it with {@link #createReply} instead of processing them.
 */
public final class CookieChecker {
  private final StaticIdentity identity;
  private final TimeSource time;
  private final SecureRandom random;
  private final ReentrantLock lock = new ReentrantLock();

  // Guarded by lock.
  private final byte[] secret = new byte[32];
  private long secretCreatedNanos;
  private boolean hasSecret;

  /** Creates a checker for messages addressed to {@code identity}. */
  public CookieChecker(StaticIdentity identity, TimeSource time, SecureRandom random) {
    this.identity = identity;
    this.time = time;
    this.random = random;
  }

  /** Returns whether mac1 proves the sender knows our public key. */
  public boolean checkMac1(HandshakeMessage msg) {
    byte[] expected = mac(identity.mac1Key, msg.bytes, msg.mac1Offset());
    return ConstantTime.equals(expected, msg.mac1());
  }

  /**
   * Returns whether mac2 carries a currently valid cookie for {@code source}.
   *
   * @param source the sender's address as from {@link #sourceBytes(InetSocketAddress)}
   */
  public boolean checkMac2(HandshakeMessage msg, byte[] source) {
    byte[] cookie;
    lock.lock();
    try {
      if (!secretFresh()) {
        return false;
      }
      cookie = mac(secret, source, source.length);
    } finally {
      lock.unlock();
    }
    byte[] expected = mac(cookie, msg.bytes, msg.mac2Offset());
    return ConstantTime.equals(expected, msg.mac2());
  }

  /**
   * Creates a cookie reply to {@code msg}, which must already have passed {@link #checkMac1}.
   *
   * @param source the sender's address as from {@link #sourceBytes(InetSocketAddress)}
   */
  public CookieReply createReply(HandshakeMessage msg, byte[] source) {
    byte[] cookie;
    lock.lock();
    try {
      if (!secretFresh()) {
        random.nextBytes(secret);
        secretCreatedNanos = time.nanoTime();
        hasSecret = true;
      }
      cookie = mac(secret, source, source.length);
    } finally {
      lock.unlock();
    }
    byte[] nonce = new byte[CookieReply.NONCE_LENGTH];
    random.nextBytes(nonce);
    CookieReply reply = CookieReply.create();
    reply.receiver(msg.sender());
    reply.nonce(nonce);
    reply.encryptedCookie(
        new XChaCha20Poly1305().seal(identity.cookieKey, nonce, cookie, msg.mac1()));
    return reply;
  }

  /** Encodes a UDP source address for cookie computation: IP address bytes then big-endian port. */
  public static byte[] sourceBytes(InetSocketAddress address) {
    byte[] ip = address.getAddress().getAddress();
    byte[] out = new byte[ip.length + 2];
    System.arraycopy(ip, 0, out, 0, ip.length);
    out[ip.length] = (byte) (address.getPort() >>> 8);
    out[ip.length + 1] = (byte) address.getPort();
    return out;
  }

  private boolean secretFresh() {
    return hasSecret
        && time.nanoTime() - secretCreatedNanos < Protocol.COOKIE_REFRESH_TIME.toNanos();
  }

  /** {@code MAC(key, data[0..len))}: keyed BLAKE2s with 16-byte output. */
  static byte[] mac(byte[] key, byte[] data, int len) {
    return new Blake2s(HandshakeMessage.MAC_LENGTH, key).update(data, 0, len).digest();
  }
}
