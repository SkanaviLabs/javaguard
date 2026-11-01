// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core.noise;

import com.skanavi.javaguard.crypto.Blake2s;
import com.skanavi.javaguard.crypto.PublicKey;
import com.skanavi.javaguard.crypto.XChaCha20Poly1305;
import java.util.concurrent.locks.ReentrantLock;
import javax.crypto.AEADBadTagException;

/**
 * Adds mac1 and mac2 to handshake messages we send to one peer, and stores the cookie that peer
 * hands us in a cookie reply when it is under load. Thread-safe.
 */
public final class CookieGenerator {
  private final byte[] mac1Key;
  private final byte[] cookieKey;
  private final TimeSource time;
  private final ReentrantLock lock = new ReentrantLock();

  // Guarded by lock.
  private byte[] cookie;
  private long cookieReceivedNanos;
  private byte[] lastMac1;

  CookieGenerator(PublicKey remoteStatic, TimeSource time) {
    byte[] remote = remoteStatic.toBytes();
    this.mac1Key = Blake2s.hash(Protocol.LABEL_MAC1, remote);
    this.cookieKey = Blake2s.hash(Protocol.LABEL_COOKIE, remote);
    this.time = time;
  }

  /**
   * Writes mac1, and mac2 if we hold a cookie younger than {@link Protocol#COOKIE_REFRESH_TIME}
   * (zeros otherwise). Call last, after the rest of the message is final.
   */
  public void addMacs(HandshakeMessage msg) {
    byte[] mac1 = CookieChecker.mac(mac1Key, msg.bytes, msg.mac1Offset());
    msg.mac1(mac1);
    lock.lock();
    try {
      lastMac1 = mac1;
      if (cookie != null
          && time.nanoTime() - cookieReceivedNanos < Protocol.COOKIE_REFRESH_TIME.toNanos()) {
        msg.mac2(CookieChecker.mac(cookie, msg.bytes, msg.mac2Offset()));
      } else {
        msg.mac2(new byte[HandshakeMessage.MAC_LENGTH]);
      }
    } finally {
      lock.unlock();
    }
  }

  /**
   * Decrypts and stores the cookie in {@code reply}. The reply is authenticated against the mac1 of
   * the last message we sent; the caller must have matched its receiver index to that message.
   *
   * @return whether the reply was valid
   */
  public boolean consumeReply(CookieReply reply) {
    lock.lock();
    try {
      if (lastMac1 == null) {
        return false;
      }
      byte[] value =
          new XChaCha20Poly1305().open(cookieKey, reply.nonce(), reply.encryptedCookie(), lastMac1);
      cookie = value;
      cookieReceivedNanos = time.nanoTime();
      return true;
    } catch (AEADBadTagException e) {
      return false;
    } finally {
      lock.unlock();
    }
  }
}
