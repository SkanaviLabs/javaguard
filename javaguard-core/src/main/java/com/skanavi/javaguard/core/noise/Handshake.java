// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core.noise;

import com.skanavi.javaguard.crypto.Blake2s;
import com.skanavi.javaguard.crypto.PresharedKey;
import com.skanavi.javaguard.crypto.PublicKey;
import com.skanavi.javaguard.crypto.Tai64n;
import java.util.Arrays;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Per-peer handshake state. Created by {@link Noise#newHandshake}; all transitions go through
 * {@link Noise}. Thread-safe.
 */
public final class Handshake implements IndexTable.Entry {
  /** Handshake progress. */
  public enum State {
    /** No handshake in progress. */
    ZEROED,
    /** We sent an initiation and await a response. */
    INITIATION_CREATED,
    /** We received a valid initiation and have not answered yet. */
    INITIATION_CONSUMED,
    /** We answered an initiation; keys can be derived (responder side). */
    RESPONSE_CREATED,
    /** We received a valid response; keys can be derived (initiator side). */
    RESPONSE_CONSUMED
  }

  final ReentrantLock lock = new ReentrantLock();
  final Noise noise;
  final PublicKey remoteStatic;
  final byte[] remoteStaticBytes;

  /** {@code DH(S_priv, S_pub_remote)}, precomputed. */
  final byte[] staticStatic;

  /** {@code HASH(INITIAL_HASH || S_pub_remote)}: the initiator's hash before writing. */
  final byte[] initiatorInitialHash;

  final CookieGenerator cookieGenerator;

  private volatile PresharedKey presharedKey;

  private volatile Object attachment;

  /** Attaches an arbitrary object, typically the owner's per-peer state. */
  public void attach(Object attachment) {
    this.attachment = attachment;
  }

  /** The attached object, or {@code null}. */
  public Object attachment() {
    return attachment;
  }

  // Guarded by lock.
  State state = State.ZEROED;
  byte[] hash;
  byte[] chainKey;
  byte[] localEphemeral;
  byte[] remoteEphemeral;
  int localIndex;
  int remoteIndex;
  byte[] latestTimestamp = new byte[Tai64n.LENGTH];
  long lastInitiationConsumedNanos;
  boolean consumedAnyInitiation;

  Handshake(Noise noise, PublicKey remoteStatic, PresharedKey presharedKey, byte[] staticStatic) {
    this.noise = noise;
    this.remoteStatic = remoteStatic;
    this.remoteStaticBytes = remoteStatic.toBytes();
    this.staticStatic = staticStatic;
    this.initiatorInitialHash = Blake2s.hash(Protocol.INITIAL_HASH, remoteStaticBytes);
    this.cookieGenerator = new CookieGenerator(remoteStatic, noise.time);
    this.presharedKey = presharedKey;
  }

  /** The peer's static public key. */
  public PublicKey remoteStatic() {
    return remoteStatic;
  }

  /** The pre-shared key, {@link PresharedKey#NONE} if unset. */
  public PresharedKey presharedKey() {
    return presharedKey;
  }

  /** Replaces the pre-shared key; takes effect for the next handshake message. */
  public void presharedKey(PresharedKey key) {
    this.presharedKey = key;
  }

  /** The mac1/mac2 generator for messages we send to this peer. */
  public CookieGenerator cookieGenerator() {
    return cookieGenerator;
  }

  /** The current state. */
  public State state() {
    lock.lock();
    try {
      return state;
    } finally {
      lock.unlock();
    }
  }

  /** Abandons any handshake in progress and releases its index. */
  public void clear() {
    lock.lock();
    try {
      zero();
    } finally {
      lock.unlock();
    }
  }

  /** Clears transient state; caller holds the lock. Keeps the replay-protection timestamp. */
  void zero() {
    if (localIndex != 0) {
      noise.indices.remove(localIndex, this);
    }
    wipe(hash);
    wipe(chainKey);
    wipe(localEphemeral);
    hash = null;
    chainKey = null;
    localEphemeral = null;
    remoteEphemeral = null;
    localIndex = 0;
    remoteIndex = 0;
    state = State.ZEROED;
  }

  private static void wipe(byte[] b) {
    if (b != null) {
      Arrays.fill(b, (byte) 0);
    }
  }

  @Override
  public String toString() {
    return "Handshake[" + remoteStatic + ", " + state() + "]";
  }
}
