// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core.noise;

import javax.crypto.SecretKey;

/**
 * Transport keys derived from a completed handshake, with the receiver indices both sides use for
 * them. Immutable; counters and replay protection belong to the transport layer.
 */
public final class Keypair implements IndexTable.Entry {
  private final SecretKey sendKey;
  private final SecretKey receiveKey;
  private final int localIndex;
  private final int remoteIndex;
  private final boolean initiator;
  private final long createdNanos;

  Keypair(
      SecretKey sendKey,
      SecretKey receiveKey,
      int localIndex,
      int remoteIndex,
      boolean initiator,
      long createdNanos) {
    this.sendKey = sendKey;
    this.receiveKey = receiveKey;
    this.localIndex = localIndex;
    this.remoteIndex = remoteIndex;
    this.initiator = initiator;
    this.createdNanos = createdNanos;
  }

  /** Key for messages we send. */
  public SecretKey sendKey() {
    return sendKey;
  }

  /** Key for messages we receive. */
  public SecretKey receiveKey() {
    return receiveKey;
  }

  /** Index the peer puts in messages to us. */
  public int localIndex() {
    return localIndex;
  }

  /** Index we put in messages to the peer. */
  public int remoteIndex() {
    return remoteIndex;
  }

  /** Whether we initiated the handshake that produced this keypair. */
  public boolean isInitiator() {
    return initiator;
  }

  /** {@link TimeSource#nanoTime()} when the keypair was derived. */
  public long createdNanos() {
    return createdNanos;
  }

  @Override
  public String toString() {
    return "Keypair[local="
        + Integer.toUnsignedString(localIndex)
        + ", remote="
        + Integer.toUnsignedString(remoteIndex)
        + ", initiator="
        + initiator
        + "]";
  }
}
