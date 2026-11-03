// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core;

// Portions derived from wireguard-go (https://git.zx2c4.com/wireguard-go/),
// Copyright (C) 2017-2025 WireGuard LLC. MIT.

import com.skanavi.javaguard.core.noise.Keypair;
import com.skanavi.javaguard.core.noise.Protocol;
import java.util.concurrent.atomic.AtomicLong;

/** A keypair in use: its send counter, receive replay window, and owning peer. */
final class Session {
  final Keypair keypair;
  final Peer peer;
  final AtomicLong sendCounter = new AtomicLong();
  final ReplayWindow replay = new ReplayWindow();
  volatile boolean discarded;

  Session(Keypair keypair, Peer peer) {
    this.keypair = keypair;
    this.peer = peer;
  }

  boolean expired(long nowNanos) {
    return nowNanos - keypair.createdNanos() >= Protocol.REJECT_AFTER_TIME.toNanos();
  }

  /** Whether new packets may be encrypted with this session. */
  boolean canSend(long nowNanos) {
    return !discarded
        && !expired(nowNanos)
        && Long.compareUnsigned(sendCounter.get(), Protocol.REJECT_AFTER_MESSAGES) < 0;
  }
}
