// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core.noise;

import com.skanavi.javaguard.crypto.Blake2s;
import com.skanavi.javaguard.crypto.PrivateKey;
import com.skanavi.javaguard.crypto.PublicKey;

/** The local static key pair, with values derived from it that every handshake needs. */
public final class StaticIdentity {
  private final PrivateKey privateKey;
  private final PublicKey publicKey;
  final byte[] privateBytes;
  final byte[] publicBytes;

  /** {@code HASH(INITIAL_HASH || S_pub)}: the responder's hash before reading an initiation. */
  final byte[] responderInitialHash;

  /** {@code HASH(LABEL_MAC1 || S_pub)}: verifies mac1 on messages sent to us. */
  final byte[] mac1Key;

  /** {@code HASH(LABEL_COOKIE || S_pub)}: encrypts cookie replies we send. */
  final byte[] cookieKey;

  /** Creates the identity for {@code privateKey}. */
  public StaticIdentity(PrivateKey privateKey) {
    this.privateKey = privateKey;
    this.publicKey = privateKey.publicKey();
    this.privateBytes = privateKey.toBytes();
    this.publicBytes = publicKey.toBytes();
    this.responderInitialHash = Blake2s.hash(Protocol.INITIAL_HASH, publicBytes);
    this.mac1Key = Blake2s.hash(Protocol.LABEL_MAC1, publicBytes);
    this.cookieKey = Blake2s.hash(Protocol.LABEL_COOKIE, publicBytes);
  }

  /** The private key. */
  public PrivateKey privateKey() {
    return privateKey;
  }

  /** The public key. */
  public PublicKey publicKey() {
    return publicKey;
  }
}
