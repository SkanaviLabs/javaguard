// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core.noise;

import com.skanavi.javaguard.crypto.PresharedKey;
import com.skanavi.javaguard.crypto.PrivateKey;
import com.skanavi.javaguard.crypto.PublicKey;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

/** Test fixture: one side of a handshake with its own identity, index table and peer map. */
final class Peer {
  final StaticIdentity identity;
  final IndexTable indices = new IndexTable();
  final ManualTimeSource time;
  final Noise noise;
  final CookieChecker checker;
  final Map<PublicKey, Handshake> peers = new HashMap<>();

  Peer(ManualTimeSource time) {
    this.time = time;
    this.identity = new StaticIdentity(PrivateKey.generate());
    this.noise = new Noise(identity, indices, time, new SecureRandom());
    this.checker = new CookieChecker(identity, time, new SecureRandom());
  }

  Handshake add(Peer other, PresharedKey psk) throws Exception {
    Handshake hs = noise.newHandshake(other.identity.publicKey(), psk);
    peers.put(other.identity.publicKey(), hs);
    return hs;
  }

  Handshake handshakeWith(Peer other) {
    return peers.get(other.identity.publicKey());
  }

  /** Simulates receipt: parse a copy of the wire bytes, check mac1, consume. */
  Handshake receiveInitiation(byte[] wire) {
    HandshakeInitiation msg = HandshakeInitiation.parse(wire);
    if (msg == null || !checker.checkMac1(msg)) {
      return null;
    }
    return noise.consumeInitiation(msg, peers::get);
  }

  Handshake receiveResponse(byte[] wire) {
    HandshakeResponse msg = HandshakeResponse.parse(wire);
    if (msg == null || !checker.checkMac1(msg)) {
      return null;
    }
    return noise.consumeResponse(msg);
  }

  byte[] sendInitiation(Peer to) {
    Handshake hs = handshakeWith(to);
    HandshakeInitiation msg = noise.createInitiation(hs);
    hs.cookieGenerator().addMacs(msg);
    return msg.bytes().clone();
  }

  byte[] sendResponse(Handshake hs) {
    HandshakeResponse msg = noise.createResponse(hs);
    if (msg == null) {
      return null;
    }
    hs.cookieGenerator().addMacs(msg);
    return msg.bytes().clone();
  }
}
