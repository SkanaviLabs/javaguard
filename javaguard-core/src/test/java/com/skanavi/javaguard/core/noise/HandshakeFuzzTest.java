// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core.noise;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import com.skanavi.javaguard.crypto.PresharedKey;
import org.junit.jupiter.api.Tag;

/**
 * Feeds arbitrary bytes to every inbound handshake path. Any exception is a finding: invalid input
 * must be rejected by returning {@code null} or {@code false}.
 */
@Tag("fuzz")
class HandshakeFuzzTest {
  private static final ManualTimeSource TIME = new ManualTimeSource();
  private static final Peer ALICE = new Peer(TIME);
  private static final Peer BOB = new Peer(TIME);

  static {
    try {
      ALICE.add(BOB, PresharedKey.NONE);
      BOB.add(ALICE, PresharedKey.NONE);
    } catch (Exception e) {
      throw new ExceptionInInitializerError(e);
    }
  }

  @FuzzTest(maxDuration = "60s")
  void inboundMessagesNeverThrow(FuzzedDataProvider in) {
    byte[] packet = in.consumeRemainingAsBytes();
    switch (Messages.type(packet, 0, packet.length)) {
      case Protocol.TYPE_INITIATION -> {
        HandshakeInitiation msg = HandshakeInitiation.parse(packet);
        if (msg != null) {
          BOB.checker.checkMac1(msg);
          BOB.checker.checkMac2(msg, new byte[6]);
          BOB.noise.consumeInitiation(msg, BOB.peers::get);
        }
      }
      case Protocol.TYPE_RESPONSE -> {
        HandshakeResponse msg = HandshakeResponse.parse(packet);
        if (msg != null) {
          ALICE.checker.checkMac1(msg);
          ALICE.noise.consumeResponse(msg);
        }
      }
      case Protocol.TYPE_COOKIE_REPLY -> {
        CookieReply msg = CookieReply.parse(packet);
        if (msg != null) {
          ALICE.handshakeWith(BOB).cookieGenerator().consumeReply(msg);
        }
      }
      default -> {}
    }
  }
}
