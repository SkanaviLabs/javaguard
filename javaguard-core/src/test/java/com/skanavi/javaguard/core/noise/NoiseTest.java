// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core.noise;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.skanavi.javaguard.core.noise.Handshake.State;
import com.skanavi.javaguard.crypto.ChaCha20Poly1305;
import com.skanavi.javaguard.crypto.PresharedKey;
import com.skanavi.javaguard.crypto.PublicKey;
import java.security.InvalidKeyException;
import java.time.Duration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class NoiseTest {
  private ManualTimeSource time;
  private Peer alice;
  private Peer bob;

  @BeforeEach
  void setUp() throws Exception {
    time = new ManualTimeSource();
    alice = new Peer(time);
    bob = new Peer(time);
    alice.add(bob, PresharedKey.NONE);
    bob.add(alice, PresharedKey.NONE);
  }

  @Test
  void fullHandshakeDerivesMatchingKeys() throws Exception {
    Keypair[] pair = handshake(alice, bob);
    Keypair a = pair[0];
    Keypair b = pair[1];
    assertThat(a.isInitiator()).isTrue();
    assertThat(b.isInitiator()).isFalse();
    assertThat(a.remoteIndex()).isEqualTo(b.localIndex());
    assertThat(b.remoteIndex()).isEqualTo(a.localIndex());
    assertKeysPair(a, b);
    assertThat(alice.indices.get(a.localIndex())).isSameAs(a);
    assertThat(bob.indices.get(b.localIndex())).isSameAs(b);
    assertThat(alice.handshakeWith(bob).state()).isEqualTo(State.ZEROED);
    assertThat(bob.handshakeWith(alice).state()).isEqualTo(State.ZEROED);
  }

  @Test
  void matchingPresharedKeysWork() throws Exception {
    PresharedKey psk = PresharedKey.generate();
    alice.handshakeWith(bob).presharedKey(psk);
    bob.handshakeWith(alice).presharedKey(psk);
    Keypair[] pair = handshake(alice, bob);
    assertKeysPair(pair[0], pair[1]);
  }

  @Test
  void presharedKeyMismatchFailsAtResponse() {
    bob.handshakeWith(alice).presharedKey(PresharedKey.generate());
    Handshake atBob = bob.receiveInitiation(alice.sendInitiation(bob));
    assertThat(atBob).isNotNull();
    assertThat(alice.receiveResponse(bob.sendResponse(atBob))).isNull();
    assertThat(alice.handshakeWith(bob).state()).isEqualTo(State.INITIATION_CREATED);
  }

  @Test
  void rejectsReplayedInitiation() {
    byte[] initiation = alice.sendInitiation(bob);
    assertThat(bob.receiveInitiation(initiation)).isNotNull();
    time.advance(Duration.ofSeconds(1));
    assertThat(bob.receiveInitiation(initiation)).isNull();
  }

  @Test
  void rateLimitsInitiationsPerPeer() {
    assertThat(bob.receiveInitiation(alice.sendInitiation(bob))).isNotNull();
    // Newer timestamp (wall clock moved past the whitening granularity), but too soon.
    time.advance(Duration.ofMillis(19));
    byte[] early = alice.sendInitiation(bob);
    time.advance(Duration.ofMillis(1));
    assertThat(bob.receiveInitiation(early)).isNull();
    time.advance(Duration.ofMillis(30));
    assertThat(bob.receiveInitiation(alice.sendInitiation(bob))).isNotNull();
  }

  @Test
  void rejectsUnknownInitiator() throws Exception {
    Peer mallory = new Peer(time);
    mallory.add(bob, PresharedKey.NONE);
    assertThat(bob.receiveInitiation(mallory.sendInitiation(bob))).isNull();
  }

  @Test
  void rejectsInitiationForSomeoneElse() throws Exception {
    Peer carol = new Peer(time);
    carol.add(alice, PresharedKey.NONE);
    alice.add(carol, PresharedKey.NONE);
    byte[] toCarol = alice.sendInitiation(carol);
    assertThat(bob.receiveInitiation(toCarol)).isNull(); // mac1 is keyed to carol
    HandshakeInitiation msg = HandshakeInitiation.parse(toCarol);
    assertThat(bob.noise.consumeInitiation(msg, bob.peers::get)).isNull(); // and so is the DH
  }

  @Test
  void rejectsEveryBitFlipInInitiation() {
    byte[] wire = alice.sendInitiation(bob);
    HandshakeInitiation good = HandshakeInitiation.parse(wire);
    for (int i = 4; i < HandshakeInitiation.MAC1; i++) {
      byte[] bad = wire.clone();
      bad[i] ^= 0x01;
      HandshakeInitiation msg = HandshakeInitiation.parse(bad);
      // Bypass mac1 so the Noise layer itself must reject (sender index is not authenticated).
      Handshake hs = bob.noise.consumeInitiation(msg, bob.peers::get);
      if (i < HandshakeInitiation.EPHEMERAL) {
        assertThat(hs).as("sender index byte %d", i).isNotNull();
        time.advance(Duration.ofSeconds(1));
        wire = alice.sendInitiation(bob);
      } else {
        assertThat(hs).as("byte %d", i).isNull();
      }
    }
    assertThat(good).isNotNull();
  }

  @Test
  void rejectsEveryBitFlipInResponse() {
    Handshake atBob = bob.receiveInitiation(alice.sendInitiation(bob));
    byte[] wire = bob.sendResponse(atBob);
    for (int i = HandshakeResponse.EPHEMERAL; i < HandshakeResponse.MAC1; i++) {
      byte[] bad = wire.clone();
      bad[i] ^= 0x01;
      assertThat(alice.noise.consumeResponse(HandshakeResponse.parse(bad)))
          .as("byte %d", i)
          .isNull();
    }
    assertThat(alice.receiveResponse(wire)).isNotNull();
  }

  @Test
  void responseIsAcceptedOnlyOnce() {
    Handshake atBob = bob.receiveInitiation(alice.sendInitiation(bob));
    byte[] response = bob.sendResponse(atBob);
    assertThat(alice.receiveResponse(response)).isNotNull();
    assertThat(alice.receiveResponse(response)).isNull();
  }

  @Test
  void responseToAbandonedInitiationIsRejected() {
    Handshake atBob = bob.receiveInitiation(alice.sendInitiation(bob));
    byte[] response = bob.sendResponse(atBob);
    alice.sendInitiation(bob); // retransmission replaces the first attempt
    assertThat(alice.receiveResponse(response)).isNull();
  }

  @Test
  void stateMachineRejectsOutOfOrderCalls() {
    Handshake hs = alice.handshakeWith(bob);
    assertThat(alice.noise.createResponse(hs)).isNull();
    assertThat(alice.noise.beginSession(hs)).isNull();
    alice.sendInitiation(bob);
    assertThat(alice.noise.beginSession(hs)).isNull();
    assertThat(alice.noise.createResponse(hs)).isNull();
  }

  @Test
  void initiationIndexIsReleasedWhenReplacedOrCleared() {
    alice.sendInitiation(bob);
    alice.sendInitiation(bob);
    assertThat(alice.indices.size()).isEqualTo(1);
    alice.handshakeWith(bob).clear();
    assertThat(alice.indices.size()).isZero();
  }

  @Test
  void rejectsInvalidPeerKeys() {
    assertThatThrownBy(
            () -> alice.noise.newHandshake(alice.identity.publicKey(), PresharedKey.NONE))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(
            () -> alice.noise.newHandshake(PublicKey.fromBytes(new byte[32]), PresharedKey.NONE))
        .isInstanceOf(InvalidKeyException.class);
  }

  @Test
  void handshakeCanRepeatForRekey() throws Exception {
    Keypair[] first = handshake(alice, bob);
    time.advance(Duration.ofSeconds(120));
    Keypair[] second = handshake(bob, alice); // responder-initiated rekey
    assertKeysPair(second[0], second[1]);
    assertThat(second[0].sendKey()).isNotEqualTo(first[1].sendKey());
    assertThat(alice.indices.size())
        .isEqualTo(2); // both keypairs indexed until the device drops one
  }

  /** Runs a complete handshake; returns {initiator keypair, responder keypair}. */
  private static Keypair[] handshake(Peer initiator, Peer responder) {
    Handshake atResponder = responder.receiveInitiation(initiator.sendInitiation(responder));
    assertThat(atResponder).isNotNull();
    assertThat(atResponder.state()).isEqualTo(State.INITIATION_CONSUMED);
    byte[] response = responder.sendResponse(atResponder);
    Handshake atInitiator = initiator.receiveResponse(response);
    assertThat(atInitiator).isNotNull();
    Keypair i = initiator.noise.beginSession(atInitiator);
    Keypair r = responder.noise.beginSession(atResponder);
    assertThat(i).isNotNull();
    assertThat(r).isNotNull();
    return new Keypair[] {i, r};
  }

  private static void assertKeysPair(Keypair a, Keypair b) throws Exception {
    var aead = new ChaCha20Poly1305();
    byte[] msg = "ping".getBytes();
    assertThat(aead.open(b.receiveKey(), 0, aead.seal(a.sendKey(), 0, msg, null), null))
        .isEqualTo(msg);
    assertThat(
            aead.open(
                a.receiveKey(), 0, new ChaCha20Poly1305().seal(b.sendKey(), 0, msg, null), null))
        .isEqualTo(msg);
    assertThat(a.sendKey()).isNotEqualTo(a.receiveKey());
  }
}
