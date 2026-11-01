// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core.noise;

import static org.assertj.core.api.Assertions.assertThat;

import com.skanavi.javaguard.crypto.PresharedKey;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Duration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CookieTest {
  private ManualTimeSource time;
  private Peer alice;
  private Peer bob;
  private byte[] aliceAddress;

  @BeforeEach
  void setUp() throws Exception {
    time = new ManualTimeSource();
    alice = new Peer(time);
    bob = new Peer(time);
    alice.add(bob, PresharedKey.NONE);
    bob.add(alice, PresharedKey.NONE);
    aliceAddress =
        CookieChecker.sourceBytes(new InetSocketAddress(InetAddress.getByName("192.0.2.1"), 51820));
  }

  @Test
  void mac1BindsMessageToRecipient() {
    HandshakeInitiation msg = HandshakeInitiation.parse(alice.sendInitiation(bob));
    assertThat(bob.checker.checkMac1(msg)).isTrue();
    assertThat(alice.checker.checkMac1(msg)).isFalse();
  }

  @Test
  void mac1CoversTheWholeMessagePrefix() {
    byte[] wire = alice.sendInitiation(bob);
    for (int i = 0; i < HandshakeInitiation.MAC1 + 16; i++) {
      byte[] bad = wire.clone();
      bad[i] ^= (byte) 0x80;
      HandshakeInitiation msg = HandshakeInitiation.parse(bad);
      assertThat(msg != null && bob.checker.checkMac1(msg)).as("byte %d", i).isFalse();
    }
  }

  @Test
  void cookieRoundTripEnablesMac2() {
    HandshakeInitiation first = HandshakeInitiation.parse(alice.sendInitiation(bob));
    assertThat(first.mac2()).containsOnly(0);
    assertThat(bob.checker.checkMac2(first, aliceAddress)).isFalse();

    CookieReply reply = CookieReply.parse(bob.checker.createReply(first, aliceAddress).bytes());
    assertThat(reply.receiver()).isEqualTo(first.sender());
    assertThat(alice.handshakeWith(bob).cookieGenerator().consumeReply(reply)).isTrue();

    HandshakeInitiation second = HandshakeInitiation.parse(alice.sendInitiation(bob));
    assertThat(bob.checker.checkMac1(second)).isTrue();
    assertThat(bob.checker.checkMac2(second, aliceAddress)).isTrue();
    byte[] otherAddress = aliceAddress.clone();
    otherAddress[3] ^= 1;
    assertThat(bob.checker.checkMac2(second, otherAddress)).isFalse();
  }

  @Test
  void cookiesExpire() {
    HandshakeInitiation first = HandshakeInitiation.parse(alice.sendInitiation(bob));
    CookieReply reply = bob.checker.createReply(first, aliceAddress);
    alice.handshakeWith(bob).cookieGenerator().consumeReply(reply);

    time.advance(Duration.ofSeconds(119));
    HandshakeInitiation fresh = HandshakeInitiation.parse(alice.sendInitiation(bob));
    assertThat(bob.checker.checkMac2(fresh, aliceAddress)).isTrue();

    time.advance(Duration.ofSeconds(2));
    assertThat(bob.checker.checkMac2(fresh, aliceAddress)).isFalse(); // responder secret rotated
    HandshakeInitiation stale = HandshakeInitiation.parse(alice.sendInitiation(bob));
    assertThat(stale.mac2()).containsOnly(0); // initiator dropped its old cookie
  }

  @Test
  void cookieReplyIsBoundToTheLastSentMac1() {
    HandshakeInitiation first = HandshakeInitiation.parse(alice.sendInitiation(bob));
    CookieReply reply = bob.checker.createReply(first, aliceAddress);
    time.advance(Duration.ofSeconds(1));
    alice.sendInitiation(bob); // a newer message replaces lastMac1
    assertThat(alice.handshakeWith(bob).cookieGenerator().consumeReply(reply)).isFalse();
  }

  @Test
  void rejectsTamperedOrUnsolicitedReplies() throws Exception {
    Peer carol = new Peer(time);
    Handshake carolToBob = carol.add(bob, PresharedKey.NONE);
    HandshakeInitiation first = HandshakeInitiation.parse(alice.sendInitiation(bob));
    CookieReply reply = bob.checker.createReply(first, aliceAddress);
    assertThat(carolToBob.cookieGenerator().consumeReply(reply)).isFalse(); // never sent anything

    byte[] bad = reply.bytes().clone();
    bad[40] ^= 1;
    assertThat(alice.handshakeWith(bob).cookieGenerator().consumeReply(CookieReply.parse(bad)))
        .isFalse();
  }

  @Test
  void sourceBytesEncodeAddressAndPort() throws Exception {
    assertThat(
            CookieChecker.sourceBytes(
                new InetSocketAddress(InetAddress.getByName("10.1.2.3"), 0x1234)))
        .containsExactly(10, 1, 2, 3, 0x12, 0x34);
    assertThat(CookieChecker.sourceBytes(new InetSocketAddress(InetAddress.getByName("::1"), 1)))
        .hasSize(18);
  }
}
