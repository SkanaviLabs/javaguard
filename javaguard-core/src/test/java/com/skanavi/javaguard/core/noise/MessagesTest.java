// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core.noise;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class MessagesTest {
  @Test
  void detectsTypes() {
    assertThat(Messages.type(new byte[] {1, 0, 0, 0}, 0, 4)).isEqualTo(Protocol.TYPE_INITIATION);
    assertThat(Messages.type(new byte[] {9, 4, 0, 0, 0}, 1, 4)).isEqualTo(Protocol.TYPE_TRANSPORT);
    assertThat(Messages.type(new byte[] {1, 0, 0, 1}, 0, 4)).isEqualTo(-1); // reserved bytes set
    assertThat(Messages.type(new byte[] {5, 0, 0, 0}, 0, 4)).isEqualTo(-1);
    assertThat(Messages.type(new byte[] {0, 0, 0, 0}, 0, 4)).isEqualTo(-1);
    assertThat(Messages.type(new byte[] {1, 0, 0}, 0, 3)).isEqualTo(-1);
  }

  @Test
  void parseChecksLengthAndType() {
    byte[] init = HandshakeInitiation.create().bytes();
    assertThat(HandshakeInitiation.parse(init)).isNotNull();
    assertThat(HandshakeInitiation.parse(init, 0, 147)).isNull();
    assertThat(HandshakeResponse.parse(init, 0, HandshakeResponse.LENGTH)).isNull();
    byte[] padded = new byte[200];
    System.arraycopy(init, 0, padded, 10, init.length);
    assertThat(HandshakeInitiation.parse(padded, 10, HandshakeInitiation.LENGTH)).isNotNull();
    assertThat(CookieReply.parse(CookieReply.create().bytes())).isNotNull();
    assertThat(CookieReply.parse(new byte[CookieReply.LENGTH])).isNull();
  }

  @Test
  void parseCopiesInput() {
    byte[] wire = HandshakeResponse.create().bytes().clone();
    HandshakeResponse msg = HandshakeResponse.parse(wire);
    wire[RECEIVER_BYTE] = 7;
    assertThat(msg.receiver()).isZero();
  }

  @Test
  void fieldLayoutMatchesTheWhitepaper() {
    assertThat(HandshakeInitiation.MAC1 + 32).isEqualTo(HandshakeInitiation.LENGTH);
    assertThat(HandshakeInitiation.TIMESTAMP + HandshakeInitiation.TIMESTAMP_LENGTH)
        .isEqualTo(HandshakeInitiation.MAC1);
    assertThat(HandshakeResponse.EMPTY + HandshakeResponse.EMPTY_LENGTH)
        .isEqualTo(HandshakeResponse.MAC1);
    assertThat(HandshakeResponse.MAC1 + 32).isEqualTo(HandshakeResponse.LENGTH);
    assertThat(CookieReply.COOKIE + CookieReply.COOKIE_LENGTH).isEqualTo(CookieReply.LENGTH);
  }

  private static final int RECEIVER_BYTE = HandshakeResponse.RECEIVER;
}
