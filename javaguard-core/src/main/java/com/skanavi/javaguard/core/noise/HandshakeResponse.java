// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core.noise;

/**
 * Handshake response (type 2, 92 bytes): sender index, receiver index, unencrypted ephemeral,
 * encrypted empty payload, mac1, mac2.
 */
public final class HandshakeResponse extends HandshakeMessage {
  /** Encoded length in bytes. */
  public static final int LENGTH = 92;

  static final int RECEIVER = 8;
  static final int EPHEMERAL = 12;
  static final int EMPTY = 44;
  static final int EMPTY_LENGTH = 16;
  static final int MAC1 = 60;

  private HandshakeResponse(byte[] bytes) {
    super(bytes);
  }

  static HandshakeResponse create() {
    byte[] b = new byte[LENGTH];
    Bytes.putInt(b, 0, Protocol.TYPE_RESPONSE);
    return new HandshakeResponse(b);
  }

  /**
   * Parses {@code packet[off..off+len)}, copying it.
   *
   * @return the message, or {@code null} if the length or type is wrong
   */
  public static HandshakeResponse parse(byte[] packet, int off, int len) {
    byte[] b = parse(packet, off, len, LENGTH, Protocol.TYPE_RESPONSE);
    return b == null ? null : new HandshakeResponse(b);
  }

  /** Parses a whole packet; see {@link #parse(byte[], int, int)}. */
  public static HandshakeResponse parse(byte[] packet) {
    return parse(packet, 0, packet.length);
  }

  /** The receiver index: the initiator's sender index from the initiation. */
  public int receiver() {
    return Bytes.getInt(bytes, RECEIVER);
  }

  void receiver(int index) {
    Bytes.putInt(bytes, RECEIVER, index);
  }

  byte[] ephemeral() {
    return Bytes.slice(bytes, EPHEMERAL, 32);
  }

  void ephemeral(byte[] key) {
    System.arraycopy(key, 0, bytes, EPHEMERAL, 32);
  }

  byte[] encryptedEmpty() {
    return Bytes.slice(bytes, EMPTY, EMPTY_LENGTH);
  }

  void encryptedEmpty(byte[] value) {
    System.arraycopy(value, 0, bytes, EMPTY, EMPTY_LENGTH);
  }

  @Override
  int mac1Offset() {
    return MAC1;
  }
}
