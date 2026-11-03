// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core.noise;

// Portions derived from wireguard-go (https://git.zx2c4.com/wireguard-go/),
// Copyright (C) 2017-2025 WireGuard LLC. MIT.

/**
 * Handshake initiation (type 1, 148 bytes): sender index, unencrypted ephemeral, encrypted static
 * key, encrypted TAI64N timestamp, mac1, mac2.
 */
public final class HandshakeInitiation extends HandshakeMessage {
  /** Encoded length in bytes. */
  public static final int LENGTH = 148;

  static final int EPHEMERAL = 8;
  static final int STATIC = 40;
  static final int STATIC_LENGTH = 32 + 16;
  static final int TIMESTAMP = 88;
  static final int TIMESTAMP_LENGTH = 12 + 16;
  static final int MAC1 = 116;

  private HandshakeInitiation(byte[] bytes) {
    super(bytes);
  }

  static HandshakeInitiation create() {
    byte[] b = new byte[LENGTH];
    Bytes.putInt(b, 0, Protocol.TYPE_INITIATION);
    return new HandshakeInitiation(b);
  }

  /**
   * Parses {@code packet[off..off+len)}, copying it.
   *
   * @return the message, or {@code null} if the length or type is wrong
   */
  public static HandshakeInitiation parse(byte[] packet, int off, int len) {
    byte[] b = parse(packet, off, len, LENGTH, Protocol.TYPE_INITIATION);
    return b == null ? null : new HandshakeInitiation(b);
  }

  /** Parses a whole packet; see {@link #parse(byte[], int, int)}. */
  public static HandshakeInitiation parse(byte[] packet) {
    return parse(packet, 0, packet.length);
  }

  byte[] ephemeral() {
    return Bytes.slice(bytes, EPHEMERAL, 32);
  }

  void ephemeral(byte[] key) {
    System.arraycopy(key, 0, bytes, EPHEMERAL, 32);
  }

  byte[] encryptedStatic() {
    return Bytes.slice(bytes, STATIC, STATIC_LENGTH);
  }

  void encryptedStatic(byte[] value) {
    System.arraycopy(value, 0, bytes, STATIC, STATIC_LENGTH);
  }

  byte[] encryptedTimestamp() {
    return Bytes.slice(bytes, TIMESTAMP, TIMESTAMP_LENGTH);
  }

  void encryptedTimestamp(byte[] value) {
    System.arraycopy(value, 0, bytes, TIMESTAMP, TIMESTAMP_LENGTH);
  }

  @Override
  int mac1Offset() {
    return MAC1;
  }
}
