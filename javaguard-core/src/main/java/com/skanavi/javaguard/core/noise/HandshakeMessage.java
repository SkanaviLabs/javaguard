// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core.noise;

/**
 * A handshake initiation or response: a fixed-size message ending in {@code mac1} and {@code mac2}.
 * Instances are mutable views over a private byte array.
 */
public abstract sealed class HandshakeMessage permits HandshakeInitiation, HandshakeResponse {
  /** Length of mac1 and mac2. */
  public static final int MAC_LENGTH = 16;

  final byte[] bytes;

  HandshakeMessage(byte[] bytes) {
    this.bytes = bytes;
  }

  static byte[] parse(byte[] packet, int off, int len, int expectedLength, int type) {
    if (len != expectedLength || Messages.type(packet, off, len) != type) {
      return null;
    }
    return Bytes.slice(packet, off, len);
  }

  /** The encoded message. Returns the backing array; callers must not modify it. */
  public final byte[] bytes() {
    return bytes;
  }

  /** The sender's receiver index. */
  public final int sender() {
    return Bytes.getInt(bytes, 4);
  }

  final void sender(int index) {
    Bytes.putInt(bytes, 4, index);
  }

  /** Offset of mac1; everything before it is covered by mac1. */
  abstract int mac1Offset();

  /** Offset of mac2; everything before it is covered by mac2. */
  final int mac2Offset() {
    return mac1Offset() + MAC_LENGTH;
  }

  /** Returns a copy of mac1. */
  public final byte[] mac1() {
    return Bytes.slice(bytes, mac1Offset(), MAC_LENGTH);
  }

  /** Returns a copy of mac2. */
  public final byte[] mac2() {
    return Bytes.slice(bytes, mac2Offset(), MAC_LENGTH);
  }

  final void mac1(byte[] mac) {
    System.arraycopy(mac, 0, bytes, mac1Offset(), MAC_LENGTH);
  }

  final void mac2(byte[] mac) {
    System.arraycopy(mac, 0, bytes, mac2Offset(), MAC_LENGTH);
  }
}
