// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core.noise;

/** Cookie reply (type 3, 64 bytes): receiver index, 24-byte nonce, encrypted cookie. */
public final class CookieReply {
  /** Encoded length in bytes. */
  public static final int LENGTH = 64;

  static final int RECEIVER = 4;
  static final int NONCE = 8;
  static final int NONCE_LENGTH = 24;
  static final int COOKIE = 32;
  static final int COOKIE_LENGTH = 16 + 16;

  private final byte[] bytes;

  private CookieReply(byte[] bytes) {
    this.bytes = bytes;
  }

  static CookieReply create() {
    byte[] b = new byte[LENGTH];
    Bytes.putInt(b, 0, Protocol.TYPE_COOKIE_REPLY);
    return new CookieReply(b);
  }

  /**
   * Parses {@code packet[off..off+len)}, copying it.
   *
   * @return the message, or {@code null} if the length or type is wrong
   */
  public static CookieReply parse(byte[] packet, int off, int len) {
    if (len != LENGTH || Messages.type(packet, off, len) != Protocol.TYPE_COOKIE_REPLY) {
      return null;
    }
    return new CookieReply(Bytes.slice(packet, off, len));
  }

  /** Parses a whole packet; see {@link #parse(byte[], int, int)}. */
  public static CookieReply parse(byte[] packet) {
    return parse(packet, 0, packet.length);
  }

  /** The encoded message. Returns the backing array; callers must not modify it. */
  public byte[] bytes() {
    return bytes;
  }

  /** The receiver index: the sender index of the handshake message this replies to. */
  public int receiver() {
    return Bytes.getInt(bytes, RECEIVER);
  }

  void receiver(int index) {
    Bytes.putInt(bytes, RECEIVER, index);
  }

  byte[] nonce() {
    return Bytes.slice(bytes, NONCE, NONCE_LENGTH);
  }

  void nonce(byte[] value) {
    System.arraycopy(value, 0, bytes, NONCE, NONCE_LENGTH);
  }

  byte[] encryptedCookie() {
    return Bytes.slice(bytes, COOKIE, COOKIE_LENGTH);
  }

  void encryptedCookie(byte[] value) {
    System.arraycopy(value, 0, bytes, COOKIE, COOKIE_LENGTH);
  }
}
