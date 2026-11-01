// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/** Builds and reads minimal IPv4 packets (protocol 253, experimental) for tests. */
final class Ipv4 {
  private Ipv4() {}

  static byte[] packet(byte[] src, byte[] dst, byte[] payload) {
    int len = 20 + payload.length;
    return ByteBuffer.allocate(len)
        .put((byte) 0x45)
        .put((byte) 0)
        .putShort((short) len)
        .putInt(0)
        .put((byte) 64)
        .put((byte) 253)
        .putShort((short) 0)
        .put(src)
        .put(dst)
        .put(payload)
        .array();
  }

  static String payload(byte[] packet) {
    return new String(packet, 20, packet.length - 20, StandardCharsets.UTF_8);
  }
}
