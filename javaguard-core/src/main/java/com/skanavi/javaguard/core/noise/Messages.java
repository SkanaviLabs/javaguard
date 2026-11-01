// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core.noise;

/** Message type detection for incoming UDP payloads. */
public final class Messages {
  private Messages() {}

  /**
   * Returns the message type of {@code packet[off..off+len)}: one of the {@code Protocol.TYPE_*}
   * constants, or {@code -1} if the packet is too short or its type field is unknown. The type
   * field is a little-endian 32-bit integer; the three reserved bytes must be zero.
   */
  public static int type(byte[] packet, int off, int len) {
    if (len < 4) {
      return -1;
    }
    int type = Bytes.getInt(packet, off);
    return type >= Protocol.TYPE_INITIATION && type <= Protocol.TYPE_TRANSPORT ? type : -1;
  }
}
