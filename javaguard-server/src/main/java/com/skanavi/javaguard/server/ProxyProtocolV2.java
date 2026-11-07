// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.server;

import com.skanavi.javaguard.crypto.Key;
import com.skanavi.javaguard.crypto.PublicKey;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;

/** Encodes PROXY protocol v2 headers. */
final class ProxyProtocolV2 {
  private static final byte[] SIGNATURE = {
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A
  };
  private static final int VERSION_2_PROXY = 0x21;
  private static final int TCP_OVER_IPV4 = 0x11;
  private static final int TCP_OVER_IPV6 = 0x21;

  private ProxyProtocolV2() {}

  /** The header for a connection from {@code source} to {@code destination}, of one family. */
  static byte[] encode(InetSocketAddress source, InetSocketAddress destination, PublicKey peer) {
    byte[] src = source.getAddress().getAddress();
    byte[] dst = destination.getAddress().getAddress();
    if (src.length != dst.length) {
      throw new IllegalArgumentException("mixed address families");
    }
    int length = 2 * src.length + 4 + 3 + Key.LENGTH;
    ByteBuffer b = ByteBuffer.allocate(SIGNATURE.length + 4 + length);
    b.put(SIGNATURE);
    b.put((byte) VERSION_2_PROXY);
    b.put((byte) (src.length == 4 ? TCP_OVER_IPV4 : TCP_OVER_IPV6));
    b.putShort((short) length);
    b.put(src).put(dst);
    b.putShort((short) source.getPort()).putShort((short) destination.getPort());
    b.put((byte) ProxyHeader.PEER_KEY_TLV).putShort((short) Key.LENGTH).put(peer.toBytes());
    return b.array();
  }
}
