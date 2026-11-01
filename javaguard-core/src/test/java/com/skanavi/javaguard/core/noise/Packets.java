// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core.noise;

import com.skanavi.javaguard.crypto.ChaCha20Poly1305;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;

/**
 * Test-only helpers: WireGuard transport framing (until the transport layer exists) and IPv4 ICMP
 * echo packets.
 */
final class Packets {
  private Packets() {}

  /** Encrypts {@code plaintext} (zero-padded to 16 bytes) into a type-4 transport message. */
  static byte[] seal(Keypair kp, long counter, byte[] plaintext) {
    int padded = (plaintext.length + 15) & ~15;
    byte[] body = Arrays.copyOf(plaintext, padded);
    byte[] out = new byte[16 + padded + ChaCha20Poly1305.TAG_LENGTH];
    ByteBuffer.wrap(out)
        .order(ByteOrder.LITTLE_ENDIAN)
        .putInt(Protocol.TYPE_TRANSPORT)
        .putInt(kp.remoteIndex())
        .putLong(counter);
    new ChaCha20Poly1305().seal(kp.sendKey(), counter, body, 0, padded, out, 16, null);
    return out;
  }

  /** Decrypts a type-4 transport message addressed to {@code kp}; returns the padded plaintext. */
  static byte[] open(Keypair kp, byte[] packet, int len) throws AEADBadTagException {
    ByteBuffer b = ByteBuffer.wrap(packet, 0, len).order(ByteOrder.LITTLE_ENDIAN);
    if (len < 32 || b.getInt() != Protocol.TYPE_TRANSPORT || b.getInt() != kp.localIndex()) {
      throw new AssertionError("not a transport message for " + kp);
    }
    long counter = b.getLong();
    byte[] out = new byte[len - 32];
    new ChaCha20Poly1305().open(kp.receiveKey(), counter, packet, 16, len - 16, out, 0, null);
    return out;
  }

  static byte[] icmpEcho(byte[] src, byte[] dst, int type, int id, int seq, byte[] payload) {
    int len = 20 + 8 + payload.length;
    ByteBuffer b = ByteBuffer.allocate(len);
    b.put((byte) 0x45).put((byte) 0).putShort((short) len);
    b.putShort((short) 0).putShort((short) 0x4000); // id, DF
    b.put((byte) 64).put((byte) 1).putShort((short) 0); // ttl, ICMP, checksum
    b.put(src).put(dst);
    b.put((byte) type).put((byte) 0).putShort((short) 0).putShort((short) id).putShort((short) seq);
    b.put(payload);
    byte[] p = b.array();
    putShort(p, 10, checksum(p, 0, 20));
    putShort(p, 22, checksum(p, 20, len - 20));
    return p;
  }

  /** Builds the echo reply for an IPv4 ICMP echo request. */
  static byte[] echoReply(byte[] request) {
    int total = ((request[2] & 0xff) << 8) | (request[3] & 0xff);
    byte[] src = Arrays.copyOfRange(request, 12, 16);
    byte[] dst = Arrays.copyOfRange(request, 16, 20);
    int id = ((request[24] & 0xff) << 8) | (request[25] & 0xff);
    int seq = ((request[26] & 0xff) << 8) | (request[27] & 0xff);
    return icmpEcho(dst, src, 0, id, seq, Arrays.copyOfRange(request, 28, total));
  }

  static boolean isIcmp(byte[] ip, int icmpType, byte[] src) {
    return ip.length >= 28
        && (ip[0] >> 4) == 4
        && ip[9] == 1
        && Arrays.equals(ip, 12, 16, src, 0, 4)
        && (ip[20] & 0xff) == icmpType;
  }

  private static int checksum(byte[] b, int off, int len) {
    long sum = 0;
    for (int i = 0; i + 1 < len; i += 2) {
      sum += ((b[off + i] & 0xff) << 8) | (b[off + i + 1] & 0xff);
    }
    if ((len & 1) != 0) {
      sum += (b[off + len - 1] & 0xff) << 8;
    }
    while ((sum >> 16) != 0) {
      sum = (sum & 0xffff) + (sum >> 16);
    }
    return (int) (~sum & 0xffff);
  }

  private static void putShort(byte[] b, int off, int v) {
    b[off] = (byte) (v >> 8);
    b[off + 1] = (byte) v;
  }
}
