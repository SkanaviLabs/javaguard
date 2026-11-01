// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.netstack;

/**
 * A parsed TCP segment (RFC 9293), and builders for outgoing segments. Understands the MSS,
 * window-scale, SACK-permitted and SACK options (RFC 7323, RFC 2018); other options are skipped.
 *
 * @param srcPort source port
 * @param dstPort destination port
 * @param seq sequence number
 * @param ack acknowledgment number
 * @param flags control bits ({@link #FIN}, {@link #SYN}, ...)
 * @param window the raw (unscaled) window field
 * @param mss the MSS option value, or -1
 * @param windowScale the window-scale option shift, or -1
 * @param sackPermitted whether the SACK-permitted option was present
 * @param sackBlocks SACK blocks as {@code [left0, right0, left1, right1, ...]}, or {@code null}
 * @param data the buffer holding the payload
 * @param dataOffset payload start in {@code data}
 * @param dataLength payload length
 */
record TcpSegment(
    int srcPort,
    int dstPort,
    int seq,
    int ack,
    int flags,
    int window,
    int mss,
    int windowScale,
    boolean sackPermitted,
    int[] sackBlocks,
    byte[] data,
    int dataOffset,
    int dataLength) {
  static final int FIN = 0x01;
  static final int SYN = 0x02;
  static final int RST = 0x04;
  static final int PSH = 0x08;
  static final int ACK = 0x10;
  static final int HEADER = 20;

  boolean has(int flag) {
    return (flags & flag) != 0;
  }

  /** Sequence space the segment occupies: payload plus one each for SYN and FIN. */
  int sequenceLength() {
    return dataLength + (has(SYN) ? 1 : 0) + (has(FIN) ? 1 : 0);
  }

  /** Parses the TCP payload of {@code ip}, verifying the checksum; {@code null} if invalid. */
  static TcpSegment parse(IpPacket ip) {
    byte[] p = ip.data();
    int off = ip.payloadOffset();
    int len = ip.payloadLength();
    if (len < HEADER) {
      return null;
    }
    int headerLength = ((p[off + 12] & 0xff) >>> 4) * 4;
    if (headerLength < HEADER || headerLength > len) {
      return null;
    }
    long sum = Checksum.pseudoHeader(ip.src(), ip.dst(), IpPacket.TCP, len);
    if (Checksum.finish(Checksum.add(sum, p, off, len)) != 0) {
      return null;
    }
    int mss = -1;
    int windowScale = -1;
    boolean sackPermitted = false;
    int[] sackBlocks = null;
    for (int i = off + HEADER; i < off + headerLength; ) {
      int kind = p[i] & 0xff;
      if (kind == 0) {
        break; // end of options
      }
      if (kind == 1) {
        i++; // NOP
        continue;
      }
      if (i + 1 >= off + headerLength) {
        return null;
      }
      int optLen = p[i + 1] & 0xff;
      if (optLen < 2 || i + optLen > off + headerLength) {
        return null;
      }
      if (kind == 2 && optLen == 4) {
        mss = IpPacket.u16(p, i + 2);
      } else if (kind == 3 && optLen == 3) {
        windowScale = Math.min(p[i + 2] & 0xff, 14);
      } else if (kind == 4 && optLen == 2) {
        sackPermitted = true;
      } else if (kind == 5 && optLen >= 10 && (optLen - 2) % 8 == 0) {
        sackBlocks = new int[(optLen - 2) / 4];
        for (int b = 0; b < sackBlocks.length; b++) {
          sackBlocks[b] = u32(p, i + 2 + 4 * b);
        }
      }
      i += optLen;
    }
    return new TcpSegment(
        IpPacket.u16(p, off),
        IpPacket.u16(p, off + 2),
        u32(p, off + 4),
        u32(p, off + 8),
        p[off + 13] & 0x3f,
        IpPacket.u16(p, off + 14),
        mss,
        windowScale,
        sackPermitted,
        sackBlocks,
        p,
        off + headerLength,
        len - headerLength);
  }

  /** Builds a segment with at most the MSS and window-scale options. */
  static byte[] build(
      byte[] src,
      byte[] dst,
      int srcPort,
      int dstPort,
      int seq,
      int ack,
      int flags,
      int window,
      int mss,
      int windowScale,
      byte[] payload,
      int payloadOffset,
      int payloadLength,
      int ipv4Id) {
    return build(
        src,
        dst,
        srcPort,
        dstPort,
        seq,
        ack,
        flags,
        window,
        mss,
        windowScale,
        false,
        null,
        payload,
        payloadOffset,
        payloadLength,
        ipv4Id);
  }

  /**
   * Builds a complete IP packet carrying one TCP segment.
   *
   * @param mss MSS option to include, or -1
   * @param windowScale window-scale option to include, or -1
   * @param sackPermitted whether to include SACK-permitted (SYN segments)
   * @param sackBlocks SACK blocks to include ({@code [left, right, ...]}, at most 4), or null
   */
  static byte[] build(
      byte[] src,
      byte[] dst,
      int srcPort,
      int dstPort,
      int seq,
      int ack,
      int flags,
      int window,
      int mss,
      int windowScale,
      boolean sackPermitted,
      int[] sackBlocks,
      byte[] payload,
      int payloadOffset,
      int payloadLength,
      int ipv4Id) {
    int sackLength = sackBlocks == null ? 0 : 4 + 4 * sackBlocks.length;
    int optionsLength =
        (mss >= 0 ? 4 : 0) + (windowScale >= 0 ? 4 : 0) + (sackPermitted ? 4 : 0) + sackLength;
    int headerLength = HEADER + optionsLength;
    int tcpLength = headerLength + payloadLength;
    byte[] p = IpPacket.build(src, dst, IpPacket.TCP, tcpLength, ipv4Id);
    int t = IpPacket.headerLength(src.length == 4 ? 4 : 6);
    IpPacket.put16(p, t, srcPort);
    IpPacket.put16(p, t + 2, dstPort);
    put32(p, t + 4, seq);
    put32(p, t + 8, ack);
    p[t + 12] = (byte) ((headerLength / 4) << 4);
    p[t + 13] = (byte) flags;
    IpPacket.put16(p, t + 14, window);
    int o = t + HEADER;
    if (mss >= 0) {
      p[o] = 2;
      p[o + 1] = 4;
      IpPacket.put16(p, o + 2, mss);
      o += 4;
    }
    if (windowScale >= 0) {
      p[o] = 1; // NOP for alignment
      p[o + 1] = 3;
      p[o + 2] = 3;
      p[o + 3] = (byte) windowScale;
      o += 4;
    }
    if (sackPermitted) {
      p[o] = 1;
      p[o + 1] = 1;
      p[o + 2] = 4;
      p[o + 3] = 2;
      o += 4;
    }
    if (sackBlocks != null) {
      p[o] = 1;
      p[o + 1] = 1;
      p[o + 2] = 5;
      p[o + 3] = (byte) (2 + 4 * sackBlocks.length);
      o += 4;
      for (int edge : sackBlocks) {
        put32(p, o, edge);
        o += 4;
      }
    }
    if (payloadLength > 0) {
      System.arraycopy(payload, payloadOffset, p, o, payloadLength);
    }
    long sum = Checksum.pseudoHeader(src, dst, IpPacket.TCP, tcpLength);
    IpPacket.put16(p, t + 16, Checksum.finish(Checksum.add(sum, p, t, tcpLength)));
    return p;
  }

  static int u32(byte[] b, int off) {
    return ((b[off] & 0xff) << 24)
        | ((b[off + 1] & 0xff) << 16)
        | ((b[off + 2] & 0xff) << 8)
        | (b[off + 3] & 0xff);
  }

  static void put32(byte[] b, int off, int v) {
    b[off] = (byte) (v >>> 24);
    b[off + 1] = (byte) (v >>> 16);
    b[off + 2] = (byte) (v >>> 8);
    b[off + 3] = (byte) v;
  }

  /** Sequence-space comparison: whether {@code a} precedes {@code b} (modulo 2^32). */
  static boolean lt(int a, int b) {
    return a - b < 0;
  }

  static boolean le(int a, int b) {
    return a - b <= 0;
  }
}
