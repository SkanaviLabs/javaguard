// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.netstack;

import java.io.ByteArrayOutputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/** DNS (RFC 1035) query encoding and A/AAAA response decoding. */
final class DnsMessage {
  static final int TYPE_A = 1;
  static final int TYPE_CNAME = 5;
  static final int TYPE_AAAA = 28;
  static final int RCODE_OK = 0;
  static final int RCODE_NXDOMAIN = 3;
  private static final int CLASS_IN = 1;
  private static final int MAX_POINTER_HOPS = 32;

  private DnsMessage() {}

  /**
   * A decoded response.
   *
   * @param rcode the response code
   * @param truncated whether the TC bit was set
   * @param addresses A or AAAA records for the query name, following CNAMEs
   */
  record Response(int rcode, boolean truncated, List<InetAddress> addresses) {}

  /** Encodes a recursive query for {@code name} (no trailing dot) of {@code type}. */
  static byte[] query(int id, String name, int type) {
    ByteArrayOutputStream out = new ByteArrayOutputStream(32 + name.length());
    out.write(id >>> 8);
    out.write(id);
    out.write(0x01); // RD
    out.write(0x00);
    out.write(0);
    out.write(1); // QDCOUNT
    out.writeBytes(new byte[6]);
    writeName(out, name);
    out.write(type >>> 8);
    out.write(type);
    out.write(0);
    out.write(CLASS_IN);
    return out.toByteArray();
  }

  /** Validates and encodes a domain name as length-prefixed labels. */
  static void writeName(ByteArrayOutputStream out, String name) {
    if (name.isEmpty() || name.length() > 253) {
      throw new IllegalArgumentException("invalid domain name length: " + name);
    }
    for (String label : name.split("\\.", -1)) {
      byte[] b = label.getBytes(StandardCharsets.US_ASCII);
      if (b.length == 0 || b.length > 63 || !label.chars().allMatch(c -> c > 32 && c < 127)) {
        throw new IllegalArgumentException("invalid domain name: " + name);
      }
      out.write(b.length);
      out.writeBytes(b);
    }
    out.write(0);
  }

  /**
   * Decodes {@code m} as the response to query {@code id} for {@code name}/{@code type}.
   *
   * @return the response, or {@code null} if {@code m} is malformed or answers something else
   */
  static Response parse(byte[] m, int id, String name, int type) {
    try {
      if (m.length < 12 || u16(m, 0) != id || (m[2] & 0x80) == 0) {
        return null;
      }
      boolean truncated = (m[2] & 0x02) != 0;
      int rcode = m[3] & 0x0f;
      int qd = u16(m, 4);
      int an = u16(m, 6);
      if (qd != 1) {
        return null;
      }
      int[] pos = {12};
      String qname = readName(m, pos);
      int qtype = u16(m, pos[0]);
      int qclass = u16(m, pos[0] + 2);
      pos[0] += 4;
      if (!qname.equalsIgnoreCase(name) || qtype != type || qclass != CLASS_IN) {
        return null;
      }
      record Rr(String owner, int type, byte[] m, int rdata, int rdlength) {}
      List<Rr> answers = new ArrayList<>();
      for (int i = 0; i < an; i++) {
        String owner = readName(m, pos);
        int rtype = u16(m, pos[0]);
        int rclass = u16(m, pos[0] + 2);
        int rdlength = u16(m, pos[0] + 8);
        int rdata = pos[0] + 10;
        if (rdata + rdlength > m.length) {
          return null;
        }
        if (rclass == CLASS_IN) {
          answers.add(new Rr(owner.toLowerCase(Locale.ROOT), rtype, m, rdata, rdlength));
        }
        pos[0] = rdata + rdlength;
      }
      // Follow the CNAME chain from the query name, then collect addresses of any name in it.
      Set<String> names = new HashSet<>();
      names.add(name.toLowerCase(Locale.ROOT));
      for (boolean grew = true; grew; ) {
        grew = false;
        for (Rr rr : answers) {
          if (rr.type() == TYPE_CNAME && names.contains(rr.owner())) {
            int[] p = {rr.rdata()};
            grew |= names.add(readName(m, p).toLowerCase(Locale.ROOT));
          }
        }
      }
      List<InetAddress> addresses = new ArrayList<>();
      for (Rr rr : answers) {
        int expected = type == TYPE_A ? 4 : 16;
        if (rr.type() == type && rr.rdlength() == expected && names.contains(rr.owner())) {
          byte[] a = new byte[expected];
          System.arraycopy(m, rr.rdata(), a, 0, expected);
          addresses.add(IpPacket.address(a));
        }
      }
      return new Response(rcode, truncated, addresses);
    } catch (ArrayIndexOutOfBoundsException | IllegalArgumentException e) {
      return null;
    }
  }

  /** Reads a possibly compressed name at {@code pos[0]}, advancing past it. */
  static String readName(byte[] m, int[] pos) {
    StringBuilder sb = new StringBuilder();
    int p = pos[0];
    int end = -1;
    for (int hops = 0; ; ) {
      int len = m[p] & 0xff;
      if (len == 0) {
        p++;
        break;
      }
      if ((len & 0xc0) == 0xc0) {
        if (++hops > MAX_POINTER_HOPS) {
          throw new IllegalArgumentException("DNS compression loop");
        }
        if (end < 0) {
          end = p + 2;
        }
        p = ((len & 0x3f) << 8) | (m[p + 1] & 0xff);
        continue;
      }
      if ((len & 0xc0) != 0) {
        throw new IllegalArgumentException("unsupported DNS label type");
      }
      if (p + 1 + len > m.length) {
        throw new IllegalArgumentException("DNS label beyond end of message");
      }
      if (sb.length() > 0) {
        sb.append('.');
      }
      sb.append(new String(m, p + 1, len, StandardCharsets.US_ASCII));
      if (sb.length() > 255) {
        throw new IllegalArgumentException("DNS name too long");
      }
      p += 1 + len;
    }
    pos[0] = end >= 0 ? end : p;
    return sb.toString();
  }

  private static int u16(byte[] b, int off) {
    return IpPacket.u16(b, off);
  }
}
