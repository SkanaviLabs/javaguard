// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.proxy;

import com.skanavi.javaguard.core.Tun;
import com.skanavi.javaguard.netstack.Netstack;
import com.skanavi.javaguard.netstack.TcpListener;
import com.skanavi.javaguard.netstack.TcpSocket;
import com.skanavi.javaguard.netstack.UdpSocket;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The far side of a tunnel for tests: a netstack at 10.0.0.2 / fd00::2 running TCP echo (7), UDP
 * echo (7), an HTTP server (80) that echoes the request head, and DNS (53) answering {@code
 * web.test} with its own addresses and NXDOMAIN for everything else.
 */
final class RemoteSite implements AutoCloseable {
  final Netstack stack = Netstack.builder().address("10.0.0.2/24").address("fd00::2/64").build();
  final Netstack client =
      Netstack.builder().address("10.0.0.1/24").address("fd00::1/64").dns("10.0.0.2").build();
  final AtomicInteger dnsQueries = new AtomicInteger();

  RemoteSite() throws IOException {
    wire(client, stack);
    wire(stack, client);
    TcpListener echo = stack.listenTcp(7);
    TcpListener http = stack.listenTcp(80);
    UdpSocket udpEcho = stack.openUdp(7);
    UdpSocket dns = stack.openUdp(53);
    daemon(() -> acceptLoop(echo, RemoteSite::echo));
    daemon(() -> acceptLoop(http, RemoteSite::http));
    daemon(() -> udpLoop(udpEcho, d -> d.data()));
    daemon(
        () ->
            udpLoop(
                dns,
                d -> {
                  dnsQueries.incrementAndGet();
                  return dnsAnswer(d.data());
                }));
  }

  @Override
  public void close() {
    client.close();
    stack.close();
  }

  private static void wire(Tun from, Tun to) {
    daemon(
        () -> {
          byte[] buf = new byte[65536];
          try {
            int n;
            while ((n = from.read(buf, 0, buf.length)) >= 0) {
              to.write(buf, 0, n);
            }
          } catch (IOException e) {
            // closed
          }
        });
  }

  interface Handler {
    void handle(TcpSocket s) throws IOException;
  }

  private static void acceptLoop(TcpListener l, Handler h) {
    try {
      while (true) {
        TcpSocket s = l.accept();
        daemon(
            () -> {
              try (s) {
                h.handle(s);
              } catch (IOException e) {
                // client went away
              }
            });
      }
    } catch (IOException e) {
      // closed
    }
  }

  private static void echo(TcpSocket s) throws IOException {
    s.inputStream().transferTo(s.outputStream());
    s.shutdownOutput();
  }

  private static void http(TcpSocket s) throws IOException {
    ByteArrayOutputStream head = new ByteArrayOutputStream();
    int b;
    int matched = 0;
    while (matched < 4 && (b = s.inputStream().read()) >= 0) {
      head.write(b);
      matched = (b == "\r\n\r\n".charAt(matched)) ? matched + 1 : (b == '\r' ? 1 : 0);
    }
    byte[] body = head.toByteArray();
    s.outputStream()
        .write(
            ("HTTP/1.1 200 OK\r\nContent-Length: " + body.length + "\r\nConnection: close\r\n\r\n")
                .getBytes(StandardCharsets.US_ASCII));
    s.outputStream().write(body);
    s.shutdownOutput();
    s.inputStream().readAllBytes();
  }

  interface Responder {
    byte[] answer(UdpSocket.Datagram d);
  }

  private static void udpLoop(UdpSocket socket, Responder r) {
    try {
      while (true) {
        UdpSocket.Datagram d = socket.receive(Duration.ofSeconds(60));
        if (d != null) {
          byte[] reply = r.answer(d);
          if (reply != null) {
            socket.send(d.source(), reply);
          }
        }
      }
    } catch (Exception e) {
      // closed
    }
  }

  /** Answers A/AAAA for web.test; NXDOMAIN otherwise. */
  static byte[] dnsAnswer(byte[] q) {
    int p = 12;
    StringBuilder name = new StringBuilder();
    while (q[p] != 0) {
      if (name.length() > 0) {
        name.append('.');
      }
      name.append(new String(q, p + 1, q[p], StandardCharsets.US_ASCII));
      p += 1 + q[p];
    }
    int qtype = ((q[p + 1] & 0xff) << 8) | (q[p + 2] & 0xff);
    int questionEnd = p + 5;
    boolean known = name.toString().equalsIgnoreCase("web.test");
    byte[] addr =
        known && qtype == 1
            ? InetAddress.ofLiteral("10.0.0.2").getAddress()
            : known && qtype == 28 ? InetAddress.ofLiteral("fd00::2").getAddress() : null;
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.write(q[0]);
    out.write(q[1]);
    out.write(0x81);
    out.write(known ? 0x80 : 0x83);
    out.writeBytes(new byte[] {0, 1, 0, (byte) (addr == null ? 0 : 1), 0, 0, 0, 0});
    out.write(q, 12, questionEnd - 12);
    if (addr != null) {
      out.writeBytes(
          new byte[] {(byte) 0xc0, 12, 0, (byte) qtype, 0, 1, 0, 0, 0, 60, 0, (byte) addr.length});
      out.writeBytes(addr);
    }
    return out.toByteArray();
  }

  private static void daemon(Runnable r) {
    Thread.ofVirtual().start(r);
  }
}
