// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.proxy;

import static org.assertj.core.api.Assertions.assertThat;

import com.skanavi.javaguard.netstack.TcpListener;
import com.skanavi.javaguard.netstack.TcpSocket;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

@Timeout(60)
class LocalProxyTest {
  private RemoteSite site;
  private LocalProxy proxy;

  @BeforeEach
  void setUp() throws Exception {
    site = new RemoteSite();
    proxy = LocalProxy.builder(site.client).build();
  }

  @AfterEach
  void tearDown() throws Exception {
    proxy.close();
    site.close();
  }

  // ---------------------------------------------------------------- SOCKS5

  @Test
  void socksConnectByDomainResolvesThroughTheTunnel() throws Exception {
    try (Socket s = new Socket(proxy.address().getAddress(), proxy.address().getPort())) {
      greet(s, 0x00);
      byte[] name = "web.test".getBytes(StandardCharsets.US_ASCII);
      byte[] req = new byte[7 + name.length];
      req[0] = 5;
      req[1] = 1;
      req[3] = 3;
      req[4] = (byte) name.length;
      System.arraycopy(name, 0, req, 5, name.length);
      req[req.length - 1] = 7;
      s.getOutputStream().write(req);
      byte[] reply = readReply(s.getInputStream());
      assertThat(reply[1]).isEqualTo((byte) 0);
      assertThat(echo(s, "through socks")).isEqualTo("through socks");
    }
    assertThat(site.dnsQueries.get()).isPositive();
  }

  @Test
  void javaNetSocketsWorkThroughTheSocksProxy() throws Exception {
    try (Socket s = new Socket(proxy.socksProxy())) {
      s.connect(InetSocketAddress.createUnresolved("web.test", 7));
      assertThat(echo(s, "java.net.Socket")).isEqualTo("java.net.Socket");
    }
    try (Socket s = proxy.socketFactory().createSocket("web.test", 7)) {
      assertThat(echo(s, "factory")).isEqualTo("factory");
    }
    try (Socket s = proxy.socketFactory().createSocket(InetAddress.ofLiteral("fd00::2"), 7)) {
      assertThat(echo(s, "ipv6")).isEqualTo("ipv6");
    }
  }

  @Test
  void socksReportsFailures() throws Exception {
    assertThat(socksConnectReply(InetAddress.ofLiteral("10.0.0.2").getAddress(), 1, 1))
        .isEqualTo(5); // refused
    assertThat(socksDomainReply("nowhere.test")).isEqualTo(4); // NXDOMAIN
    assertThat(socksDomainReply("localhost")).isEqualTo(4); // never falls back to host DNS
    assertThat(socksConnectReply(InetAddress.ofLiteral("10.0.0.2").getAddress(), 7, 2))
        .isEqualTo(7); // BIND
  }

  @Test
  void socksHalfCloseReachesTheServer() throws Exception {
    try (Socket s = new Socket(proxy.socksProxy())) {
      s.connect(InetSocketAddress.createUnresolved("web.test", 7));
      s.getOutputStream().write(new byte[100_000]);
      s.shutdownOutput();
      assertThat(s.getInputStream().readAllBytes()).hasSize(100_000); // echo ends after our FIN
    }
  }

  @Test
  void socksCarriesBulkTransfersBothWays() throws Exception {
    byte[] data = new byte[8 << 20];
    new Random(1).nextBytes(data);
    try (TcpListener far = site.stack.listenTcp(9);
        ExecutorService sessions = Executors.newVirtualThreadPerTaskExecutor()) {
      List<Future<byte[]>> echoed = new ArrayList<>();
      for (int i = 0; i < 4; i++) {
        Thread.ofVirtual().start(this::echoThroughProxy);
        TcpSocket s = far.accept(Duration.ofSeconds(30));
        echoed.add(sessions.submit(() -> sendAndReadBack(s, data)));
      }
      for (Future<byte[]> e : echoed) {
        assertThat(e.get()).isEqualTo(data);
      }
    }
  }

  @Test
  void socksUsernamePasswordAuthentication() throws Exception {
    try (LocalProxy secured =
        LocalProxy.builder(site.client).credentials("alice", "s3cret").build()) {
      try (Socket s = connect(secured)) {
        s.getOutputStream().write(new byte[] {5, 1, 0}); // offers only "no auth"
        assertThat(s.getInputStream().readNBytes(2)).containsExactly(5, 0xff);
      }
      for (String password : new String[] {"wrong", "s3cret"}) {
        try (Socket s = connect(secured)) {
          s.getOutputStream().write(new byte[] {5, 1, 2});
          assertThat(s.getInputStream().readNBytes(2)).containsExactly(5, 2);
          byte[] u = "alice".getBytes();
          byte[] p = password.getBytes();
          byte[] auth = new byte[3 + u.length + p.length];
          auth[0] = 1;
          auth[1] = (byte) u.length;
          System.arraycopy(u, 0, auth, 2, u.length);
          auth[2 + u.length] = (byte) p.length;
          System.arraycopy(p, 0, auth, 3 + u.length, p.length);
          s.getOutputStream().write(auth);
          assertThat(s.getInputStream().readNBytes(2)[1])
              .isEqualTo((byte) (password.equals("s3cret") ? 0 : 1));
        }
      }
    }
  }

  @Test
  void socksUdpAssociateRelaysDatagrams() throws Exception {
    try (Socket control = connect(proxy);
        DatagramSocket udp =
            new DatagramSocket(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0))) {
      greet(control, 0x00);
      control.getOutputStream().write(new byte[] {5, 3, 0, 1, 0, 0, 0, 0, 0, 0});
      byte[] reply = readReply(control.getInputStream());
      assertThat(reply[1]).isEqualTo((byte) 0);
      InetSocketAddress relay =
          new InetSocketAddress(
              InetAddress.getByAddress(Arrays.copyOfRange(reply, 4, 8)),
              ((reply[8] & 0xff) << 8) | (reply[9] & 0xff));
      udp.setSoTimeout(5000);
      // By domain, then by IPv4 address.
      byte[] name = "web.test".getBytes();
      byte[] byName = new byte[7 + name.length + 4];
      byName[3] = 3;
      byName[4] = (byte) name.length;
      System.arraycopy(name, 0, byName, 5, name.length);
      byName[6 + name.length] = 7;
      System.arraycopy("ping".getBytes(), 0, byName, 7 + name.length, 4);
      udp.send(new DatagramPacket(byName, byName.length, relay));
      DatagramPacket p = new DatagramPacket(new byte[2000], 2000);
      udp.receive(p);
      assertThat(p.getData()[3]).isEqualTo((byte) 1); // reply carries the IPv4 source
      assertThat(Arrays.copyOfRange(p.getData(), 4, 8))
          .isEqualTo(InetAddress.ofLiteral("10.0.0.2").getAddress());
      assertThat(new String(p.getData(), 10, p.getLength() - 10)).isEqualTo("ping");
    }
  }

  // ---------------------------------------------------------------- HTTP

  @Test
  void httpConnectTunnels() throws Exception {
    try (Socket s = connect(proxy)) {
      s.getOutputStream()
          .write("CONNECT web.test:7 HTTP/1.1\r\nHost: web.test:7\r\n\r\n".getBytes());
      assertThat(readLine(s.getInputStream())).startsWith("HTTP/1.1 200");
      readLine(s.getInputStream()); // blank line
      assertThat(echo(s, "tunnel")).isEqualTo("tunnel");
    }
    try (Socket s = connect(proxy)) {
      s.getOutputStream().write("CONNECT 10.0.0.2:1 HTTP/1.1\r\n\r\n".getBytes());
      assertThat(readLine(s.getInputStream())).startsWith("HTTP/1.1 502");
    }
  }

  @Test
  void httpClientUsesTheProxyForPlainHttp() throws Exception {
    HttpClient client = proxy.httpClientBuilder().build();
    HttpResponse<String> r =
        client.send(
            HttpRequest.newBuilder(URI.create("http://web.test/hello?x=1")).build(),
            HttpResponse.BodyHandlers.ofString());
    assertThat(r.statusCode()).isEqualTo(200);
    assertThat(r.body())
        .startsWith("GET /hello?x=1 HTTP/1.1\r\n")
        .containsIgnoringCase("host: web.test")
        .contains("Connection: close")
        .doesNotContainIgnoringCase("proxy-");
  }

  @Test
  void httpProxyAuthentication() throws Exception {
    try (LocalProxy secured = LocalProxy.builder(site.client).credentials("bob", "pw").build()) {
      try (Socket s = connect(secured)) {
        s.getOutputStream()
            .write("GET http://web.test/ HTTP/1.1\r\nHost: web.test\r\n\r\n".getBytes());
        assertThat(readLine(s.getInputStream())).startsWith("HTTP/1.1 407");
      }
      try (Socket s = connect(secured)) {
        String auth = Base64.getEncoder().encodeToString("bob:pw".getBytes());
        s.getOutputStream()
            .write(
                ("GET http://web.test/ HTTP/1.1\r\nHost: web.test\r\n"
                        + "Proxy-Authorization: Basic "
                        + auth
                        + "\r\n\r\n")
                    .getBytes());
        assertThat(readLine(s.getInputStream())).startsWith("HTTP/1.1 200");
      }
    }
  }

  @Test
  void malformedHttpIsRejected() throws Exception {
    try (Socket s = connect(proxy)) {
      s.getOutputStream().write("GET /relative HTTP/1.1\r\n\r\n".getBytes());
      assertThat(readLine(s.getInputStream())).startsWith("HTTP/1.1 400");
    }
  }

  // ---------------------------------------------------------------- helpers

  private static Socket connect(LocalProxy p) throws IOException {
    Socket s = new Socket(p.address().getAddress(), p.address().getPort());
    s.setSoTimeout(10_000);
    return s;
  }

  private static void greet(Socket s, int method) throws IOException {
    s.getOutputStream().write(new byte[] {5, 1, (byte) method});
    assertThat(s.getInputStream().readNBytes(2)).containsExactly(5, method);
  }

  private static byte[] readReply(InputStream in) throws IOException {
    DataInputStream d = new DataInputStream(in);
    byte[] head = d.readNBytes(4);
    int addrLen = head[3] == 1 ? 4 : head[3] == 4 ? 16 : d.readUnsignedByte();
    byte[] rest = d.readNBytes(addrLen + 2);
    byte[] all = new byte[4 + rest.length];
    System.arraycopy(head, 0, all, 0, 4);
    System.arraycopy(rest, 0, all, 4, rest.length);
    return all;
  }

  private int socksConnectReply(byte[] ipv4, int port, int command) throws IOException {
    try (Socket s = connect(proxy)) {
      greet(s, 0);
      s.getOutputStream()
          .write(
              new byte[] {
                5,
                (byte) command,
                0,
                1,
                ipv4[0],
                ipv4[1],
                ipv4[2],
                ipv4[3],
                (byte) (port >>> 8),
                (byte) port
              });
      return readReply(s.getInputStream())[1];
    }
  }

  private int socksDomainReply(String host) throws IOException {
    try (Socket s = connect(proxy)) {
      greet(s, 0);
      byte[] name = host.getBytes();
      byte[] req = new byte[7 + name.length];
      req[0] = 5;
      req[1] = 1;
      req[3] = 3;
      req[4] = (byte) name.length;
      System.arraycopy(name, 0, req, 5, name.length);
      req[req.length - 1] = 80;
      s.getOutputStream().write(req);
      return readReply(s.getInputStream())[1];
    }
  }

  private static String echo(Socket s, String text) throws IOException {
    OutputStream out = s.getOutputStream();
    out.write(text.getBytes());
    out.flush();
    byte[] got = s.getInputStream().readNBytes(text.length());
    return new String(got);
  }

  /**
   * Echoes on one thread, so a full send buffer stops it reading: the proxy then has to write to
   * this socket and read from it with both directions backed up.
   */
  private void echoThroughProxy() {
    try (Socket s = new Socket(proxy.socksProxy())) {
      s.connect(new InetSocketAddress(InetAddress.ofLiteral("10.0.0.2"), 9));
      s.getInputStream().transferTo(s.getOutputStream());
      s.shutdownOutput();
    } catch (IOException e) {
      // the far side's read reports the failure
    }
  }

  /** Sends {@code data} while reading it back. A stalled proxy ends in the read timeout. */
  private static byte[] sendAndReadBack(TcpSocket s, byte[] data) throws Exception {
    try (s) {
      s.readTimeout(Duration.ofSeconds(30));
      Thread writer =
          Thread.ofVirtual()
              .start(
                  () -> {
                    try {
                      s.outputStream().write(data);
                      s.shutdownOutput();
                    } catch (IOException e) {
                      s.abort();
                    }
                  });
      byte[] got = s.inputStream().readAllBytes();
      writer.join();
      return got;
    }
  }

  private static String readLine(InputStream in) throws IOException {
    StringBuilder sb = new StringBuilder();
    int b;
    while ((b = in.read()) >= 0 && b != '\n') {
      if (b != '\r') {
        sb.append((char) b);
      }
    }
    return sb.toString();
  }
}
