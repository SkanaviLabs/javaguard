// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.proxy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.skanavi.javaguard.netstack.TcpListener;
import com.skanavi.javaguard.netstack.TcpSocket;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

@Timeout(60)
class UpstreamSocks5Test {
  private static final String UPSTREAM = "10.0.0.2";
  private static final int UPSTREAM_PORT = 1080;
  private static final int NO_UPSTREAM_PORT = 1081;
  private static final int REP_OK = 0;
  private static final int REP_FAILURE = 1;
  private static final int REP_HOST_UNREACHABLE = 4;
  private static final int REP_REFUSED = 5;
  private static final int REP_COMMAND_NOT_SUPPORTED = 7;

  private RemoteSite site;
  private FakeUpstream upstream;
  private LocalProxy proxy;

  @BeforeEach
  void setUp() throws Exception {
    site = new RemoteSite();
    upstream = new FakeUpstream(site.stack.listenTcp(UPSTREAM_PORT));
    proxy = LocalProxy.builder(site.client).upstreamSocks5(UPSTREAM, UPSTREAM_PORT).build();
  }

  @AfterEach
  void tearDown() throws Exception {
    proxy.close();
    site.close();
  }

  // ---------------------------------------------------------------- addressing

  @Test
  void hostNamesReachTheUpstreamUnresolved() throws Exception {
    try (Socket s = socksConnectByName(proxy, "nowhere.test", 443)) {
      assertThat(readReply(s)[1]).isEqualTo((byte) REP_OK);
      assertThat(echo(s, "relayed")).isEqualTo("relayed");
    }
    assertThat(upstream.nextRequest())
        .isEqualTo(new Request(3, "nowhere.test", 443)); // NXDOMAIN here
    assertThat(site.dnsQueries.get()).isZero();
  }

  @Test
  void addressLiteralsUseTheirOwnAddressTypes() throws Exception {
    try (Socket s = connect(proxy)) {
      greet(s);
      s.getOutputStream().write(new byte[] {5, 1, 0, 1, (byte) 192, 0, 2, 1, 0, 80});
      assertThat(readReply(s)[1]).isEqualTo((byte) REP_OK);
    }
    assertThat(upstream.nextRequest()).isEqualTo(new Request(1, "192.0.2.1", 80));

    try (Socket s = httpConnect(proxy, "[2001:db8::1]:443")) {
      assertThat(readLine(s)).startsWith("HTTP/1.1 200");
    }
    assertThat(upstream.nextRequest())
        .isEqualTo(new Request(4, InetAddress.ofLiteral("2001:db8::1").getHostAddress(), 443));
    assertThat(site.dnsQueries.get()).isZero();
  }

  @Test
  void theUpstreamsOwnHostNameIsResolvedThroughTheTunnel() throws Exception {
    try (LocalProxy named =
            LocalProxy.builder(site.client).upstreamSocks5("web.test", UPSTREAM_PORT).build();
        Socket s = socksConnectByName(named, "target.test", 80)) {
      assertThat(readReply(s)[1]).isEqualTo((byte) REP_OK);
    }
    assertThat(site.dnsQueries.get()).isPositive();
    assertThat(upstream.nextRequest().host()).isEqualTo("target.test");
  }

  @Test
  void aNameTooLongForSocks5FailsWithoutSendingIt() throws Exception {
    try (Socket s = httpConnect(proxy, "a".repeat(256) + ":80")) {
      assertThat(readLine(s)).startsWith("HTTP/1.1 502");
    }
    assertThat(upstream.requests).isEmpty();
  }

  // ---------------------------------------------------------------- every path

  @Test
  void everyTcpPathGoesThroughTheUpstream() throws Exception {
    try (Socket s = socksConnectByName(proxy, "socks.test", 7)) {
      assertThat(readReply(s)[1]).isEqualTo((byte) REP_OK);
      assertThat(echo(s, "socks")).isEqualTo("socks");
    }
    assertThat(upstream.nextRequest().host()).isEqualTo("socks.test");

    try (Socket s = httpConnect(proxy, "tunnel.test:7")) {
      assertThat(readLine(s)).startsWith("HTTP/1.1 200");
      readLine(s); // blank line
      assertThat(echo(s, "tunnel")).isEqualTo("tunnel");
    }
    assertThat(upstream.nextRequest().host()).isEqualTo("tunnel.test");

    try (Socket s = connect(proxy)) {
      s.getOutputStream()
          .write("GET http://plain.test/x HTTP/1.1\r\nHost: plain.test\r\n\r\n".getBytes());
      assertThat(readLine(s)).isEqualTo("GET /x HTTP/1.1"); // the upstream echoes the request
    }
    assertThat(upstream.nextRequest()).isEqualTo(new Request(3, "plain.test", 80));
  }

  @Test
  void udpAssociateIsRefused() throws Exception {
    try (Socket s = connect(proxy)) {
      greet(s);
      s.getOutputStream().write(new byte[] {5, 3, 0, 1, 0, 0, 0, 0, 0, 0});
      assertThat(readReply(s)[1]).isEqualTo((byte) REP_COMMAND_NOT_SUPPORTED);
    }
  }

  @Test
  void withoutAnUpstreamTargetsAreDialedDirectly() throws Exception {
    try (LocalProxy direct = LocalProxy.builder(site.client).build();
        Socket s = socksConnectByName(direct, "web.test", 7)) {
      assertThat(readReply(s)[1]).isEqualTo((byte) REP_OK);
      assertThat(echo(s, "direct")).isEqualTo("direct");
    }
    assertThat(site.dnsQueries.get()).isPositive();
    assertThat(upstream.connections.get()).isZero();
  }

  // ---------------------------------------------------------------- authentication

  @Test
  void authenticatesToTheUpstream() throws Exception {
    upstream.requiredPassword = "pässword";
    try (LocalProxy authed = withCredentials("alice", "pässword");
        Socket s = socksConnectByName(authed, "target.test", 80)) {
      assertThat(readReply(s)[1]).isEqualTo((byte) REP_OK);
      assertThat(echo(s, "authed")).isEqualTo("authed");
    }
    assertThat(upstream.offeredMethods.poll(5, TimeUnit.SECONDS)).containsExactly(0, 2);
    assertThat(upstream.seenUser).isEqualTo("alice");
  }

  @Test
  void anUpstreamWithoutAuthenticationNeedsNoCredentialsSent() throws Exception {
    try (LocalProxy authed = withCredentials("alice", "pw");
        Socket s = socksConnectByName(authed, "target.test", 80)) {
      assertThat(readReply(s)[1]).isEqualTo((byte) REP_OK);
    }
    assertThat(upstream.seenUser).isNull();
  }

  @Test
  void rejectedCredentialsFailTheConnection() throws Exception {
    upstream.requiredPassword = "right";
    try (LocalProxy authed = withCredentials("alice", "wrong");
        Socket s = socksConnectByName(authed, "target.test", 80)) {
      assertThat(readReply(s)[1]).isEqualTo((byte) REP_FAILURE);
    }
    assertThat(upstream.requests).isEmpty();
  }

  @Test
  void anUpstreamDemandingCredentialsWeLackFailsTheConnection() throws Exception {
    upstream.forcedMethod = 2;
    try (Socket s = socksConnectByName(proxy, "target.test", 80)) {
      assertThat(readReply(s)[1]).isEqualTo((byte) REP_FAILURE);
    }
    assertThat(upstream.requests).isEmpty();
  }

  // ---------------------------------------------------------------- replies

  @Test
  void upstreamRepliesMapToClientErrors() throws Exception {
    record Case(int upstreamReply, int socksReply, String httpStatus) {}
    List<Case> cases =
        List.of(
            new Case(1, REP_FAILURE, "502"),
            new Case(2, REP_FAILURE, "502"),
            new Case(3, REP_FAILURE, "502"),
            new Case(4, REP_HOST_UNREACHABLE, "504"),
            new Case(5, REP_REFUSED, "502"),
            new Case(6, REP_FAILURE, "502"),
            new Case(7, REP_FAILURE, "502"),
            new Case(8, REP_FAILURE, "502"));
    for (Case c : cases) {
      upstream.reply = c.upstreamReply();
      try (Socket s = socksConnectByName(proxy, "target.test", 80)) {
        assertThat(readReply(s)[1])
            .as("reply %d", c.upstreamReply())
            .isEqualTo((byte) c.socksReply());
      }
      try (Socket s = httpConnect(proxy, "target.test:80")) {
        assertThat(readLine(s)).as("reply %d", c.upstreamReply()).contains(c.httpStatus());
      }
    }
  }

  @Test
  void bytesRightAfterTheReplyAreKept() throws Exception {
    byte[] ipv4 = {1, 10, 0, 0, 2, 0x12, 0x34};
    byte[] ipv6 = new byte[19];
    ipv6[0] = 4;
    byte[] domain = {3, 4, 'h', 'o', 's', 't', 0x12, 0x34};
    byte[] emptyDomain = {3, 0, 0x12, 0x34};
    for (byte[] bound : List.of(ipv4, ipv6, domain, emptyDomain)) {
      upstream.bound = bound;
      upstream.earlyBytes = "early".getBytes();
      try (Socket s = socksConnectByName(proxy, "target.test", 80)) {
        assertThat(readReply(s)[1]).isEqualTo((byte) REP_OK);
        assertThat(s.getInputStream().readNBytes(5)).isEqualTo("early".getBytes());
        assertThat(echo(s, "then more")).isEqualTo("then more");
      }
    }
  }

  @Test
  void aMalformedReplyFailsTheConnection() throws Exception {
    upstream.bound = new byte[] {9, 0, 0};
    try (Socket s = socksConnectByName(proxy, "target.test", 80)) {
      assertThat(readReply(s)[1]).isEqualTo((byte) REP_FAILURE);
    }
    assertThat(upstream.closed.await(5, TimeUnit.SECONDS)).isTrue();
  }

  // ---------------------------------------------------------------- deadlines

  @Test
  void aSilentUpstreamTimesOutAndIsDisconnected() throws Exception {
    upstream.silent = true;
    try (LocalProxy impatient = withTimeout(Duration.ofMillis(300))) {
      try (Socket s = socksConnectByName(impatient, "target.test", 80)) {
        assertThat(readReply(s)[1]).isEqualTo((byte) REP_HOST_UNREACHABLE);
      }
      assertThat(upstream.closed.await(5, TimeUnit.SECONDS)).isTrue();
      try (Socket s = httpConnect(impatient, "target.test:80")) {
        assertThat(readLine(s)).startsWith("HTTP/1.1 504");
      }
    }
  }

  @Test
  void theHandshakeDeadlineDoesNotOutliveTheHandshake() throws Exception {
    try (LocalProxy impatient = withTimeout(Duration.ofMillis(300));
        Socket s = socksConnectByName(impatient, "target.test", 80)) {
      assertThat(readReply(s)[1]).isEqualTo((byte) REP_OK);
      Thread.sleep(600); // idle for longer than the deadline
      assertThat(echo(s, "still here")).isEqualTo("still here");
    }
  }

  // ---------------------------------------------------------------- failing closed

  @Test
  void anUnreachableUpstreamIsAnErrorAndTheTargetSeesNothing() throws Exception {
    AtomicInteger targetConnections = new AtomicInteger();
    TcpListener target = site.stack.listenTcp(9000);
    Thread.ofVirtual()
        .start(
            () -> {
              try {
                while (true) {
                  target.accept();
                  targetConnections.incrementAndGet();
                }
              } catch (IOException e) {
                // closed
              }
            });
    try (LocalProxy down =
        LocalProxy.builder(site.client).upstreamSocks5(UPSTREAM, NO_UPSTREAM_PORT).build()) {
      try (Socket s = connect(down)) {
        greet(s);
        s.getOutputStream().write(new byte[] {5, 1, 0, 1, 10, 0, 0, 2, 0x23, 0x28}); // port 9000
        assertThat(readReply(s)[1]).isEqualTo((byte) REP_REFUSED);
      }
      try (Socket s = httpConnect(down, "10.0.0.2:9000")) {
        assertThat(readLine(s)).startsWith("HTTP/1.1 502");
      }
    }
    Thread.sleep(200); // a stray connection would have completed by now
    assertThat(targetConnections.get()).isZero();
  }

  // ---------------------------------------------------------------- configuration

  @Test
  void badConfigurationFailsWhileBuilding() {
    LocalProxy.Builder b = LocalProxy.builder(site.client);
    assertThatThrownBy(() -> b.upstreamSocks5(null, 1080)).isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> b.upstreamSocks5("", 1080))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> b.upstreamSocks5("h", 0)).isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> b.upstreamSocks5("h", 65536))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> b.upstreamSocks5("h", 1080, null, "p"))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> b.upstreamSocks5("h", 1080, "u", null))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> b.upstreamSocks5("h", 1080, "", "p"))
        .isInstanceOf(IllegalArgumentException.class);
    String secret = "s".repeat(256);
    assertThatThrownBy(() -> b.upstreamSocks5("h", 1080, "u", secret))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageNotContaining(secret);
  }

  // ---------------------------------------------------------------- helpers

  private LocalProxy withCredentials(String user, String password) throws IOException {
    return LocalProxy.builder(site.client)
        .upstreamSocks5(UPSTREAM, UPSTREAM_PORT, user, password)
        .build();
  }

  private LocalProxy withTimeout(Duration timeout) throws IOException {
    return LocalProxy.builder(site.client)
        .upstreamSocks5(UPSTREAM, UPSTREAM_PORT)
        .connectTimeout(timeout)
        .build();
  }

  private static Socket connect(LocalProxy p) throws IOException {
    Socket s = new Socket(p.address().getAddress(), p.address().getPort());
    s.setSoTimeout(10_000);
    return s;
  }

  private static void greet(Socket s) throws IOException {
    s.getOutputStream().write(new byte[] {5, 1, 0});
    assertThat(s.getInputStream().readNBytes(2)).containsExactly(5, 0);
  }

  private static Socket socksConnectByName(LocalProxy p, String host, int port) throws IOException {
    Socket s = connect(p);
    greet(s);
    ByteArrayOutputStream req = new ByteArrayOutputStream();
    req.writeBytes(new byte[] {5, 1, 0, 3, (byte) host.length()});
    req.writeBytes(host.getBytes(StandardCharsets.US_ASCII));
    req.write(port >>> 8);
    req.write(port);
    s.getOutputStream().write(req.toByteArray());
    return s;
  }

  private static Socket httpConnect(LocalProxy p, String authority) throws IOException {
    Socket s = connect(p);
    s.getOutputStream().write(("CONNECT " + authority + " HTTP/1.1\r\n\r\n").getBytes());
    return s;
  }

  private static byte[] readReply(Socket s) throws IOException {
    byte[] reply = s.getInputStream().readNBytes(10); // LocalProxy replies with IPv4 here
    assertThat(reply).hasSize(10);
    return reply;
  }

  private static String echo(Socket s, String text) throws IOException {
    s.getOutputStream().write(text.getBytes());
    return new String(s.getInputStream().readNBytes(text.length()));
  }

  private static String readLine(Socket s) throws IOException {
    InputStream in = s.getInputStream();
    StringBuilder sb = new StringBuilder();
    int b;
    while ((b = in.read()) >= 0 && b != '\n') {
      if (b != '\r') {
        sb.append((char) b);
      }
    }
    return sb.toString();
  }

  /** What a client asked the upstream for. */
  private record Request(int addressType, String host, int port) {}

  /** A scripted SOCKS5 server on the peer's netstack that echoes after a successful CONNECT. */
  private static final class FakeUpstream {
    final BlockingQueue<Request> requests = new LinkedBlockingQueue<>();
    final BlockingQueue<List<Integer>> offeredMethods = new LinkedBlockingQueue<>();
    final AtomicInteger connections = new AtomicInteger();
    final CountDownLatch closed = new CountDownLatch(1);
    volatile int reply = REP_OK;
    volatile byte[] bound = {1, 0, 0, 0, 0, 0, 0};
    volatile byte[] earlyBytes = new byte[0];
    volatile String requiredPassword;
    volatile int forcedMethod = -1;
    volatile boolean silent;
    volatile String seenUser;

    FakeUpstream(TcpListener listener) {
      Thread.ofVirtual().start(() -> acceptLoop(listener));
    }

    Request nextRequest() throws InterruptedException {
      Request r = requests.poll(5, TimeUnit.SECONDS);
      assertThat(r).isNotNull();
      return r;
    }

    private void acceptLoop(TcpListener listener) {
      try {
        while (true) {
          TcpSocket s = listener.accept();
          connections.incrementAndGet();
          Thread.ofVirtual()
              .start(
                  () -> {
                    try (s) {
                      serve(s);
                    } catch (IOException e) {
                      // client went away
                    }
                    closed.countDown();
                  });
        }
      } catch (IOException e) {
        // closed
      }
    }

    private void serve(TcpSocket s) throws IOException {
      DataInputStream in = new DataInputStream(s.inputStream());
      if (silent) {
        in.readAllBytes(); // says nothing, and returns when the client hangs up
        return;
      }
      if (!negotiate(s, in)) {
        return;
      }
      in.readNBytes(3); // version, command, reserved
      int atyp = in.readUnsignedByte();
      String host =
          switch (atyp) {
            case 1 -> InetAddress.getByAddress(in.readNBytes(4)).getHostAddress();
            case 4 -> InetAddress.getByAddress(in.readNBytes(16)).getHostAddress();
            default -> new String(in.readNBytes(in.readUnsignedByte()), StandardCharsets.UTF_8);
          };
      requests.add(new Request(atyp, host, in.readUnsignedShort()));
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      out.writeBytes(new byte[] {5, (byte) reply, 0});
      out.writeBytes(bound);
      out.writeBytes(earlyBytes); // same segment as the reply, as a fast server would send it
      s.outputStream().write(out.toByteArray());
      if (reply == REP_OK) {
        in.transferTo(s.outputStream());
        s.shutdownOutput();
      }
    }

    private boolean negotiate(TcpSocket s, DataInputStream in) throws IOException {
      in.readUnsignedByte(); // version
      byte[] methods = in.readNBytes(in.readUnsignedByte());
      List<Integer> offered = new java.util.ArrayList<>();
      for (byte m : methods) {
        offered.add(m & 0xff);
      }
      offeredMethods.add(offered);
      int method = forcedMethod >= 0 ? forcedMethod : requiredPassword != null ? 2 : 0;
      s.outputStream().write(new byte[] {5, (byte) method});
      if (method != 2) {
        return true;
      }
      if (!offered.contains(2)) {
        return false;
      }
      in.readUnsignedByte(); // subnegotiation version
      seenUser = new String(in.readNBytes(in.readUnsignedByte()), StandardCharsets.UTF_8);
      String password = new String(in.readNBytes(in.readUnsignedByte()), StandardCharsets.UTF_8);
      boolean ok = password.equals(requiredPassword);
      s.outputStream().write(new byte[] {1, (byte) (ok ? 0 : 1)});
      return ok;
    }
  }
}
