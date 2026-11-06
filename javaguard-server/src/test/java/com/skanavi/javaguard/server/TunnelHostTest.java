// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.server;

import static com.skanavi.javaguard.server.TunnelClient.config;
import static com.skanavi.javaguard.server.TunnelClient.freeUdpPort;
import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.skanavi.javaguard.config.ConfigException;
import com.skanavi.javaguard.config.WgQuickConfig;
import com.skanavi.javaguard.core.IpPrefix;
import com.skanavi.javaguard.core.PeerConfig;
import com.skanavi.javaguard.crypto.PrivateKey;
import com.skanavi.javaguard.netstack.TcpSocket;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Random;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.eclipse.jetty.server.Server;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

@SuppressWarnings("try") // sockets held open for the length of a block
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class TunnelHostTest {
  private static final Duration LONG = Duration.ofSeconds(20);
  private static final int PORT = 7000;
  private static final int HEADER_LENGTH = 16 + 12 + 35;

  private final PrivateKey hostKey = PrivateKey.generate();
  private final List<AutoCloseable> resources = new ArrayList<>();
  private final TunnelClient alice = track(new TunnelClient("10.60.0.2"));
  private final TunnelClient bob = track(new TunnelClient("10.60.0.3"));
  private int hostPort;

  @AfterEach
  void closeEverything() throws Exception {
    for (AutoCloseable c : resources.reversed()) {
      c.close();
    }
  }

  private <T extends AutoCloseable> T track(T resource) {
    resources.add(resource);
    return resource;
  }

  private TunnelHost start(TunnelHost.Builder builder) throws Exception {
    hostPort = freeUdpPort();
    TunnelHost host =
        track(builder.start(WgQuickConfig.parse(config(hostKey, hostPort, alice, bob))));
    alice.start(hostKey.publicKey(), hostPort);
    bob.start(hostKey.publicKey(), hostPort);
    return host;
  }

  private TunnelHost start() throws Exception {
    return start(TunnelHost.builder());
  }

  private Path socketPath() throws IOException {
    Path dir = Files.createTempDirectory(Path.of("/tmp"), "jg"); // short: paths have a size limit
    resources.add(
        () -> {
          Files.deleteIfExists(dir.resolve("s"));
          Files.delete(dir);
        });
    return dir.resolve("s");
  }

  @Test
  void handlersLearnWhichPeerConnected() throws Exception {
    TunnelHost host = start();
    host.serveTcp(PORT, c -> c.socket().outputStream().write(c.peer().toBytes()));

    for (TunnelClient client : List.of(alice, bob)) {
      try (TcpSocket s = client.connect(PORT, LONG)) {
        assertThat(s.inputStream().readAllBytes()).isEqualTo(client.publicKey().toBytes());
      }
    }
  }

  @Test
  void aUnixSocketTargetGetsAProxyHeaderThenTheStream() throws Exception {
    TunnelHost host = start();
    Path path = socketPath();
    ServerSocketChannel server = track(ServerSocketChannel.open(StandardProtocolFamily.UNIX));
    server.bind(UnixDomainSocketAddress.of(path));
    CompletableFuture<byte[]> header = new CompletableFuture<>();
    Thread.ofVirtual()
        .start(
            () -> {
              try (SocketChannel c = server.accept()) {
                ByteBuffer head = ByteBuffer.allocate(HEADER_LENGTH);
                while (head.hasRemaining() && c.read(head) >= 0) {}
                header.complete(head.array());
                byte[] body = Channels.newInputStream(c).readAllBytes(); // to the half-close
                c.write(
                    ByteBuffer.wrap(new String(body, US_ASCII).toUpperCase().getBytes(US_ASCII)));
              } catch (IOException e) {
                header.completeExceptionally(e);
              }
            });
    host.expose(PORT, Target.unixSocket(path), ProxyHeader.V2);

    try (TcpSocket s = alice.connect(PORT, LONG)) {
      s.outputStream().write("hello".getBytes(US_ASCII));
      s.shutdownOutput();

      assertThat(new String(s.inputStream().readAllBytes(), US_ASCII)).isEqualTo("HELLO");
      assertThat(header.get())
          .isEqualTo(
              ProxyProtocolV2.encode(
                  s.localAddress(),
                  new InetSocketAddress(InetAddress.ofLiteral(TunnelClient.HOST_IP), PORT),
                  alice.publicKey()));
    }
  }

  @Test
  void jettyOnAUnixSocketSeesTheRealPeer() throws Exception {
    TunnelHost host = start();
    Path path = socketPath();
    Server jetty = WebServer.start(path);
    resources.add(jetty::stop);
    host.expose(PORT, Target.unixSocket(path), ProxyHeader.V2);

    for (TunnelClient client : List.of(alice, bob)) {
      try (TcpSocket s = client.connect(PORT, LONG)) {
        s.outputStream()
            .write("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".getBytes(US_ASCII));
        String response = new String(s.inputStream().readAllBytes(), US_ASCII);

        assertThat(response)
            .startsWith("HTTP/1.1 200")
            .endsWith(client.ip + " " + HexFormat.of().formatHex(client.publicKey().toBytes()));
      }
    }
  }

  @Test
  void aLoopbackTargetCarriesABulkTransferBothWays() throws Exception {
    TunnelHost host = start();
    ServerSocket server = track(new ServerSocket(0, 1, InetAddress.getLoopbackAddress()));
    Thread.ofVirtual()
        .start(
            () -> {
              try (Socket c = server.accept()) {
                c.getInputStream().transferTo(c.getOutputStream());
              } catch (IOException e) {
                // the client side reports the failure
              }
            });
    host.expose(PORT, Target.loopback(server.getLocalPort()));

    byte[] data = new byte[8 << 20];
    new Random(1).nextBytes(data);
    try (TcpSocket s = alice.connect(PORT, LONG)) {
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
      assertThat(s.inputStream().readAllBytes()).isEqualTo(data);
      writer.join();
    }
  }

  @Test
  void aMissingTargetResetsThePeer() throws Exception {
    TunnelHost host = start();
    int unused;
    try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
      unused = s.getLocalPort();
    }
    host.expose(PORT, Target.loopback(unused));

    try (TcpSocket s = alice.connect(PORT, LONG)) {
      assertThatThrownBy(() -> s.inputStream().read()).isInstanceOf(IOException.class);
    }
  }

  /** Holds each connection open and records how its read ended. */
  private static ConnectionHandler holding(
      CountDownLatch accepted, CompletableFuture<Throwable> ended) {
    return c -> {
      accepted.countDown();
      try {
        c.socket().inputStream().read();
        ended.complete(null);
      } catch (IOException e) {
        ended.complete(e);
      }
    };
  }

  @Test
  void removingAPeerResetsItsConnections() throws Exception {
    TunnelHost host = start();
    CountDownLatch accepted = new CountDownLatch(1);
    CompletableFuture<Throwable> ended = new CompletableFuture<>();
    host.serveTcp(PORT, holding(accepted, ended));
    try (TcpSocket s = alice.connect(PORT, LONG)) {
      accepted.await();

      assertThat(host.removePeer(alice.publicKey())).isTrue();

      assertThat(ended.get(10, TimeUnit.SECONDS)).isInstanceOf(IOException.class);
    }
  }

  @Test
  void anAddressChangingHandsResetsTheOldOwnersConnections() throws Exception {
    TunnelHost host = start();
    CountDownLatch accepted = new CountDownLatch(1);
    CompletableFuture<Throwable> ended = new CompletableFuture<>();
    host.serveTcp(PORT, holding(accepted, ended));
    try (TcpSocket s = alice.connect(PORT, LONG)) {
      accepted.await();

      host.device().peer(bob.publicKey()).addAllowedIp(IpPrefix.parse(alice.ip + "/32"));

      assertThat(ended.get(10, TimeUnit.SECONDS)).isInstanceOf(IOException.class);
    }
  }

  @Test
  void onePeerAtItsLimitDoesNotAffectAnother() throws Exception {
    TunnelHost host = start(TunnelHost.builder().maxConnectionsPerPeer(2));
    CountDownLatch accepted = new CountDownLatch(3);
    host.serveTcp(PORT, holding(accepted, new CompletableFuture<>()));

    try (TcpSocket first = alice.connect(PORT, LONG);
        TcpSocket second = alice.connect(PORT, LONG)) {
      assertThatThrownBy(() -> alice.connect(PORT, Duration.ofSeconds(2)))
          .isInstanceOf(SocketTimeoutException.class);
      assertThat(host.stack().refusedTcpConnections()).isPositive();

      try (TcpSocket other = bob.connect(PORT, LONG)) {
        assertThat(accepted.await(10, TimeUnit.SECONDS)).isTrue();
      }
    }
  }

  @Test
  void addPeerAtRuntimeKeepsAddressesExclusive() throws Exception {
    TunnelHost host = start();
    var key = PrivateKey.generate().publicKey();

    for (String prefix : List.of("10.60.0.0/24", alice.ip + "/32", TunnelClient.HOST_IP + "/32")) {
      assertThatThrownBy(() -> host.addPeer(PeerConfig.builder(key).allowedIp(prefix).build()))
          .as(prefix)
          .isInstanceOf(IllegalArgumentException.class);
    }
    assertThatThrownBy(() -> host.addPeer(PeerConfig.builder(key).build()))
        .isInstanceOf(IllegalArgumentException.class);

    host.addPeer(PeerConfig.builder(key).allowedIp("10.60.0.9/32").build());
    assertThat(host.device().peerFor(InetAddress.ofLiteral("10.60.0.9"))).isPresent();
  }

  private void assertRejected(String text, String message) {
    assertThatThrownBy(() -> TunnelHost.builder().start(WgQuickConfig.parse(text)))
        .isInstanceOf(ConfigException.class)
        .hasMessageContaining(message);
  }

  @Test
  void configurationsMustGiveEachPeerItsOwnAddresses() throws Exception {
    String iface = config(hostKey, 51999);
    String key = "[Peer]\nPublicKey = " + alice.publicKey().toBase64() + "\n";
    String other = "[Peer]\nPublicKey = " + bob.publicKey().toBase64() + "\n";

    assertRejected(iface + key + "AllowedIPs = 0.0.0.0/0\n", "not a single address");
    assertRejected(iface + key + "AllowedIPs = 10.60.0.0/24\n", "not a single address");
    assertRejected(iface + key + "AllowedIPs = 10.60.0.1/32\n", "own address");
    assertRejected(iface + key, "needs AllowedIPs");
    assertRejected(
        iface + key + "AllowedIPs = 10.60.0.2/32\n" + other + "AllowedIPs = 10.60.0.2/32\n",
        "two peers");
    assertRejected(iface.replace("ListenPort = 51999\n", ""), "ListenPort");
    assertRejected(iface.replace("Address = 10.60.0.1/24\n", ""), "Address");
  }
}
