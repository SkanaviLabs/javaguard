// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.netstack;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

@Timeout(value = 120, unit = TimeUnit.SECONDS)
class TcpTest {
  private static final Duration CONNECT = Duration.ofSeconds(5);
  private Netstack client;
  private Netstack server;

  private void start(double loss, double reorder, double duplicate) {
    client = stack("10.0.0.1/24", "fd00::1/64");
    server = stack("10.0.0.2/24", "fd00::2/64");
    new LossyWire(loss, reorder, duplicate).connect(client, server, 42);
  }

  private static Netstack stack(String v4, String v6) {
    return Netstack.builder()
        .address(v4)
        .address(v6)
        .tcpMinRto(Duration.ofMillis(50))
        .tcpTimeWait(Duration.ofMillis(200))
        .build();
  }

  @AfterEach
  void tearDown() {
    if (client != null) {
      client.close();
      server.close();
    }
  }

  private static InetSocketAddress at(String ip, int port) {
    return new InetSocketAddress(InetAddress.ofLiteral(ip), port);
  }

  @Test
  void echo() throws Exception {
    start(0, 0, 0);
    try (TcpListener l = server.listenTcp(7)) {
      CompletableFuture<Void> srv = CompletableFuture.runAsync(() -> echoOnce(l));
      try (TcpSocket s = client.connectTcp(at("10.0.0.2", 7), CONNECT)) {
        s.outputStream().write("hello tcp".getBytes());
        s.shutdownOutput();
        assertThat(new String(s.inputStream().readAllBytes())).isEqualTo("hello tcp");
        assertThat(s.remoteAddress()).isEqualTo(at("10.0.0.2", 7));
      }
      srv.get(10, TimeUnit.SECONDS);
    }
  }

  @ParameterizedTest(name = "loss={0} reorder={1} duplicate={2}")
  @CsvSource({"0, 0, 0", "0.01, 0, 0", "0.05, 0, 0", "0, 0.1, 0", "0, 0, 0.05", "0.02, 0.05, 0.02"})
  void bulkTransferBothWaysSurvivesImpairments(double loss, double reorder, double duplicate)
      throws Exception {
    start(loss, reorder, duplicate);
    int size = loss == 0 && reorder == 0 && duplicate == 0 ? 16 << 20 : 4 << 20;
    byte[] upload = random(size, 1);
    byte[] download = random(size, 2);
    try (TcpListener l = server.listenTcp(9000)) {
      CompletableFuture<byte[]> srv =
          CompletableFuture.supplyAsync(
              () -> {
                try (TcpSocket s = l.accept()) {
                  CompletableFuture<Void> sender =
                      CompletableFuture.runAsync(() -> sendAll(s, download));
                  byte[] got = s.inputStream().readAllBytes();
                  sender.get();
                  return got;
                } catch (Exception e) {
                  throw new RuntimeException(e);
                }
              });
      long start = System.nanoTime();
      try (TcpSocket s = client.connectTcp(at("10.0.0.2", 9000), CONNECT)) {
        CompletableFuture<Void> sender = CompletableFuture.runAsync(() -> sendAll(s, upload));
        byte[] got = s.inputStream().readAllBytes();
        sender.get();
        assertThat(sha256(got)).isEqualTo(sha256(download));
      }
      assertThat(sha256(srv.get(60, TimeUnit.SECONDS))).isEqualTo(sha256(upload));
      double seconds = (System.nanoTime() - start) / 1e9;
      System.out.printf(
          "loss=%s reorder=%s dup=%s: 2 x %d MiB in %.2f s (%.1f Mbit/s each way)%n",
          loss, reorder, duplicate, size >> 20, seconds, size * 8 / seconds / 1e6);
    }
  }

  @Test
  void ipv6() throws Exception {
    start(0, 0, 0);
    try (TcpListener l = server.listenTcp(7)) {
      CompletableFuture.runAsync(() -> echoOnce(l));
      try (TcpSocket s = client.connectTcp(at("fd00::2", 7), CONNECT)) {
        assertThat(s.localAddress().getAddress()).isEqualTo(InetAddress.ofLiteral("fd00::1"));
        s.outputStream().write(random(100_000, 3));
        s.shutdownOutput();
        assertThat(s.inputStream().readAllBytes()).isEqualTo(random(100_000, 3));
      }
    }
  }

  @Test
  void closedPortRefuses() {
    start(0, 0, 0);
    assertThatThrownBy(() -> client.connectTcp(at("10.0.0.2", 1), CONNECT))
        .isInstanceOf(ConnectException.class);
  }

  @Test
  void unreachableHostTimesOut() {
    start(0, 0, 0);
    assertThatThrownBy(() -> client.connectTcp(at("10.0.0.99", 80), Duration.ofMillis(300)))
        .isInstanceOf(SocketTimeoutException.class);
  }

  @Test
  void halfCloseLetsTheOtherSideKeepSending() throws Exception {
    start(0, 0, 0);
    try (TcpListener l = server.listenTcp(8)) {
      CompletableFuture<Void> srv =
          CompletableFuture.runAsync(
              () -> {
                try (TcpSocket s = l.accept()) {
                  byte[] request = s.inputStream().readAllBytes(); // until client's FIN
                  s.outputStream().write(("got " + request.length).getBytes());
                } catch (IOException e) {
                  throw new RuntimeException(e);
                }
              });
      try (TcpSocket s = client.connectTcp(at("10.0.0.2", 8), CONNECT)) {
        s.outputStream().write(new byte[1234]);
        s.shutdownOutput();
        assertThatThrownBy(() -> s.outputStream().write(1)).isInstanceOf(SocketException.class);
        assertThat(new String(s.inputStream().readAllBytes())).isEqualTo("got 1234");
      }
      srv.get(10, TimeUnit.SECONDS);
    }
  }

  @Test
  void gracefulCloseCleansUpBothSides() throws Exception {
    start(0, 0, 0);
    try (TcpListener l = server.listenTcp(7)) {
      CompletableFuture<Void> srv = CompletableFuture.runAsync(() -> echoOnce(l));
      try (TcpSocket s = client.connectTcp(at("10.0.0.2", 7), CONNECT)) {
        s.outputStream().write(1);
        s.shutdownOutput();
        assertThat(s.inputStream().readAllBytes()).containsExactly(1);
      }
      srv.get(10, TimeUnit.SECONDS);
    }
    waitUntil(() -> client.tcpConnectionCount() == 0 && server.tcpConnectionCount() == 0);
  }

  @Test
  void closingWithUnreadDataResetsThePeer() throws Exception {
    start(0, 0, 0);
    try (TcpListener l = server.listenTcp(7)) {
      TcpSocket c = client.connectTcp(at("10.0.0.2", 7), CONNECT);
      TcpSocket s = l.accept(Duration.ofSeconds(5));
      s.outputStream().write("unread".getBytes());
      waitUntil(() -> c.inputStream().available() > 0);
      c.close(); // unread data: RST
      assertThatThrownBy(() -> s.inputStream().readAllBytes())
          .isInstanceOf(SocketException.class)
          .hasMessageContaining("reset");
    }
  }

  @Test
  void abortResetsThePeer() throws Exception {
    start(0, 0, 0);
    try (TcpListener l = server.listenTcp(7)) {
      TcpSocket c = client.connectTcp(at("10.0.0.2", 7), CONNECT);
      TcpSocket s = l.accept(Duration.ofSeconds(5));
      c.abort();
      assertThatThrownBy(() -> s.inputStream().read()).hasMessageContaining("reset");
      assertThat(c.isOpen()).isFalse();
    }
  }

  @Test
  void slowReaderTriggersZeroWindowAndRecovers() throws Exception {
    start(0, 0, 0);
    byte[] data = random(2 << 20, 4);
    try (TcpListener l = server.listenTcp(7)) {
      CompletableFuture<byte[]> srv =
          CompletableFuture.supplyAsync(
              () -> {
                try (TcpSocket s = l.accept()) {
                  Thread.sleep(1500); // let the 256 KiB window fill up
                  return s.inputStream().readAllBytes();
                } catch (Exception e) {
                  throw new RuntimeException(e);
                }
              });
      try (TcpSocket s = client.connectTcp(at("10.0.0.2", 7), CONNECT)) {
        s.outputStream().write(data);
        s.shutdownOutput();
        assertThat(sha256(srv.get(60, TimeUnit.SECONDS))).isEqualTo(sha256(data));
      }
    }
  }

  @Test
  void manyConcurrentConnections() throws Exception {
    start(0.01, 0, 0);
    try (TcpListener l = server.listenTcp(7)) {
      Thread.ofVirtual()
          .start(
              () -> {
                try {
                  while (true) {
                    TcpSocket s = l.accept();
                    Thread.ofVirtual().start(() -> echo(s));
                  }
                } catch (IOException e) {
                  // listener closed
                }
              });
      List<CompletableFuture<Boolean>> clients = new ArrayList<>();
      for (int i = 0; i < 50; i++) {
        int n = i;
        clients.add(
            CompletableFuture.supplyAsync(
                () -> {
                  try (TcpSocket s = client.connectTcp(at("10.0.0.2", 7), Duration.ofSeconds(20))) {
                    byte[] data = random(20_000 + n, n);
                    s.outputStream().write(data);
                    s.shutdownOutput();
                    return java.util.Arrays.equals(s.inputStream().readAllBytes(), data);
                  } catch (IOException e) {
                    throw new RuntimeException(e);
                  }
                }));
      }
      for (CompletableFuture<Boolean> c : clients) {
        assertThat(c.get(60, TimeUnit.SECONDS)).isTrue();
      }
    }
  }

  @Test
  void closingTheListenerFailsAccept() throws Exception {
    start(0, 0, 0);
    TcpListener l = server.listenTcp(7);
    CompletableFuture<?> waiting =
        CompletableFuture.runAsync(
            () -> {
              try {
                l.accept();
              } catch (IOException e) {
                throw new RuntimeException(e);
              }
            });
    Thread.sleep(100);
    l.close();
    assertThatThrownBy(() -> waiting.get(5, TimeUnit.SECONDS))
        .hasRootCauseInstanceOf(SocketException.class);
    server.listenTcp(7).close(); // port is free again
  }

  @Test
  void readTimeout() throws Exception {
    start(0, 0, 0);
    try (TcpListener l = server.listenTcp(7);
        TcpSocket s = client.connectTcp(at("10.0.0.2", 7), CONNECT)) {
      s.readTimeout(Duration.ofMillis(100));
      assertThatThrownBy(() -> s.inputStream().read()).isInstanceOf(SocketTimeoutException.class);
      l.accept(Duration.ofSeconds(1)).close();
    }
  }

  // ---------------------------------------------------------------- helpers

  private static void echoOnce(TcpListener l) {
    try {
      echo(l.accept());
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  private static void echo(TcpSocket s) {
    try (s) {
      s.inputStream().transferTo(s.outputStream());
      s.shutdownOutput();
    } catch (IOException e) {
      // peer went away
    }
  }

  private static void sendAll(TcpSocket s, byte[] data) {
    try {
      OutputStream out = s.outputStream();
      for (int off = 0; off < data.length; off += 64 * 1024) {
        out.write(data, off, Math.min(64 * 1024, data.length - off));
      }
      s.shutdownOutput();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  static byte[] random(int size, long seed) {
    byte[] b = new byte[size];
    new Random(seed).nextBytes(b);
    return b;
  }

  static byte[] sha256(byte[] b) throws Exception {
    return MessageDigest.getInstance("SHA-256").digest(b);
  }

  interface Condition {
    boolean test() throws Exception;
  }

  private static void waitUntil(Condition c) throws Exception {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
    while (!c.test()) {
      if (System.nanoTime() > deadline) {
        throw new AssertionError("condition not met in time");
      }
      Thread.sleep(20);
    }
  }

  @SuppressWarnings("unused")
  private static byte[] readAll(InputStream in) throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    in.transferTo(out);
    return out.toByteArray();
  }
}
