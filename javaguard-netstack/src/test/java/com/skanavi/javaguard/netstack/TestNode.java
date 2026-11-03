// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.netstack;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

import com.skanavi.javaguard.core.Bind;
import com.skanavi.javaguard.core.Device;
import com.skanavi.javaguard.core.Peer;
import com.skanavi.javaguard.core.PeerConfig;
import com.skanavi.javaguard.core.Scheduler;
import com.skanavi.javaguard.core.UdpBind;
import com.skanavi.javaguard.crypto.PrivateKey;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.BooleanSupplier;
import java.util.function.Function;

/** One real device and netstack on loopback UDP, with the small servers tunnel tests need. */
final class TestNode implements AutoCloseable {
  static final InetAddress LOOPBACK = InetAddress.getLoopbackAddress();

  /** How long to watch for traffic that must not arrive. */
  static final Duration SHORT = Duration.ofSeconds(2);

  /** How long to wait for traffic that must arrive. */
  static final Duration LONG = Duration.ofSeconds(30);

  final String name;
  final PrivateKey key;
  final Netstack stack;
  final Device device;

  TestNode(String name, Netstack stack) throws IOException {
    this(name, PrivateKey.generate(), stack, loopbackBind(), null);
  }

  TestNode(String name, PrivateKey key, Netstack stack) throws IOException {
    this(name, key, stack, loopbackBind(), null);
  }

  TestNode(String name, PrivateKey key, Netstack stack, Bind bind, Scheduler scheduler) {
    this.name = name;
    this.key = key;
    this.stack = stack;
    Device.Builder builder = Device.builder().privateKey(key).bind(bind).tun(stack);
    if (scheduler != null) {
      builder.scheduler(scheduler);
    }
    this.device = builder.build();
  }

  static Bind loopbackBind() throws IOException {
    return UdpBind.open(new InetSocketAddress(LOOPBACK, 0));
  }

  /** Adds {@code other} as a peer at its loopback endpoint, routing {@code allowedIps} to it. */
  Peer connect(TestNode other, String... allowedIps) {
    return addPeer(other, new InetSocketAddress(LOOPBACK, other.device.listenPort()), allowedIps);
  }

  /** Adds {@code other} as a peer at {@code endpoint}, which may be null. */
  Peer addPeer(TestNode other, InetSocketAddress endpoint, String... allowedIps) {
    PeerConfig.Builder peer = PeerConfig.builder(other.device.publicKey()).endpoint(endpoint);
    for (String ip : allowedIps) {
      peer.allowedIp(ip);
    }
    return device.addPeer(peer.build());
  }

  Peer peer(TestNode other) {
    return device.peer(other.device.publicKey());
  }

  void start() {
    device.start();
  }

  boolean canPing(String host, Duration timeout) throws InterruptedException {
    return stack.ping(InetAddress.ofLiteral(host), timeout).isPresent();
  }

  /** Sends {@code data}, half-closes, and returns everything the server sends back. */
  byte[] exchange(String host, int port, byte[] data) throws IOException {
    try (TcpSocket s = stack.connectTcp(address(host, port), LONG)) {
      s.readTimeout(LONG);
      s.outputStream().write(data);
      s.shutdownOutput();
      return s.inputStream().readAllBytes();
    }
  }

  /** What a {@link #serveIdentity} server at {@code host} answers. */
  String whoIs(String host, int port) throws IOException {
    return new String(exchange(host, port, new byte[0]), UTF_8);
  }

  /** Sends {@code message} and returns the reply from a {@link #serveUdpEcho} server. */
  String udpExchange(String host, int port, String message) throws Exception {
    try (UdpSocket socket = stack.openUdp()) {
      socket.send(address(host, port), message.getBytes(UTF_8));
      UdpSocket.Datagram reply = socket.receive(LONG);
      assertThat(reply).as("reply from %s", host).isNotNull();
      return new String(reply.data(), UTF_8);
    }
  }

  /** Answers TCP connections on {@code port} with this node's name and the caller's address. */
  void serveIdentity(int port) throws IOException {
    serve(
        port,
        s -> {
          long read = s.inputStream().readAllBytes().length;
          String who = s.remoteAddress().getAddress().getHostAddress();
          return identity(who, read).getBytes(UTF_8);
        });
  }

  String identity(String callerIp, long bytes) {
    return name + " saw " + InetAddress.ofLiteral(callerIp).getHostAddress() + " " + bytes;
  }

  /** Answers TCP connections on {@code port} with the SHA-256 of what they sent. */
  void serveDigest(int port) throws IOException {
    serve(port, s -> sha256(s.inputStream().readAllBytes()));
  }

  /** Answers each TCP connection on {@code port} with {@code handler}'s reply. */
  void serve(int port, Handler handler) throws IOException {
    TcpListener listener = stack.listenTcp(port);
    Thread.ofVirtual()
        .start(
            () -> {
              try {
                while (true) {
                  TcpSocket socket = listener.accept();
                  Thread.ofVirtual().start(() -> answer(socket, handler));
                }
              } catch (IOException e) {
                // closed
              }
            });
  }

  private static void answer(TcpSocket socket, Handler handler) {
    try (socket) {
      socket.outputStream().write(handler.reply(socket));
      socket.shutdownOutput();
    } catch (Exception e) {
      // the client side reports the failure
    }
  }

  /** Replies to UDP on {@code port} with this node's name and the datagram. */
  void serveUdpEcho(int port) throws IOException {
    UdpSocket socket = stack.openUdp(port);
    Thread.ofVirtual()
        .start(
            () -> {
              try {
                while (true) {
                  UdpSocket.Datagram d = socket.receive(LONG);
                  if (d != null) {
                    String text = name + ":" + new String(d.data(), UTF_8);
                    socket.send(d.source(), text.getBytes(UTF_8));
                  }
                }
              } catch (Exception e) {
                // closed
              }
            });
  }

  @Override
  public void close() throws IOException {
    device.close();
  }

  // ---------------------------------------------------------------- shared helpers

  static InetSocketAddress address(String host, int port) {
    return new InetSocketAddress(InetAddress.ofLiteral(host), port);
  }

  static byte[] sha256(byte[] data) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(data);
    } catch (NoSuchAlgorithmException e) {
      throw new AssertionError(e);
    }
  }

  /** Runs one task per item concurrently and rethrows the first failure. */
  static <T> void runAll(List<T> items, Function<T, Callable<Void>> task) throws Exception {
    try (ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor()) {
      List<Future<Void>> futures = new ArrayList<>();
      for (T item : items) {
        futures.add(pool.submit(task.apply(item)));
      }
      for (Future<Void> f : futures) {
        f.get();
      }
    }
  }

  /** Polls until {@code condition} holds, failing after {@link #LONG}. */
  static void await(String what, BooleanSupplier condition) throws InterruptedException {
    long deadline = System.nanoTime() + LONG.toNanos();
    while (!condition.getAsBoolean()) {
      assertThat(System.nanoTime()).as("waiting for %s", what).isLessThan(deadline);
      Thread.sleep(10);
    }
  }

  /** Live platform threads not in {@code known}, leaving out the JDK's virtual thread carriers. */
  static Set<Thread> liveThreads(Set<Thread> known) {
    Set<Thread> live = new HashSet<>(Thread.getAllStackTraces().keySet());
    live.removeAll(known);
    live.removeIf(t -> !t.isAlive() || t.getName().startsWith("ForkJoinPool"));
    return live;
  }

  /** Fails unless every thread outside {@code baseline} ends within ten seconds. */
  static void awaitThreadsGone(Set<Thread> baseline) throws InterruptedException {
    long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
    while (System.nanoTime() < deadline && !liveThreads(baseline).isEmpty()) {
      Thread.sleep(50);
    }
    assertThat(liveThreads(baseline)).extracting(Thread::getName).isEmpty();
  }

  /** Produces a TCP reply from a connection. */
  @FunctionalInterface
  interface Handler {
    byte[] reply(TcpSocket socket) throws Exception;
  }
}
