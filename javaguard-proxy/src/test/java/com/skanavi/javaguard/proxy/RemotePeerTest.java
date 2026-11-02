// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.proxy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.skanavi.javaguard.core.Device;
import com.skanavi.javaguard.core.Peer;
import com.skanavi.javaguard.core.PeerConfig;
import com.skanavi.javaguard.core.UdpBind;
import com.skanavi.javaguard.crypto.PrivateKey;
import com.skanavi.javaguard.crypto.PublicKey;
import com.skanavi.javaguard.netstack.Netstack;
import com.skanavi.javaguard.netstack.TcpSocket;
import com.skanavi.javaguard.netstack.UdpSocket;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * Tests against a real WireGuard peer reached over the Internet, set up with {@code
 * scripts/remote-peer/setup-server.sh}: Linux kernel WireGuard on {@code jgtest0} (10.77.0.2,
 * fd77::2), with HTTP on :8080, a SHA-256 upload sink on :9001, UDP echo on :7000 and DNS ({@code
 * web.jgtest}, {@code alias.jgtest}). Run with {@code ./gradlew :javaguard-proxy:remoteTest
 * -PremoteEndpoint=... -PremotePublicKey=... -PremoteKeyFile=...}; add {@code
 * -PremoteSsh=root@host} for server-side checks and {@code -PremoteMinutes=N} for the soak.
 */
@Tag("remote")
class RemotePeerTest {
  private static final InetAddress SERVER4 = InetAddress.ofLiteral("10.77.0.2");
  private static final InetAddress SERVER6 = InetAddress.ofLiteral("fd77::2");
  private static final Duration CONNECT = Duration.ofSeconds(15);

  private static Netstack stack;
  private static Device device;
  private static Peer peer;
  private static Map<String, String> sums;

  @BeforeAll
  static void connect() throws Exception {
    String endpoint = System.getProperty("javaguard.remoteEndpoint");
    assumeTrue(endpoint != null, "set -PremoteEndpoint to run remote tests");
    PublicKey serverKey = PublicKey.fromBase64(System.getProperty("javaguard.remotePublicKey"));
    PrivateKey key =
        PrivateKey.fromBase64(
            Files.readString(Path.of(System.getProperty("javaguard.remoteKeyFile"))));
    int colon = endpoint.lastIndexOf(':');
    InetSocketAddress server =
        new InetSocketAddress(
            InetAddress.getByName(endpoint.substring(0, colon)),
            Integer.parseInt(endpoint.substring(colon + 1)));
    stack = Netstack.builder().address("10.77.0.1/24").address("fd77::1/64").dns(SERVER4).build();
    device = Device.builder().privateKey(key).bind(UdpBind.open(0)).tun(stack).build();
    peer =
        device.addPeer(
            PeerConfig.builder(serverKey)
                .endpoint(server)
                .allowedIp("10.77.0.0/24")
                .allowedIp("fd77::/64")
                .persistentKeepalive(Duration.ofSeconds(25))
                .build());
    device.start();
    assertThat(stack.ping(SERVER4, Duration.ofSeconds(15))).as("tunnel comes up").isPresent();
    sums = new HashMap<>();
    for (String line :
        new String(httpGet(SERVER4, "/SHA256SUMS"), StandardCharsets.US_ASCII).split("\n")) {
      String[] f = line.trim().split("\\s+");
      sums.put(f[1], f[0]);
    }
  }

  @AfterAll
  static void disconnect() throws IOException {
    if (device != null) {
      device.close();
    }
  }

  @Test
  void functional() throws Exception {
    // Latency and loss, both address families.
    for (InetAddress target : List.of(SERVER4, SERVER6)) {
      Stats rtt = new Stats();
      int lost = 0;
      for (int i = 0; i < 20; i++) {
        Optional<Duration> r = stack.ping(target, Duration.ofSeconds(3));
        if (r.isPresent()) {
          rtt.add(r.get().toNanos() / 1e6);
        } else {
          lost++;
        }
      }
      System.out.printf("ping %s: %s ms, %d/20 lost%n", target.getHostAddress(), rtt, lost);
      assertThat(lost).as("ping loss to %s", target).isLessThanOrEqualTo(2);
    }

    // DNS inside the tunnel, including a CNAME.
    List<InetAddress> expected = List.of(SERVER4, SERVER6);
    assertThat(stack.dns().resolve("web.jgtest")).containsExactlyElementsOf(expected);
    assertThat(stack.dns().resolve("alias.jgtest")).containsExactlyElementsOf(expected);

    // HTTP over the netstack's TCP, verified against the server's SHA256SUMS.
    assertThat(new String(httpGet(SERVER4, "/index.html"), StandardCharsets.UTF_8))
        .isEqualTo("hello from the network test peer\n");
    download(SERVER4, "1m.bin");
    download(SERVER4, "50m.bin");
    download(SERVER6, "5m.bin");

    // Four parallel downloads.
    long t0 = System.nanoTime();
    List<CompletableFuture<Void>> parallel = new ArrayList<>();
    for (int i = 0; i < 4; i++) {
      parallel.add(
          CompletableFuture.runAsync(
              () -> {
                try {
                  verify("5m.bin", httpGet(SERVER4, "/5m.bin"));
                } catch (Exception e) {
                  throw new RuntimeException(e);
                }
              }));
    }
    for (CompletableFuture<Void> f : parallel) {
      f.get(5, TimeUnit.MINUTES);
    }
    report("4 x parallel download", 4 * 5L << 20, t0);

    // Uploads, verified by the server's SHA-256.
    upload(SERVER4, 20 << 20, 1);
    upload(SERVER6, 5 << 20, 2);

    // UDP echo.
    for (InetAddress target : List.of(SERVER4, SERVER6)) {
      int replies = 0;
      try (UdpSocket s = stack.openUdp()) {
        for (int i = 0; i < 20; i++) {
          byte[] payload = ("datagram " + i).repeat(30).getBytes(StandardCharsets.US_ASCII);
          s.send(new InetSocketAddress(target, 7000), payload);
          UdpSocket.Datagram d = s.receive(Duration.ofSeconds(2));
          if (d != null && Arrays.equals(d.data(), payload)) {
            replies++;
          }
        }
      }
      System.out.printf("UDP echo %s: %d/20%n", target.getHostAddress(), replies);
      assertThat(replies).isGreaterThanOrEqualTo(18);
    }

    // The local proxy: HttpClient and the system curl, by name.
    try (LocalProxy proxy = LocalProxy.builder(stack).build()) {
      HttpClient client = proxy.httpClientBuilder().build();
      t0 = System.nanoTime();
      HttpResponse<byte[]> r =
          client.send(
              HttpRequest.newBuilder(URI.create("http://web.jgtest:8080/5m.bin")).build(),
              HttpResponse.BodyHandlers.ofByteArray());
      assertThat(r.statusCode()).isEqualTo(200);
      verify("5m.bin", r.body());
      report("HttpClient via proxy", r.body().length, t0);
      if (Files.isExecutable(Path.of("/usr/bin/curl"))) {
        String address = "127.0.0.1:" + proxy.address().getPort();
        assertThat(curl("--socks5-hostname", address, "http://alias.jgtest:8080/index.html"))
            .isEqualTo("hello from the network test peer\n");
        assertThat(curl("-x", "http://" + address, "http://web.jgtest:8080/index.html"))
            .isEqualTo("hello from the network test peer\n");
      }
    }

    // From the server's side: its view of us, and pings back through our NAT.
    String ssh = System.getProperty("javaguard.remoteSsh");
    if (ssh != null) {
      System.out.println(
          "server sees: " + remote(ssh, "wg show jgtest0 endpoints; wg show jgtest0 transfer"));
      assertThat(remoteExit(ssh, "ping -c 3 -W 3 10.77.0.1")).as("server pings us (IPv4)").isZero();
      assertThat(remoteExit(ssh, "ping -6 -c 3 -W 3 fd77::1"))
          .as("server pings us (IPv6)")
          .isZero();
    }
    System.out.printf(
        "peer stats: rx=%d tx=%d, last handshake %s%n",
        peer.rxBytes(), peer.txBytes(), peer.lastHandshake().orElse(null));
  }

  /**
   * Repeats a mixed workload once a minute for {@code -PremoteMinutes}, appending one CSV row per
   * cycle to {@code -PremoteLog}. Every hour the tunnel idles for four minutes (only keepalives)
   * and the server must still reach us afterwards. Corrupted data fails immediately; transient
   * network errors are counted and must stay under 5% of cycles.
   */
  @Test
  void soak() throws Exception {
    long minutes = Long.getLong("javaguard.remoteMinutes", 0);
    assumeTrue(minutes > 0, "set -PremoteMinutes to run the remote soak");
    String ssh = System.getProperty("javaguard.remoteSsh");
    Path log = Path.of(System.getProperty("javaguard.remoteLog", "remote-soak.csv"));
    boolean header = !Files.exists(log);
    try (PrintStream csv =
        new PrintStream(
            Files.newOutputStream(
                log,
                java.nio.file.StandardOpenOption.CREATE,
                java.nio.file.StandardOpenOption.APPEND),
            true)) {
      if (header) {
        csv.println(
            "time,cycle,down_mbps,up_mbps,rtt_avg_ms,rtt_max_ms,ping_lost,errors,handshake_age_s,rx_bytes,tx_bytes,note");
      }
      long end = System.nanoTime() + TimeUnit.MINUTES.toNanos(minutes);
      long nextIdle = System.nanoTime() + TimeUnit.MINUTES.toNanos(60);
      int cycle = 0;
      int errors = 0;
      int consecutive = 0;
      Random random = new Random();
      while (System.nanoTime() < end) {
        long cycleStart = System.nanoTime();
        cycle++;
        String note = "";
        double down = Double.NaN;
        double up = Double.NaN;
        Stats rtt = new Stats();
        int lost = 0;
        try {
          long t = System.nanoTime();
          verify("5m.bin", httpGet(SERVER4, "/5m.bin"));
          down = (5L << 20) * 8 / ((System.nanoTime() - t) / 1e9) / 1e6;
          t = System.nanoTime();
          upload(SERVER4, 5 << 20, random.nextLong(), false);
          up = (5L << 20) * 8 / ((System.nanoTime() - t) / 1e9) / 1e6;
          if (!stack.dns().resolve("web.jgtest").contains(SERVER4)) {
            throw new IOException("wrong DNS answer");
          }
          for (int i = 0; i < 5; i++) {
            Optional<Duration> r =
                stack.ping(i % 2 == 0 ? SERVER4 : SERVER6, Duration.ofSeconds(3));
            if (r.isPresent()) {
              rtt.add(r.get().toNanos() / 1e6);
            } else {
              lost++;
            }
          }
          consecutive = 0;
        } catch (CorruptionError e) {
          csv.printf(
              "%s,%d,,,,,,%d,,,,CORRUPTION %s%n", Instant.now(), cycle, errors, e.getMessage());
          throw e;
        } catch (Exception e) {
          errors++;
          consecutive++;
          note = e.toString().replace(',', ';');
        }
        if (System.nanoTime() >= nextIdle && ssh != null) {
          Thread.sleep(TimeUnit.MINUTES.toMillis(4)); // only keepalives cross the tunnel
          boolean reachable = remoteExit(ssh, "ping -c 3 -W 3 10.77.0.1") == 0;
          note =
              (note.isEmpty() ? "" : note + "; ")
                  + "after 4 min idle, server ping "
                  + (reachable ? "ok" : "FAILED");
          if (!reachable) {
            errors++;
          }
          nextIdle = System.nanoTime() + TimeUnit.MINUTES.toNanos(60);
        }
        long age =
            peer.lastHandshake()
                .map(h -> Duration.between(h, Instant.now()).toSeconds())
                .orElse(-1L);
        csv.printf(
            "%s,%d,%.1f,%.1f,%.1f,%.1f,%d,%d,%d,%d,%d,%s%n",
            Instant.now(),
            cycle,
            down,
            up,
            rtt.avg(),
            rtt.max(),
            lost,
            errors,
            age,
            peer.rxBytes(),
            peer.txBytes(),
            note);
        assertThat(consecutive).as("consecutive failed cycles (%s)", note).isLessThan(10);
        long sleep = TimeUnit.SECONDS.toNanos(60) - (System.nanoTime() - cycleStart);
        if (sleep > 0) {
          TimeUnit.NANOSECONDS.sleep(sleep);
        }
      }
      System.out.printf("remote soak: %d cycles, %d errors%n", cycle, errors);
      assertThat((double) errors / cycle).as("error ratio").isLessThan(0.05);
    }
  }

  // ---------------------------------------------------------------- helpers

  /** Data that arrived but is wrong: never tolerated, unlike a network error. */
  static final class CorruptionError extends AssertionError {
    private static final long serialVersionUID = 1L;

    CorruptionError(String message) {
      super(message);
    }
  }

  private static void download(InetAddress server, String name) throws Exception {
    long t0 = System.nanoTime();
    byte[] body = httpGet(server, "/" + name);
    verify(name, body);
    report("download " + name + " via " + server.getHostAddress(), body.length, t0);
  }

  private static void verify(String name, byte[] body) throws Exception {
    String sha = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(body));
    if (!sha.equals(sums.get(name))) {
      throw new CorruptionError(name + ": got " + body.length + " bytes with SHA-256 " + sha);
    }
  }

  private static void upload(InetAddress server, int size, long seed) throws Exception {
    upload(server, size, seed, true);
  }

  private static void upload(InetAddress server, int size, long seed, boolean print)
      throws Exception {
    byte[] data = new byte[size];
    new Random(seed).nextBytes(data);
    long t0 = System.nanoTime();
    String reply;
    try (TcpSocket s = stack.connectTcp(new InetSocketAddress(server, 9001), CONNECT)) {
      s.readTimeout(Duration.ofSeconds(60));
      OutputStream out = s.outputStream();
      for (int off = 0; off < data.length; off += 1 << 16) {
        out.write(data, off, Math.min(1 << 16, data.length - off));
      }
      s.shutdownOutput();
      reply = new String(s.inputStream().readAllBytes(), StandardCharsets.US_ASCII).trim();
    }
    String sha = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));
    if (!reply.startsWith(sha)) {
      throw new CorruptionError("upload of " + size + " bytes: server computed " + reply);
    }
    if (print) {
      report("upload " + (size >> 20) + " MiB via " + server.getHostAddress(), size, t0);
    }
  }

  private static byte[] httpGet(InetAddress server, String path) throws IOException {
    try (TcpSocket s = stack.connectTcp(new InetSocketAddress(server, 8080), CONNECT)) {
      s.readTimeout(Duration.ofSeconds(60));
      String host =
          server.getAddress().length == 16
              ? "[" + server.getHostAddress() + "]"
              : server.getHostAddress();
      s.outputStream()
          .write(
              ("GET " + path + " HTTP/1.0\r\nHost: " + host + "\r\n\r\n")
                  .getBytes(StandardCharsets.US_ASCII));
      byte[] response = s.inputStream().readAllBytes();
      for (int i = 0; i + 3 < response.length; i++) {
        if (response[i] == '\r'
            && response[i + 1] == '\n'
            && response[i + 2] == '\r'
            && response[i + 3] == '\n') {
          String head = new String(response, 0, i, StandardCharsets.US_ASCII);
          if (!head.contains(" 200 ")) {
            throw new IOException("HTTP " + head.lines().findFirst().orElse(""));
          }
          return Arrays.copyOfRange(response, i + 4, response.length);
        }
      }
      throw new IOException("malformed HTTP response of " + response.length + " bytes");
    }
  }

  private static void report(String what, long bytes, long startNanos) {
    double s = (System.nanoTime() - startNanos) / 1e9;
    System.out.printf(
        "%s: %.1f MiB in %.2f s = %.1f Mbit/s%n", what, bytes / 1048576.0, s, bytes * 8 / s / 1e6);
  }

  private static String curl(String... args) throws Exception {
    List<String> command = new ArrayList<>(List.of("/usr/bin/curl", "-sS", "--max-time", "30"));
    command.addAll(List.of(args));
    Process p = new ProcessBuilder(command).redirectErrorStream(true).start();
    String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    assertThat(p.waitFor(40, TimeUnit.SECONDS)).isTrue();
    assertThat(p.exitValue()).as("curl %s: %s", String.join(" ", args), out).isZero();
    return out;
  }

  private static String remote(String ssh, String command) throws Exception {
    Process p =
        new ProcessBuilder("ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", ssh, command)
            .redirectErrorStream(true)
            .start();
    String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
    p.waitFor(60, TimeUnit.SECONDS);
    return out;
  }

  private static int remoteExit(String ssh, String command) throws Exception {
    Process p =
        new ProcessBuilder("ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", ssh, command)
            .redirectErrorStream(true)
            .start();
    p.getInputStream().readAllBytes();
    return p.waitFor(60, TimeUnit.SECONDS) ? p.exitValue() : -1;
  }

  /** Running min/avg/max. */
  private static final class Stats {
    private double min = Double.MAX_VALUE;
    private double max;
    private double sum;
    private int n;

    void add(double v) {
      min = Math.min(min, v);
      max = Math.max(max, v);
      sum += v;
      n++;
    }

    double avg() {
      return n == 0 ? Double.NaN : sum / n;
    }

    double max() {
      return n == 0 ? Double.NaN : max;
    }

    @Override
    public String toString() {
      return n == 0 ? "none" : String.format("min %.1f / avg %.1f / max %.1f", min, avg(), max);
    }
  }
}
