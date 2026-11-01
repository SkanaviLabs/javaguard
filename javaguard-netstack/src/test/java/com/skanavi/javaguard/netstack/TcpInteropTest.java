// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.netstack;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.skanavi.javaguard.core.Device;
import com.skanavi.javaguard.core.PeerConfig;
import com.skanavi.javaguard.core.UdpBind;
import com.skanavi.javaguard.core.interop.Docker;
import com.skanavi.javaguard.core.interop.WireGuardContainer;
import com.skanavi.javaguard.core.interop.WireGuardContainer.Implementation;
import com.skanavi.javaguard.crypto.PrivateKey;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * TCP over a real WireGuard tunnel against Linux's TCP stack: javaguard fetches from busybox httpd,
 * uploads to socat, and serves HTTP that the container fetches with wget. Each runs with and
 * without 1% injected packet loss, and every transfer is checked with SHA-256 on both ends.
 */
@Tag("interop")
class TcpInteropTest {
  private static final int BIG = 16 << 20;
  private static final InetAddress CONTAINER = InetAddress.ofLiteral("10.9.0.2");

  @BeforeAll
  static void requireDocker() throws IOException {
    assumeTrue(Docker.available(), "Docker is not available");
    Docker.buildImage();
  }

  static Stream<Arguments> cases() {
    return Stream.of(Implementation.values())
        .flatMap(i -> Stream.of(Arguments.of(i, 0.0), Arguments.of(i, 0.01)));
  }

  @ParameterizedTest(name = "{0}, loss {1}")
  @MethodSource("cases")
  void httpAndBulkTransfersAgainstLinuxTcp(Implementation impl, double loss) throws Exception {
    PrivateKey key = PrivateKey.generate();
    Netstack stack = Netstack.builder().address("10.9.0.1/24").build();
    try (WireGuardContainer peer = new WireGuardContainer(impl, key.publicKey(), null);
        Device device =
            Device.builder()
                .privateKey(key)
                .bind(UdpBind.open(0))
                .tun(new ImpairedTun(stack, loss))
                .build()) {
      peer.exec(
          "mkdir -p /www && echo 'hello from linux' > /www/index.html"
              + " && head -c "
              + BIG
              + " /dev/urandom > /www/big.bin"
              + " && (busybox-extras httpd -f -p 10.9.0.2:8080 -h /www >/dev/null 2>&1 &)"
              + " && (socat -u TCP-LISTEN:9001,bind=10.9.0.2,reuseaddr"
              + " OPEN:/tmp/upload,creat,trunc >/dev/null 2>&1 &)");
      String bigSha = peer.exec("sha256sum /www/big.bin | cut -d' ' -f1");
      device.addPeer(
          PeerConfig.builder(peer.publicKey())
              .endpoint(peer.endpoint())
              .allowedIp("10.9.0.2/32")
              .build());
      device.start();
      assertThat(stack.ping(CONTAINER, Duration.ofSeconds(10))).isPresent();

      // javaguard as HTTP client.
      assertThat(new String(httpGet(stack, "/index.html"), StandardCharsets.UTF_8))
          .isEqualTo("hello from linux\n");
      long t0 = System.nanoTime();
      byte[] big = httpGet(stack, "/big.bin");
      report(impl, loss, "download", big.length, t0);
      assertThat(big).hasSize(BIG);
      assertThat(sha256(big)).isEqualTo(bigSha);

      // javaguard uploading to a Linux receiver.
      byte[] upload = TcpTest.random(BIG, 99);
      t0 = System.nanoTime();
      try (TcpSocket s =
          stack.connectTcp(new InetSocketAddress(CONTAINER, 9001), Duration.ofSeconds(10))) {
        OutputStream out = s.outputStream();
        for (int off = 0; off < upload.length; off += 1 << 16) {
          out.write(upload, off, Math.min(1 << 16, upload.length - off));
        }
        s.shutdownOutput();
        assertThat(s.inputStream().read()).isEqualTo(-1); // socat closes after our FIN
      }
      report(impl, loss, "upload", upload.length, t0);
      assertThat(peer.exec("sha256sum /tmp/upload | cut -d' ' -f1")).isEqualTo(sha256(upload));

      // javaguard as HTTP server, fetched by the container's wget.
      byte[] page = TcpTest.random(4 << 20, 5);
      try (TcpListener listener = stack.listenTcp(8080)) {
        Thread server = Thread.ofVirtual().start(() -> serve(listener, page));
        Docker.Result wget =
            peer.tryExec(
                "wget -q -O /tmp/page http://10.9.0.1:8080/ && sha256sum /tmp/page | cut -d' ' -f1");
        assertThat(wget.exitCode()).as(wget.output()).isZero();
        assertThat(wget.output().strip()).isEqualTo(sha256(page));
        server.join(5000);
      }
    }
  }

  private static byte[] httpGet(Netstack stack, String path) throws IOException {
    try (TcpSocket s =
        stack.connectTcp(new InetSocketAddress(CONTAINER, 8080), Duration.ofSeconds(10))) {
      s.outputStream()
          .write(
              ("GET " + path + " HTTP/1.0\r\nHost: 10.9.0.2\r\n\r\n")
                  .getBytes(StandardCharsets.US_ASCII));
      byte[] response = s.inputStream().readAllBytes();
      int split = indexOf(response, "\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
      String head = new String(response, 0, split, StandardCharsets.US_ASCII);
      assertThat(head).startsWith("HTTP/1.").contains(" 200 ");
      return Arrays.copyOfRange(response, split + 4, response.length);
    }
  }

  private static void serve(TcpListener listener, byte[] body) {
    try (TcpSocket s = listener.accept()) {
      ByteArrayOutputStream request = new ByteArrayOutputStream();
      byte[] buf = new byte[1024];
      while (indexOf(request.toByteArray(), "\r\n\r\n".getBytes(StandardCharsets.US_ASCII)) < 0) {
        int n = s.inputStream().read(buf);
        if (n < 0) {
          return;
        }
        request.write(buf, 0, n);
      }
      s.outputStream()
          .write(
              ("HTTP/1.0 200 OK\r\nContent-Length: "
                      + body.length
                      + "\r\nConnection: close\r\n\r\n")
                  .getBytes(StandardCharsets.US_ASCII));
      s.outputStream().write(body);
      s.shutdownOutput();
      s.inputStream().readAllBytes(); // until the client closes
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  private static int indexOf(byte[] haystack, byte[] needle) {
    outer:
    for (int i = 0; i + needle.length <= haystack.length; i++) {
      for (int j = 0; j < needle.length; j++) {
        if (haystack[i + j] != needle[j]) {
          continue outer;
        }
      }
      return i;
    }
    return -1;
  }

  private static String sha256(byte[] b) throws Exception {
    return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));
  }

  private static void report(Implementation impl, double loss, String what, int bytes, long start) {
    double s = (System.nanoTime() - start) / 1e9;
    System.out.printf(
        "%s loss=%.0f%% %s %d MiB in %.2f s = %.1f Mbit/s%n",
        impl, loss * 100, what, bytes >> 20, s, bytes * 8 / s / 1e6);
  }
}
