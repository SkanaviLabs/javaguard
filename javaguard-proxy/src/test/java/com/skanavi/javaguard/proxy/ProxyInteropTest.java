// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.proxy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.skanavi.javaguard.core.Device;
import com.skanavi.javaguard.core.PeerConfig;
import com.skanavi.javaguard.core.UdpBind;
import com.skanavi.javaguard.core.interop.Docker;
import com.skanavi.javaguard.core.interop.WireGuardContainer;
import com.skanavi.javaguard.core.interop.WireGuardContainer.Implementation;
import com.skanavi.javaguard.crypto.PrivateKey;
import com.skanavi.javaguard.netstack.Netstack;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * The phase exit test: ordinary clients on the host (java.net.http.HttpClient and the system curl)
 * reach HTTP and HTTPS servers behind a Linux WireGuard peer through {@link LocalProxy}, with names
 * resolved by DNS inside the tunnel, and without root.
 */
@Tag("interop")
class ProxyInteropTest {
  @TempDir Path dir;

  @BeforeAll
  static void requireDocker() throws IOException {
    assumeTrue(Docker.available(), "Docker is not available");
    Docker.buildImage();
  }

  @ParameterizedTest
  @EnumSource(Implementation.class)
  void hostClientsReachServersBehindThePeer(Implementation impl) throws Exception {
    PrivateKey key = PrivateKey.generate();
    Netstack stack = Netstack.builder().address("10.9.0.1/24").dns("10.9.0.2").build();
    try (WireGuardContainer peer = new WireGuardContainer(impl, key.publicKey(), null);
        Device device = Device.builder().privateKey(key).bind(UdpBind.open(0)).tun(stack).build();
        LocalProxy proxy = LocalProxy.builder(stack).build()) {
      peer.exec(
          "mkdir -p /www && echo 'plain hello' > /www/index.html"
              + " && echo 'secure hello' > /www/secure.txt"
              + " && (busybox-extras httpd -f -p 10.9.0.2:8080 -h /www >/dev/null 2>&1 &)"
              + " && openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=web.test"
              + " -addext subjectAltName=DNS:web.test -keyout /k.pem -out /c.pem 2>/dev/null"
              + " && cat /c.pem /k.pem > /tls.pem"
              // TLS in front of the same httpd, which reads each request before answering.
              + " && (socat OPENSSL-LISTEN:8443,bind=10.9.0.2,cert=/tls.pem,verify=0,fork,reuseaddr"
              + " TCP:10.9.0.2:8080 >/dev/null 2>&1 &)"
              + " && (dnsmasq --no-resolv --no-hosts --user=root --listen-address=10.9.0.2"
              + " --bind-interfaces --host-record=web.test,10.9.0.2)");
      String certificate = peer.exec("cat /c.pem");
      device.addPeer(
          PeerConfig.builder(peer.publicKey())
              .endpoint(peer.endpoint())
              .allowedIp("10.9.0.0/24")
              .build());
      device.start();
      assertThat(stack.ping(InetAddress.ofLiteral("10.9.0.2"), Duration.ofSeconds(10))).isPresent();

      // java.net.http.HttpClient: plain HTTP via the proxy, HTTPS via CONNECT.
      HttpClient http =
          proxy
              .httpClientBuilder()
              .sslContext(trusting(certificate))
              .connectTimeout(Duration.ofSeconds(10))
              .build();
      HttpResponse<String> plain =
          http.send(
              HttpRequest.newBuilder(URI.create("http://web.test:8080/index.html")).build(),
              HttpResponse.BodyHandlers.ofString());
      assertThat(plain.statusCode()).isEqualTo(200);
      assertThat(plain.body()).isEqualTo("plain hello\n");
      HttpResponse<String> secure =
          http.send(
              HttpRequest.newBuilder(URI.create("https://web.test:8443/secure.txt")).build(),
              HttpResponse.BodyHandlers.ofString());
      assertThat(secure.statusCode()).isEqualTo(200);
      assertThat(secure.body()).isEqualTo("secure hello\n");

      // The system curl, as a stand-in for any third-party client or browser.
      assumeTrue(Files.isExecutable(Path.of("/usr/bin/curl")), "curl not installed");
      Path ca = Files.writeString(dir.resolve("ca.pem"), certificate);
      String address = "127.0.0.1:" + proxy.address().getPort();
      assertThat(curl("--socks5-hostname", address, "http://web.test:8080/index.html"))
          .isEqualTo("plain hello\n");
      assertThat(curl("-x", "http://" + address, "http://web.test:8080/index.html"))
          .isEqualTo("plain hello\n");
      assertThat(
              curl(
                  "-x",
                  "http://" + address,
                  "--cacert",
                  ca.toString(),
                  "https://web.test:8443/secure.txt"))
          .isEqualTo("secure hello\n");
      assertThat(
              curl(
                  "--socks5-hostname",
                  address,
                  "--cacert",
                  ca.toString(),
                  "https://web.test:8443/secure.txt"))
          .isEqualTo("secure hello\n");
    }
  }

  private static SSLContext trusting(String pem) throws Exception {
    KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
    ks.load(null, null);
    ks.setCertificateEntry(
        "peer",
        CertificateFactory.getInstance("X.509")
            .generateCertificate(
                new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII))));
    TrustManagerFactory tmf =
        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    tmf.init(ks);
    SSLContext ctx = SSLContext.getInstance("TLS");
    ctx.init(null, tmf.getTrustManagers(), null);
    return ctx;
  }

  private static String curl(String... args) throws Exception {
    List<String> command =
        new java.util.ArrayList<>(List.of("/usr/bin/curl", "-sS", "--max-time", "20"));
    command.addAll(List.of(args));
    Process p = new ProcessBuilder(command).redirectErrorStream(true).start();
    String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    assertThat(p.waitFor(30, TimeUnit.SECONDS)).isTrue();
    assertThat(p.exitValue()).as("curl %s: %s", String.join(" ", args), out).isZero();
    return out;
  }
}
