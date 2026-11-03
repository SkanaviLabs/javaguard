// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.proxy;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

import com.skanavi.javaguard.core.Device;
import com.skanavi.javaguard.core.PeerConfig;
import com.skanavi.javaguard.core.UdpBind;
import com.skanavi.javaguard.crypto.PrivateKey;
import com.skanavi.javaguard.netstack.Netstack;
import com.skanavi.javaguard.netstack.TcpListener;
import com.skanavi.javaguard.netstack.TcpSocket;
import com.skanavi.javaguard.netstack.UdpSocket;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * Several {@link LocalProxy} instances in one JVM, each on its own real tunnel. Every tenant uses
 * the same inner addresses and answers the same host name, so only the proxy decides who is
 * reached.
 */
@Timeout(60)
class MultiTunnelProxyTest {
  private static final InetAddress LOOPBACK = InetAddress.getLoopbackAddress();
  private static final String HOST = "web.test";

  private final List<AutoCloseable> resources = new ArrayList<>();

  @AfterEach
  void closeEverything() throws Exception {
    for (AutoCloseable c : resources.reversed()) {
      c.close();
    }
  }

  @Test
  void httpClientsReachTheTenantBehindTheirOwnProxy() throws Exception {
    List<Tenant> tenants = new ArrayList<>();
    for (int i = 0; i < 4; i++) {
      tenants.add(tenant("tenant-" + i, LocalProxy.Builder::build));
    }
    try (ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor()) {
      List<Future<Void>> futures = new ArrayList<>();
      for (Tenant t : tenants) {
        futures.add(
            pool.submit(
                () -> {
                  HttpClient client = t.proxy.httpClientBuilder().build();
                  for (int n = 0; n < 5; n++) {
                    assertThat(get(client)).isEqualTo(t.name);
                  }
                  return null;
                }));
      }
      for (Future<Void> f : futures) {
        f.get();
      }
    }
  }

  @Test
  void socketFactoriesReachTheTenantBehindTheirOwnProxy() throws Exception {
    Tenant a = tenant("a", LocalProxy.Builder::build);
    Tenant b = tenant("b", LocalProxy.Builder::build);
    for (Tenant t : List.of(a, b)) {
      try (Socket s = t.proxy.socketFactory().createSocket(HOST, 80)) {
        s.getOutputStream().write("GET / HTTP/1.1\r\nHost: web.test\r\n\r\n".getBytes(US_ASCII));
        String response = new String(s.getInputStream().readAllBytes(), UTF_8);
        assertThat(response).endsWith("\r\n\r\n" + t.name);
      }
    }
  }

  @Test
  void eachProxyAcceptsOnlyItsOwnCredentials() throws Exception {
    Tenant a = tenant("a", p -> p.credentials("alice", "secret-a").build());
    Tenant b = tenant("b", p -> p.credentials("bob", "secret-b").build());

    assertThat(connectStatus(a.proxy, "alice:secret-a")).contains(" 200 ");
    assertThat(connectStatus(b.proxy, "bob:secret-b")).contains(" 200 ");
    assertThat(connectStatus(a.proxy, "bob:secret-b")).contains(" 407 ");
    assertThat(connectStatus(b.proxy, "alice:secret-a")).contains(" 407 ");
  }

  @Test
  void closingOneProxyLeavesTheOthersWorking() throws Exception {
    Tenant closing = tenant("closing", LocalProxy.Builder::build);
    Tenant staying = tenant("staying", LocalProxy.Builder::build);
    assertThat(get(closing.proxy.httpClientBuilder().build())).isEqualTo("closing");

    closing.proxy.close();

    assertThat(get(staying.proxy.httpClientBuilder().build())).isEqualTo("staying");
  }

  private static String get(HttpClient client) throws Exception {
    HttpRequest request = HttpRequest.newBuilder(URI.create("http://" + HOST + "/")).build();
    HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
    assertThat(response.statusCode()).isEqualTo(200);
    return response.body();
  }

  /** The status line of an HTTP CONNECT sent with {@code credentials}. */
  private static String connectStatus(LocalProxy proxy, String credentials) throws IOException {
    String auth = Base64.getEncoder().encodeToString(credentials.getBytes(UTF_8));
    try (Socket s = new Socket(proxy.address().getAddress(), proxy.address().getPort())) {
      s.setSoTimeout(30_000);
      String request =
          "CONNECT "
              + HOST
              + ":80 HTTP/1.1\r\nHost: "
              + HOST
              + ":80\r\nProxy-Authorization: Basic "
              + auth
              + "\r\n\r\n";
      s.getOutputStream().write(request.getBytes(US_ASCII));
      return new BufferedReader(new InputStreamReader(s.getInputStream(), US_ASCII)).readLine();
    }
  }

  // ---------------------------------------------------------------- tenants

  @FunctionalInterface
  private interface ProxyFactory {
    LocalProxy build(LocalProxy.Builder builder) throws IOException;
  }

  private record Tenant(String name, LocalProxy proxy) {}

  /** A real tunnel to a site that serves {@code name} over HTTP, with a proxy in front of it. */
  private Tenant tenant(String name, ProxyFactory factory) throws IOException {
    PrivateKey clientKey = PrivateKey.generate();
    PrivateKey siteKey = PrivateKey.generate();
    Netstack clientStack = Netstack.builder().address("10.0.0.1/24").dns("10.0.0.2").build();
    Netstack siteStack = Netstack.builder().address("10.0.0.2/24").build();
    Device client = device(clientKey, clientStack);
    Device site = device(siteKey, siteStack);
    client.addPeer(
        PeerConfig.builder(siteKey.publicKey())
            .endpoint(new InetSocketAddress(LOOPBACK, site.listenPort()))
            .allowedIp("10.0.0.2/32")
            .build());
    site.addPeer(PeerConfig.builder(clientKey.publicKey()).allowedIp("10.0.0.1/32").build());
    client.start();
    site.start();

    TcpListener http = siteStack.listenTcp(80);
    UdpSocket dns = siteStack.openUdp(53);
    Thread.ofVirtual().start(() -> serveHttp(http, name));
    Thread.ofVirtual().start(() -> serveDns(dns));

    LocalProxy proxy = factory.build(LocalProxy.builder(clientStack));
    resources.add(proxy);
    return new Tenant(name, proxy);
  }

  private Device device(PrivateKey key, Netstack stack) throws IOException {
    Device device =
        Device.builder()
            .privateKey(key)
            .bind(UdpBind.open(new InetSocketAddress(LOOPBACK, 0)))
            .tun(stack)
            .build();
    resources.add(device);
    return device;
  }

  private static void serveHttp(TcpListener listener, String body) {
    try {
      while (true) {
        TcpSocket socket = listener.accept();
        Thread.ofVirtual().start(() -> answerHttp(socket, body));
      }
    } catch (IOException e) {
      // closed
    }
  }

  private static void answerHttp(TcpSocket socket, String body) {
    try (socket) {
      int matched = 0;
      int b;
      while (matched < 4 && (b = socket.inputStream().read()) >= 0) {
        matched = b == "\r\n\r\n".charAt(matched) ? matched + 1 : (b == '\r' ? 1 : 0);
      }
      socket
          .outputStream()
          .write(
              ("HTTP/1.1 200 OK\r\nContent-Length: "
                      + body.length()
                      + "\r\nConnection: close\r\n\r\n"
                      + body)
                  .getBytes(US_ASCII));
      socket.shutdownOutput();
    } catch (IOException e) {
      // the client side reports the failure
    }
  }

  private static void serveDns(UdpSocket socket) {
    try {
      while (true) {
        UdpSocket.Datagram q = socket.receive(Duration.ofSeconds(30));
        if (q != null) {
          socket.send(q.source(), RemoteSite.dnsAnswer(q.data()));
        }
      }
    } catch (Exception e) {
      // closed
    }
  }
}
