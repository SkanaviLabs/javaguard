// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.examples;

import com.skanavi.javaguard.proxy.LocalProxy;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;

/**
 * Fetches a URL through the tunnel with the JDK's {@link HttpClient}, using a {@link LocalProxy} on
 * loopback. Host names in the URL are resolved by the tunnel's DNS.
 *
 * <pre>
 * ./gradlew :javaguard-examples:run -Pexample=EmbeddedHttpClient \
 *     --args="client.conf http://intranet.example/"
 * </pre>
 */
public final class EmbeddedHttpClient {
  private EmbeddedHttpClient() {}

  /**
   * Runs the example.
   *
   * @param args configuration file, URL
   * @throws Exception on any failure
   */
  public static void main(String[] args) throws Exception {
    if (args.length != 2) {
      System.err.println("usage: EmbeddedHttpClient <config> <url>");
      System.exit(2);
    }
    try (Tunnel tunnel = Tunnel.start(Path.of(args[0]));
        LocalProxy proxy = LocalProxy.builder(tunnel.stack()).build()) {
      HttpClient client = proxy.httpClientBuilder().build();
      HttpResponse<String> response =
          client.send(
              HttpRequest.newBuilder(URI.create(args[1])).build(),
              HttpResponse.BodyHandlers.ofString());
      System.out.println("HTTP " + response.statusCode());
      System.out.println(response.body());
    }
  }
}
