// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.examples;

import com.skanavi.javaguard.netstack.TcpSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;

/**
 * Uses the netstack's TCP API directly, without a proxy: resolves a name through the tunnel,
 * connects, sends a line, and prints what comes back until the server closes.
 *
 * <pre>
 * ./gradlew :javaguard-examples:run -Pexample=TunnelTcpClient \
 *     --args="client.conf db.internal 7 hello"
 * </pre>
 */
public final class TunnelTcpClient {
  private TunnelTcpClient() {}

  /**
   * Runs the example.
   *
   * @param args configuration file, host, port, line to send
   * @throws Exception on any failure
   */
  public static void main(String[] args) throws Exception {
    if (args.length != 4) {
      System.err.println("usage: TunnelTcpClient <config> <host> <port> <line>");
      System.exit(2);
    }
    try (Tunnel tunnel = Tunnel.start(Path.of(args[0]))) {
      InetAddress address = tunnel.stack().dns().resolve(args[1]).get(0);
      InetSocketAddress target = new InetSocketAddress(address, Integer.parseInt(args[2]));
      try (TcpSocket socket = tunnel.stack().connectTcp(target, Duration.ofSeconds(10))) {
        socket.outputStream().write((args[3] + "\n").getBytes(StandardCharsets.UTF_8));
        socket.shutdownOutput();
        socket.inputStream().transferTo(System.out);
      }
    }
  }
}
