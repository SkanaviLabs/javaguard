// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.examples;

import com.skanavi.javaguard.netstack.TcpListener;
import com.skanavi.javaguard.netstack.TcpSocket;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

/**
 * Serves HTTP inside the tunnel: peers reach it at this tunnel's {@code Address}, port 8080. The
 * service is invisible on the host's own network interfaces.
 *
 * <pre>
 * ./gradlew :javaguard-examples:run -Pexample=TunnelServer --args="server.conf"
 * </pre>
 */
public final class TunnelServer {
  private TunnelServer() {}

  /**
   * Runs the example until interrupted.
   *
   * @param args configuration file
   * @throws Exception on any failure
   */
  public static void main(String[] args) throws Exception {
    if (args.length != 1) {
      System.err.println("usage: TunnelServer <config>");
      System.exit(2);
    }
    try (Tunnel tunnel = Tunnel.start(Path.of(args[0]));
        TcpListener listener = tunnel.stack().listenTcp(8080)) {
      System.out.println("listening on " + tunnel.stack().addresses() + " port 8080");
      while (true) {
        TcpSocket client = listener.accept();
        Thread.ofVirtual().start(() -> respond(client));
      }
    }
  }

  private static void respond(TcpSocket client) {
    try (client) {
      byte[] buf = new byte[4096];
      client.inputStream().read(buf); // the request; a real server would parse it
      String body = "hello from inside the tunnel\n";
      client
          .outputStream()
          .write(
              ("HTTP/1.1 200 OK\r\nContent-Length: "
                      + body.length()
                      + "\r\nConnection: close\r\n\r\n"
                      + body)
                  .getBytes(StandardCharsets.US_ASCII));
      client.shutdownOutput();
    } catch (IOException e) {
      // client went away
    }
  }
}
