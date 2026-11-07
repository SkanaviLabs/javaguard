// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.server;

import java.nio.file.Path;
import java.util.HexFormat;
import org.eclipse.jetty.http.HttpVersion;
import org.eclipse.jetty.io.Content;
import org.eclipse.jetty.io.EndPoint;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.ProxyConnectionFactory;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.unixdomain.server.UnixDomainServerConnector;
import org.eclipse.jetty.util.Callback;

/** A real Jetty on a Unix socket, answering with the client it believes it is talking to. */
final class WebServer {
  private WebServer() {}

  static Server start(Path socket) throws Exception {
    Server server = new Server();
    UnixDomainServerConnector connector =
        new UnixDomainServerConnector(
            server,
            new ProxyConnectionFactory(HttpVersion.HTTP_1_1.asString()),
            new HttpConnectionFactory());
    connector.setUnixDomainPath(socket);
    server.addConnector(connector);
    server.setHandler(
        new Handler.Abstract() {
          @Override
          public boolean handle(Request request, Response response, Callback callback) {
            EndPoint endPoint = request.getConnectionMetaData().getConnection().getEndPoint();
            byte[] key =
                endPoint instanceof ProxyConnectionFactory.ProxyEndPoint proxied
                    ? proxied.getTLV(ProxyHeader.PEER_KEY_TLV)
                    : new byte[0];
            String body = Request.getRemoteAddr(request) + " " + HexFormat.of().formatHex(key);
            Content.Sink.write(response, true, body, callback);
            return true;
          }
        });
    server.start();
    return server;
  }
}
