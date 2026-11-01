// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.proxy;

import com.skanavi.javaguard.netstack.TcpSocket;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;

/**
 * One HTTP proxy client connection: {@code CONNECT host:port} tunnels (used for HTTPS), or a plain
 * request with an absolute {@code http://} URI, forwarded once with {@code Connection: close}.
 */
final class HttpProxySession {
  private static final int MAX_HEAD = 64 * 1024;

  private final Socket client;
  private final Dialer dialer;
  private final Socks5Session.Credentials credentials;

  HttpProxySession(Socket client, Dialer dialer, Socks5Session.Credentials credentials) {
    this.client = client;
    this.dialer = dialer;
    this.credentials = credentials;
  }

  void run(InputStream in) throws IOException {
    OutputStream out = client.getOutputStream();
    List<String> head = readHead(in);
    if (head == null || head.isEmpty()) {
      respond(out, 400, "Bad Request");
      return;
    }
    String[] requestLine = head.get(0).split(" ");
    if (requestLine.length != 3 || !requestLine[2].startsWith("HTTP/1.")) {
      respond(out, 400, "Bad Request");
      return;
    }
    if (credentials != null && !authorized(head)) {
      out.write(
          ("HTTP/1.1 407 Proxy Authentication Required\r\n"
                  + "Proxy-Authenticate: Basic realm=\"javaguard\"\r\nContent-Length: 0\r\n"
                  + "Connection: close\r\n\r\n")
              .getBytes(StandardCharsets.US_ASCII));
      out.flush();
      return;
    }
    String method = requestLine[0];
    String target = requestLine[1];
    if (method.equals("CONNECT")) {
      connect(out, target);
    } else {
      forward(out, method, target, requestLine[2], head);
    }
  }

  private void connect(OutputStream out, String authority) throws IOException {
    HostPort hp = HostPort.parse(authority, -1);
    if (hp == null) {
      respond(out, 400, "Bad Request");
      return;
    }
    TcpSocket remote = dial(out, hp);
    if (remote == null) {
      return;
    }
    out.write("HTTP/1.1 200 Connection Established\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
    out.flush();
    Relay.run(client, remote);
  }

  private void forward(
      OutputStream out, String method, String target, String version, List<String> head)
      throws IOException {
    URI uri;
    try {
      uri = new URI(target);
    } catch (URISyntaxException e) {
      respond(out, 400, "Bad Request");
      return;
    }
    if (!"http".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null) {
      respond(out, 400, "Bad Request");
      return;
    }
    String host =
        uri.getHost().startsWith("[")
            ? uri.getHost().substring(1, uri.getHost().length() - 1)
            : uri.getHost();
    HostPort hp = new HostPort(host, uri.getPort() < 0 ? 80 : uri.getPort());
    TcpSocket remote = dial(out, hp);
    if (remote == null) {
      return;
    }
    StringBuilder request = new StringBuilder();
    String path = uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
    if (uri.getRawQuery() != null) {
      path += "?" + uri.getRawQuery();
    }
    request.append(method).append(' ').append(path).append(' ').append(version).append("\r\n");
    for (String line : head.subList(1, head.size())) {
      String name =
          line.contains(":")
              ? line.substring(0, line.indexOf(':')).strip().toLowerCase(Locale.ROOT)
              : "";
      if (name.startsWith("proxy-") || name.equals("connection") || name.equals("keep-alive")) {
        continue;
      }
      request.append(line).append("\r\n");
    }
    request.append("Connection: close\r\n\r\n");
    remote.outputStream().write(request.toString().getBytes(StandardCharsets.ISO_8859_1));
    Relay.run(client, remote); // request body, if any, then the response
  }

  /** Connects, or writes an error response and returns null. */
  private TcpSocket dial(OutputStream out, HostPort hp) throws IOException {
    try {
      return dialer.connect(hp.host(), hp.port());
    } catch (SocketTimeoutException e) {
      respond(out, 504, "Gateway Timeout");
    } catch (ConnectException e) {
      respond(out, 502, "Bad Gateway");
    } catch (IOException e) {
      respond(out, 502, "Bad Gateway");
    }
    return null;
  }

  private boolean authorized(List<String> head) {
    for (String line : head) {
      int colon = line.indexOf(':');
      if (colon > 0 && line.substring(0, colon).strip().equalsIgnoreCase("Proxy-Authorization")) {
        String value = line.substring(colon + 1).strip();
        if (value.regionMatches(true, 0, "Basic ", 0, 6)) {
          try {
            String decoded =
                new String(
                    Base64.getDecoder().decode(value.substring(6).strip()), StandardCharsets.UTF_8);
            int sep = decoded.indexOf(':');
            if (sep >= 0) {
              return credentials.matches(
                  decoded.substring(0, sep).getBytes(StandardCharsets.UTF_8),
                  decoded.substring(sep + 1).getBytes(StandardCharsets.UTF_8));
            }
          } catch (IllegalArgumentException e) {
            return false;
          }
        }
      }
    }
    return false;
  }

  /** Reads header lines up to the blank line, byte by byte so nothing after it is consumed. */
  private static List<String> readHead(InputStream in) throws IOException {
    List<String> lines = new ArrayList<>();
    ByteArrayOutputStream line = new ByteArrayOutputStream();
    int total = 0;
    int b;
    while ((b = in.read()) >= 0) {
      if (++total > MAX_HEAD) {
        return null;
      }
      if (b == '\n') {
        String s = line.toString(StandardCharsets.ISO_8859_1);
        if (s.endsWith("\r")) {
          s = s.substring(0, s.length() - 1);
        }
        if (s.isEmpty()) {
          return lines;
        }
        lines.add(s);
        line.reset();
      } else {
        line.write(b);
      }
    }
    return null;
  }

  private static void respond(OutputStream out, int status, String reason) throws IOException {
    out.write(
        ("HTTP/1.1 " + status + " " + reason + "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .getBytes(StandardCharsets.US_ASCII));
    out.flush();
  }

  /** A host (IPv6 without brackets) and port. */
  record HostPort(String host, int port) {
    static HostPort parse(String authority, int defaultPort) {
      String host;
      String port;
      if (authority.startsWith("[")) {
        int close = authority.indexOf(']');
        if (close < 0) {
          return null;
        }
        host = authority.substring(1, close);
        port =
            close + 1 < authority.length() && authority.charAt(close + 1) == ':'
                ? authority.substring(close + 2)
                : null;
      } else {
        int colon = authority.lastIndexOf(':');
        host = colon < 0 ? authority : authority.substring(0, colon);
        port = colon < 0 ? null : authority.substring(colon + 1);
      }
      try {
        int p = port == null ? defaultPort : Integer.parseInt(port);
        return host.isEmpty() || p < 1 || p > 65535 ? null : new HostPort(host, p);
      } catch (NumberFormatException e) {
        return null;
      }
    }
  }
}
