// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.proxy;

import com.skanavi.javaguard.netstack.TcpSocket;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

/**
 * The client half of SOCKS5 (RFC 1928) with username/password authentication (RFC 1929), used to
 * reach targets through an upstream proxy. Host names are sent as they are, never resolved here.
 */
final class Socks5Client {
  private static final int AUTH_VERSION = 1;
  private static final int MAX_NAME_BYTES = 255;

  private Socks5Client() {}

  /**
   * Asks the proxy at the far end of {@code socket} to connect to {@code host:port}. On return the
   * socket carries the relayed stream, and nothing of it has been read. {@code timeout} limits each
   * read of the handshake, and later reads have no limit. The caller closes the socket on failure.
   *
   * @param credentials offered to the proxy, or null to offer no authentication
   * @throws ConnectException if the proxy reports that the target refused
   * @throws SocketTimeoutException if the proxy goes silent or reports the host unreachable
   */
  static void connect(
      TcpSocket socket,
      Socks5Session.Credentials credentials,
      String host,
      int port,
      Duration timeout)
      throws IOException {
    byte[] request = connectRequest(host, port);
    InputStream in = socket.inputStream();
    OutputStream out = socket.outputStream();
    socket.readTimeout(timeout);
    negotiate(in, out, credentials);
    out.write(request);
    readReply(in);
    socket.readTimeout(Duration.ZERO);
  }

  private static void negotiate(
      InputStream in, OutputStream out, Socks5Session.Credentials credentials) throws IOException {
    out.write(
        credentials == null
            ? new byte[] {Socks5Session.VERSION, 1, Socks5Session.METHOD_NONE}
            : new byte[] {
              Socks5Session.VERSION, 2, Socks5Session.METHOD_NONE, Socks5Session.METHOD_PASSWORD
            });
    byte[] choice = readExactly(in, 2);
    checkVersion(choice[0]);
    int method = choice[1] & 0xff;
    if (method == Socks5Session.METHOD_PASSWORD && credentials != null) {
      authenticate(in, out, credentials);
    } else if (method != Socks5Session.METHOD_NONE) {
      throw new IOException("upstream SOCKS5 proxy accepts no offered authentication method");
    }
  }

  private static void authenticate(
      InputStream in, OutputStream out, Socks5Session.Credentials credentials) throws IOException {
    ByteArrayOutputStream b = new ByteArrayOutputStream();
    b.write(AUTH_VERSION);
    b.write(credentials.user().length);
    b.writeBytes(credentials.user());
    b.write(credentials.password().length);
    b.writeBytes(credentials.password());
    out.write(b.toByteArray());
    if (readExactly(in, 2)[1] != 0) {
      throw new IOException("upstream SOCKS5 proxy rejected the credentials");
    }
  }

  private static byte[] connectRequest(String host, int port) throws IOException {
    ByteArrayOutputStream b = new ByteArrayOutputStream();
    b.write(Socks5Session.VERSION);
    b.write(Socks5Session.CMD_CONNECT);
    b.write(0);
    byte[] address = literal(host);
    if (address != null) {
      b.write(address.length == 4 ? Socks5Session.ATYP_IPV4 : Socks5Session.ATYP_IPV6);
      b.writeBytes(address);
    } else {
      byte[] name = host.getBytes(StandardCharsets.UTF_8);
      if (name.length == 0 || name.length > MAX_NAME_BYTES) {
        throw new IOException("host name does not fit in a SOCKS5 request");
      }
      b.write(Socks5Session.ATYP_DOMAIN);
      b.write(name.length);
      b.writeBytes(name);
    }
    b.write(port >>> 8);
    b.write(port);
    return b.toByteArray();
  }

  /** The bytes of an IP address literal, or null for a name. This never does a lookup. */
  private static byte[] literal(String host) {
    try {
      return InetAddress.ofLiteral(host).getAddress();
    } catch (IllegalArgumentException e) {
      return null;
    }
  }

  /**
   * Reads the reply and no further, since what follows it belongs to the relayed stream. A failure
   * is reported before the bound address is read, as some proxies do not send one.
   */
  private static void readReply(InputStream in) throws IOException {
    byte[] head = readExactly(in, 2);
    checkVersion(head[0]);
    int reply = head[1] & 0xff;
    if (reply != Socks5Session.REP_OK) {
      throw failure(reply);
    }
    int atyp = readExactly(in, 2)[1] & 0xff;
    int addressLength =
        switch (atyp) {
          case Socks5Session.ATYP_IPV4 -> 4;
          case Socks5Session.ATYP_IPV6 -> 16;
          case Socks5Session.ATYP_DOMAIN -> readExactly(in, 1)[0] & 0xff;
          default -> throw new IOException("upstream SOCKS5 reply has address type " + atyp);
        };
    readExactly(in, addressLength + 2);
  }

  /** The exception that makes the sessions give their clients the matching error. */
  private static IOException failure(int reply) {
    return switch (reply) {
      case Socks5Session.REP_REFUSED -> new ConnectException("connection refused by upstream");
      case Socks5Session.REP_HOST_UNREACHABLE ->
          new SocketTimeoutException("host unreachable from upstream");
      default -> new IOException("upstream SOCKS5 proxy replied " + reply);
    };
  }

  private static void checkVersion(byte version) throws IOException {
    if (version != Socks5Session.VERSION) {
      throw new IOException("upstream proxy does not speak SOCKS5");
    }
  }

  private static byte[] readExactly(InputStream in, int length) throws IOException {
    byte[] b = in.readNBytes(length);
    if (b.length < length) {
      throw new EOFException("upstream SOCKS5 proxy closed the connection");
    }
    return b;
  }
}
