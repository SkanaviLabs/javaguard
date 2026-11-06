// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.proxy;

import com.skanavi.javaguard.netstack.TcpSocket;
import com.skanavi.javaguard.netstack.UdpSocket;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Arrays;

/**
 * One SOCKS5 client connection (RFC 1928): method negotiation, optional username/password
 * authentication (RFC 1929), then CONNECT or UDP ASSOCIATE. BIND is not supported.
 */
final class Socks5Session {
  static final int VERSION = 5;
  static final int METHOD_NONE = 0x00;
  static final int METHOD_PASSWORD = 0x02;
  private static final int METHOD_UNACCEPTABLE = 0xff;
  static final int CMD_CONNECT = 1;
  private static final int CMD_UDP_ASSOCIATE = 3;
  static final int ATYP_IPV4 = 1;
  static final int ATYP_DOMAIN = 3;
  static final int ATYP_IPV6 = 4;

  static final int REP_OK = 0;
  static final int REP_FAILURE = 1;
  static final int REP_NETWORK_UNREACHABLE = 3;
  static final int REP_HOST_UNREACHABLE = 4;
  static final int REP_REFUSED = 5;
  static final int REP_COMMAND_NOT_SUPPORTED = 7;
  static final int REP_ADDRESS_NOT_SUPPORTED = 8;

  private final Socket client;
  private final Dialer dialer;
  private final Credentials credentials;

  Socks5Session(Socket client, Dialer dialer, Credentials credentials) {
    this.client = client;
    this.dialer = dialer;
    this.credentials = credentials;
  }

  /** Runs the session; {@code in} has the version byte already consumed. */
  void run(InputStream rawIn) throws IOException {
    DataInputStream in = new DataInputStream(rawIn);
    OutputStream out = client.getOutputStream();
    if (!negotiate(in, out)) {
      return;
    }
    if (in.readUnsignedByte() != VERSION) {
      return;
    }
    int command = in.readUnsignedByte();
    in.readUnsignedByte(); // reserved
    String host;
    int atyp = in.readUnsignedByte();
    switch (atyp) {
      case ATYP_IPV4 -> host = InetAddress.getByAddress(in.readNBytes(4)).getHostAddress();
      case ATYP_IPV6 -> host = InetAddress.getByAddress(in.readNBytes(16)).getHostAddress();
      case ATYP_DOMAIN ->
          host = new String(in.readNBytes(in.readUnsignedByte()), StandardCharsets.US_ASCII);
      default -> {
        reply(out, REP_ADDRESS_NOT_SUPPORTED, null);
        return;
      }
    }
    int port = in.readUnsignedShort();
    switch (command) {
      case CMD_CONNECT -> connect(out, host, port);
      case CMD_UDP_ASSOCIATE -> {
        if (dialer.hasUpstream()) {
          reply(out, REP_COMMAND_NOT_SUPPORTED, null); // UDP would bypass the upstream
        } else {
          udpAssociate(in, out);
        }
      }
      default -> reply(out, REP_COMMAND_NOT_SUPPORTED, null);
    }
  }

  private boolean negotiate(DataInputStream in, OutputStream out) throws IOException {
    byte[] methods = in.readNBytes(in.readUnsignedByte());
    int wanted = credentials == null ? METHOD_NONE : METHOD_PASSWORD;
    boolean offered = false;
    for (byte m : methods) {
      offered |= (m & 0xff) == wanted;
    }
    out.write(new byte[] {VERSION, (byte) (offered ? wanted : METHOD_UNACCEPTABLE)});
    out.flush();
    if (!offered) {
      return false;
    }
    if (credentials == null) {
      return true;
    }
    if (in.readUnsignedByte() != 1) {
      return false;
    }
    byte[] user = in.readNBytes(in.readUnsignedByte());
    byte[] pass = in.readNBytes(in.readUnsignedByte());
    boolean ok = credentials.matches(user, pass);
    out.write(new byte[] {1, (byte) (ok ? 0 : 1)});
    out.flush();
    return ok;
  }

  private void connect(OutputStream out, String host, int port) throws IOException {
    TcpSocket remote;
    try {
      remote = dialer.connect(host, port);
    } catch (IOException e) {
      reply(out, replyFor(e), null);
      return;
    }
    reply(out, REP_OK, remote.localAddress());
    Relay.run(client, remote);
  }

  static int replyFor(IOException e) {
    if (e instanceof ConnectException
        && e.getMessage() != null
        && e.getMessage().contains("refused")) {
      return REP_REFUSED;
    }
    if (e instanceof ConnectException) {
      return REP_NETWORK_UNREACHABLE;
    }
    if (e instanceof SocketTimeoutException || e instanceof UnknownHostException) {
      return REP_HOST_UNREACHABLE;
    }
    return REP_FAILURE;
  }

  /**
   * Relays UDP for this client until its control connection closes. Datagrams are accepted only
   * from the client's IP address, and only from the first port it uses.
   */
  private void udpAssociate(DataInputStream control, OutputStream out) throws IOException {
    InetAddress clientIp = client.getInetAddress();
    DatagramSocket relay = new DatagramSocket(new InetSocketAddress(client.getLocalAddress(), 0));
    UdpSocket tunnel;
    try {
      tunnel = dialer.stack().openUdp();
    } catch (IOException e) {
      relay.close();
      throw e;
    }
    Thread fromClient = null;
    Thread toClient = null;
    try {
      reply(out, REP_OK, (InetSocketAddress) relay.getLocalSocketAddress());
      InetSocketAddress[] clientEndpoint = new InetSocketAddress[1];
      fromClient =
          Thread.ofVirtual().start(() -> clientToTunnel(relay, tunnel, clientIp, clientEndpoint));
      toClient = Thread.ofVirtual().start(() -> tunnelToClient(relay, tunnel, clientEndpoint));
      while (control.read() >= 0) {
        // RFC 1928: the association lasts as long as the TCP connection
      }
    } catch (IOException e) {
      // control connection broken: end the association
    } finally {
      relay.close();
      tunnel.close();
      if (fromClient != null) {
        fromClient.interrupt();
        toClient.interrupt();
      }
    }
  }

  private void clientToTunnel(
      DatagramSocket relay, UdpSocket tunnel, InetAddress clientIp, InetSocketAddress[] endpoint) {
    byte[] buf = new byte[65535];
    while (!relay.isClosed()) {
      try {
        DatagramPacket p = new DatagramPacket(buf, buf.length);
        relay.receive(p);
        InetSocketAddress from = (InetSocketAddress) p.getSocketAddress();
        if (!from.getAddress().equals(clientIp)) {
          continue;
        }
        synchronized (endpoint) {
          if (endpoint[0] == null) {
            endpoint[0] = from;
          } else if (!endpoint[0].equals(from)) {
            continue;
          }
        }
        UdpHeader h = UdpHeader.parse(buf, p.getLength());
        if (h == null || h.fragment() != 0) {
          continue; // fragmentation is optional and not supported
        }
        InetAddress target = h.host() == null ? h.address() : dialer.resolve(h.host()).get(0);
        tunnel.send(
            new InetSocketAddress(target, h.port()),
            buf,
            h.dataOffset(),
            p.getLength() - h.dataOffset());
      } catch (IOException | IllegalArgumentException e) {
        if (relay.isClosed()) {
          return;
        }
        // drop this datagram: unresolvable, too large, or no tunnel address of that family
      }
    }
  }

  private void tunnelToClient(
      DatagramSocket relay, UdpSocket tunnel, InetSocketAddress[] endpoint) {
    while (!relay.isClosed()) {
      try {
        UdpSocket.Datagram d = tunnel.receive(Duration.ofSeconds(1));
        InetSocketAddress to;
        synchronized (endpoint) {
          to = endpoint[0];
        }
        if (d == null || to == null) {
          continue;
        }
        byte[] wrapped = UdpHeader.wrap(d.source(), d.data());
        relay.send(new DatagramPacket(wrapped, wrapped.length, to));
      } catch (IOException e) {
        return;
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        return;
      }
    }
  }

  private void reply(OutputStream out, int rep, InetSocketAddress bound) throws IOException {
    ByteArrayOutputStream b = new ByteArrayOutputStream();
    b.write(VERSION);
    b.write(rep);
    b.write(0);
    InetAddress addr = bound == null ? InetAddress.getByAddress(new byte[4]) : bound.getAddress();
    b.write(addr instanceof Inet4Address ? ATYP_IPV4 : ATYP_IPV6);
    b.writeBytes(addr.getAddress());
    int port = bound == null ? 0 : bound.getPort();
    b.write(port >>> 8);
    b.write(port);
    out.write(b.toByteArray());
    out.flush();
  }

  /** The SOCKS5 UDP request header. */
  record UdpHeader(int fragment, InetAddress address, String host, int port, int dataOffset) {
    static UdpHeader parse(byte[] b, int len) {
      if (len < 4 || b[0] != 0 || b[1] != 0) {
        return null;
      }
      int frag = b[2] & 0xff;
      int atyp = b[3] & 0xff;
      try {
        return switch (atyp) {
          case ATYP_IPV4 ->
              len < 10
                  ? null
                  : new UdpHeader(
                      frag,
                      InetAddress.getByAddress(Arrays.copyOfRange(b, 4, 8)),
                      null,
                      port(b, 8),
                      10);
          case ATYP_IPV6 ->
              len < 22
                  ? null
                  : new UdpHeader(
                      frag,
                      InetAddress.getByAddress(Arrays.copyOfRange(b, 4, 20)),
                      null,
                      port(b, 20),
                      22);
          case ATYP_DOMAIN -> {
            int n = b[4] & 0xff;
            yield len < 7 + n
                ? null
                : new UdpHeader(
                    frag,
                    null,
                    new String(b, 5, n, StandardCharsets.US_ASCII),
                    port(b, 5 + n),
                    7 + n);
          }
          default -> null;
        };
      } catch (UnknownHostException e) {
        return null;
      }
    }

    static byte[] wrap(InetSocketAddress source, byte[] data) {
      byte[] addr = source.getAddress().getAddress();
      byte[] out = new byte[4 + addr.length + 2 + data.length];
      out[3] = (byte) (addr.length == 4 ? ATYP_IPV4 : ATYP_IPV6);
      System.arraycopy(addr, 0, out, 4, addr.length);
      out[4 + addr.length] = (byte) (source.getPort() >>> 8);
      out[5 + addr.length] = (byte) source.getPort();
      System.arraycopy(data, 0, out, 6 + addr.length, data.length);
      return out;
    }

    private static int port(byte[] b, int off) {
      return ((b[off] & 0xff) << 8) | (b[off + 1] & 0xff);
    }
  }

  /** Username and password required from clients. */
  record Credentials(byte[] user, byte[] password) {
    boolean matches(byte[] u, byte[] p) {
      // Evaluate both comparisons so timing does not reveal which one failed.
      boolean userOk = MessageDigest.isEqual(user, u);
      boolean passOk = MessageDigest.isEqual(password, p);
      return userOk & passOk;
    }
  }
}
