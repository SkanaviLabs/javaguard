// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.server;

import com.skanavi.javaguard.netstack.TcpSocket;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;

/** Copies a peer's connection to and from a local listener, passing on half-closes. */
final class LocalRelay implements ConnectionHandler {
  private static final int BUFFER = 64 * 1024;

  private final Target target;
  private final ProxyHeader header;

  LocalRelay(Target target, ProxyHeader header) {
    this.target = target;
    this.header = header;
  }

  /** Relays until both directions finish. A failure propagates, which resets the peer. */
  @Override
  public void handle(TunnelConnection connection) throws IOException, InterruptedException {
    TcpSocket socket = connection.socket();
    try (SocketChannel local = connect()) {
      if (header == ProxyHeader.V2) {
        writeFully(
            local,
            ByteBuffer.wrap(
                ProxyProtocolV2.encode(
                    socket.remoteAddress(), socket.localAddress(), connection.peer())));
      }
      Thread upstream =
          Thread.ofVirtual().name("javaguard-relay-up").start(() -> toLocal(socket, local));
      ByteBuffer buf = ByteBuffer.allocate(BUFFER);
      while (local.read(buf) >= 0) {
        socket.outputStream().write(buf.array(), 0, buf.position());
        buf.clear();
      }
      socket.shutdownOutput();
      upstream.join();
    }
  }

  private SocketChannel connect() throws IOException {
    SocketAddress address =
        switch (target) {
          case Target.Loopback t ->
              new InetSocketAddress(InetAddress.getLoopbackAddress(), t.port());
          case Target.UnixSocket t -> UnixDomainSocketAddress.of(t.path());
        };
    return SocketChannel.open(address);
  }

  private static void toLocal(TcpSocket socket, SocketChannel local) {
    try {
      InputStream in = socket.inputStream();
      byte[] buf = new byte[BUFFER];
      int n;
      while ((n = in.read(buf)) >= 0) {
        writeFully(local, ByteBuffer.wrap(buf, 0, n));
      }
      local.shutdownOutput();
    } catch (IOException e) {
      socket.abort();
      try {
        local.close(); // wakes the other direction
      } catch (IOException ignored) {
        // already broken
      }
    }
  }

  private static void writeFully(SocketChannel channel, ByteBuffer data) throws IOException {
    while (data.hasRemaining()) {
      channel.write(data);
    }
  }
}
