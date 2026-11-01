// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.netstack;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.Objects;

/**
 * A TCP connection on a {@link Netstack}, with blocking streams in the style of {@link
 * java.net.Socket}. Closing either stream closes the socket; use {@link #shutdownOutput()} to
 * half-close. Writes return once data is buffered (Nagle's algorithm is off). Thread-safe; one
 * reader and one writer may work concurrently.
 */
public final class TcpSocket implements Closeable {
  private final TcpConnection connection;
  private volatile long readTimeoutNanos;
  private final InputStream in = new In();
  private final OutputStream out = new Out();

  TcpSocket(TcpConnection connection) {
    this.connection = connection;
  }

  /** The local address and port. */
  public InetSocketAddress localAddress() {
    return new InetSocketAddress(connection.key.localAddress(), connection.key.localPort());
  }

  /** The remote address and port. */
  public InetSocketAddress remoteAddress() {
    return new InetSocketAddress(connection.key.remoteAddress(), connection.key.remotePort());
  }

  /** The stream of bytes received. */
  public InputStream inputStream() {
    return in;
  }

  /** The stream of bytes to send. */
  public OutputStream outputStream() {
    return out;
  }

  /** Limits how long a read blocks; zero (the default) waits forever. */
  public void readTimeout(Duration timeout) {
    this.readTimeoutNanos = timeout.toNanos();
  }

  /**
   * Turns on keepalive probes after {@code idle} without traffic (repeated every min(idle, 75 s);
   * the connection is reset after 9 unanswered probes). {@link Duration#ZERO} turns them off.
   */
  public void keepAlive(Duration idle) {
    connection.keepAlive(idle.toNanos());
  }

  /** Sends a FIN after queued data; reading continues to work. */
  public void shutdownOutput() {
    connection.shutdownOutput();
  }

  /** Whether the connection has not been closed, reset or timed out. */
  public boolean isOpen() {
    return connection.state() != TcpConnection.State.CLOSED;
  }

  /**
   * Closes the socket. Queued data is still delivered and the connection closes gracefully, unless
   * received data was left unread, in which case it is reset.
   */
  @Override
  public void close() {
    connection.close();
  }

  /** Resets the connection immediately, discarding queued data. */
  public void abort() {
    connection.abort();
  }

  @Override
  public String toString() {
    return "TcpSocket[" + localAddress() + " -> " + remoteAddress() + "]";
  }

  private final class In extends InputStream {
    @Override
    public int read() throws IOException {
      byte[] one = new byte[1];
      return read(one, 0, 1) < 0 ? -1 : one[0] & 0xff;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
      Objects.checkFromIndexSize(off, len, b.length);
      return connection.read(b, off, len, readTimeoutNanos);
    }

    @Override
    public int available() {
      return connection.available();
    }

    @Override
    public void close() {
      TcpSocket.this.close();
    }
  }

  private final class Out extends OutputStream {
    @Override
    public void write(int b) throws IOException {
      write(new byte[] {(byte) b}, 0, 1);
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
      Objects.checkFromIndexSize(off, len, b.length);
      connection.write(b, off, len);
    }

    @Override
    public void close() {
      TcpSocket.this.close();
    }
  }
}
