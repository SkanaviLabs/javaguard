// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.netstack;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.ClosedChannelException;
import java.time.Duration;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * A UDP socket on a {@link Netstack}, bound to one local port for both IPv4 and IPv6. Datagrams
 * larger than fit in one packet are rejected (no fragmentation). Up to 256 received datagrams are
 * buffered; more are dropped. Thread-safe.
 */
public final class UdpSocket implements Closeable {
  /** A received datagram. */
  public record Datagram(InetSocketAddress source, byte[] data) {}

  private static final Datagram CLOSED = new Datagram(null, null);

  private final Netstack stack;
  private final int port;
  private final BlockingQueue<Datagram> queue = new ArrayBlockingQueue<>(257);
  private volatile boolean closed;

  UdpSocket(Netstack stack, int port) {
    this.stack = stack;
    this.port = port;
  }

  /** The local port. */
  public int localPort() {
    return port;
  }

  /** Sends {@code data} to {@code target}. */
  public void send(InetSocketAddress target, byte[] data) throws IOException {
    send(target, data, 0, data.length);
  }

  /** Sends {@code data[off..off+len)} to {@code target}. */
  public void send(InetSocketAddress target, byte[] data, int off, int len) throws IOException {
    if (closed || stack.isClosed()) {
      throw new ClosedChannelException();
    }
    if (target.isUnresolved()) {
      throw new IllegalArgumentException("target must be resolved: " + target);
    }
    int max = stack.maxUdpPayload(target.getAddress());
    if (len > max) {
      throw new IllegalArgumentException(
          "datagram of " + len + " bytes exceeds " + max + " (MTU, no fragmentation)");
    }
    stack.sendUdp(port, target, data, off, len);
  }

  /**
   * Waits up to {@code timeout} for a datagram.
   *
   * @return the datagram, or {@code null} on timeout
   * @throws ClosedChannelException if the socket is closed
   */
  public Datagram receive(Duration timeout) throws IOException, InterruptedException {
    if (closed) {
      throw new ClosedChannelException();
    }
    Datagram d = queue.poll(timeout.toNanos(), TimeUnit.NANOSECONDS);
    if (d == CLOSED) {
      queue.offer(CLOSED);
      throw new ClosedChannelException();
    }
    return d;
  }

  void deliver(Datagram d) {
    if (!closed) {
      queue.offer(d);
    }
  }

  @Override
  public void close() {
    if (!closed) {
      closed = true;
      stack.release(this);
      queue.clear();
      queue.offer(CLOSED);
    }
  }
}
