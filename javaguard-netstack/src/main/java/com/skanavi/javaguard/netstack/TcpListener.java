// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.netstack;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetAddress;
import java.net.SocketException;
import java.time.Duration;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A listening TCP port on a {@link Netstack}, on all of its addresses. Up to 256 handshakes may be
 * in progress and up to {@code backlog} established connections may wait for {@link #accept()};
 * further SYNs are dropped, as are SYNs over the {@link Netstack.Builder#tcpMaxInbound(int)} and
 * {@link Netstack.Builder#tcpMaxInboundPerRemote(int)} limits. Thread-safe.
 */
public final class TcpListener implements Closeable {
  private static final int MAX_HALF_OPEN = 256;
  private static final TcpSocket CLOSED = new TcpSocket(null);

  private final Netstack stack;
  private final int port;
  private final BlockingQueue<TcpSocket> backlog;
  private final AtomicInteger halfOpen = new AtomicInteger();
  private volatile boolean closed;

  TcpListener(Netstack stack, int port, int backlog) {
    this.stack = stack;
    this.port = port;
    this.backlog = new ArrayBlockingQueue<>(backlog + 1);
  }

  /** The listening port. */
  public int localPort() {
    return port;
  }

  /** Waits for the next established connection. */
  public TcpSocket accept() throws IOException {
    try {
      return unwrap(backlog.take());
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new SocketException("accept interrupted");
    }
  }

  /** Waits up to {@code timeout} for the next connection; {@code null} on timeout. */
  public TcpSocket accept(Duration timeout) throws IOException {
    try {
      TcpSocket s = backlog.poll(timeout.toNanos(), TimeUnit.NANOSECONDS);
      return s == null ? null : unwrap(s);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new SocketException("accept interrupted");
    }
  }

  private TcpSocket unwrap(TcpSocket s) throws SocketException {
    if (s == CLOSED) {
      backlog.offer(CLOSED);
      throw new SocketException("listener closed");
    }
    return s;
  }

  /** Handles a SYN for this port with no existing connection. */
  void onSyn(InetAddress local, InetAddress remote, TcpSegment syn) {
    if (closed
        || backlog.remainingCapacity() <= 1
        || halfOpen.get() >= MAX_HALF_OPEN
        || !stack.reserveInbound(remote)) {
      return;
    }
    TcpKey key = new TcpKey(local, port, remote, syn.srcPort());
    halfOpen.incrementAndGet();
    stack.registerTcp(key, TcpConnection.accept(stack, key, this, syn));
  }

  /** A handshake finished; returns false if the connection cannot be queued. */
  boolean established(TcpConnection c) {
    halfOpen.decrementAndGet();
    return !closed && backlog.offer(new TcpSocket(c));
  }

  void halfOpenClosed() {
    halfOpen.decrementAndGet();
  }

  /** Stops listening and resets connections that were not accepted yet. */
  @Override
  public void close() {
    if (closed) {
      return;
    }
    closed = true;
    stack.removeListener(port, this);
    TcpSocket s;
    while ((s = backlog.poll()) != null) {
      if (s != CLOSED) {
        s.abort();
      }
    }
    backlog.offer(CLOSED);
  }
}
