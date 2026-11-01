// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core;

import java.time.Duration;
import java.util.Arrays;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * A {@link Tun} backed by two bounded in-memory queues: the application sends raw IP packets into
 * the tunnel with {@link #send} and takes packets that came out of it with {@link #receive}.
 * Packets are copied on both sides. Thread-safe.
 */
public final class PacketPipe implements Tun {
  private static final byte[] CLOSED = new byte[0];

  private final int mtu;
  private final BlockingQueue<byte[]> outbound;
  private final BlockingQueue<byte[]> inbound;
  private volatile boolean closed;

  /** Creates a pipe for packets of up to {@code mtu} bytes, buffering up to 1024 each way. */
  public PacketPipe(int mtu) {
    this(mtu, 1024);
  }

  /** Creates a pipe buffering up to {@code capacity} packets each way. */
  public PacketPipe(int mtu, int capacity) {
    if (mtu < 576 || mtu > 65535) {
      throw new IllegalArgumentException("MTU out of range: " + mtu);
    }
    this.mtu = mtu;
    this.outbound = new ArrayBlockingQueue<>(capacity + 1);
    this.inbound = new ArrayBlockingQueue<>(capacity);
  }

  // ---- Application side ----

  /**
   * Queues an IP packet to be sent through the tunnel.
   *
   * @return {@code false} if the queue is full or the pipe is closed (packet dropped)
   */
  public boolean send(byte[] packet) {
    if (packet.length > mtu) {
      throw new IllegalArgumentException("packet exceeds MTU " + mtu);
    }
    return !closed && outbound.offer(packet.clone());
  }

  /** Returns the next packet that came out of the tunnel, waiting up to {@code timeout}. */
  public byte[] receive(Duration timeout) throws InterruptedException {
    return inbound.poll(timeout.toNanos(), TimeUnit.NANOSECONDS);
  }

  /** Returns the next packet that came out of the tunnel, or {@code null} if none is waiting. */
  public byte[] receive() {
    return inbound.poll();
  }

  // ---- Tun side ----

  @Override
  public int mtu() {
    return mtu;
  }

  @Override
  public int read(byte[] buf, int off, int len) {
    try {
      byte[] p = outbound.take();
      if (p == CLOSED) {
        outbound.offer(CLOSED);
        return -1;
      }
      int n = Math.min(p.length, len);
      System.arraycopy(p, 0, buf, off, n);
      return n;
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      return -1;
    }
  }

  @Override
  public void write(byte[] buf, int off, int len) {
    if (!closed) {
      inbound.offer(Arrays.copyOfRange(buf, off, off + len));
    }
  }

  @Override
  public void close() {
    closed = true;
    outbound.clear();
    outbound.offer(CLOSED);
  }
}
