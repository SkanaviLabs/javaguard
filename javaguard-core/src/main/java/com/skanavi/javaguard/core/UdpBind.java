// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;

/** A {@link Bind} over a JDK {@link DatagramChannel}, dual-stack where the OS allows. */
public final class UdpBind implements Bind {
  private final DatagramChannel channel;
  private final int port;

  private UdpBind(DatagramChannel channel) throws IOException {
    this.channel = channel;
    this.port = ((InetSocketAddress) channel.getLocalAddress()).getPort();
  }

  /** Binds all interfaces on {@code port}; 0 picks a free port. */
  public static UdpBind open(int port) throws IOException {
    return open(new InetSocketAddress(port));
  }

  /** Binds {@code local}. */
  public static UdpBind open(InetSocketAddress local) throws IOException {
    DatagramChannel channel = DatagramChannel.open();
    try {
      channel.bind(local);
      return new UdpBind(channel);
    } catch (IOException | RuntimeException e) {
      channel.close();
      throw e;
    }
  }

  @Override
  public Datagram receive(byte[] buf) throws IOException {
    ByteBuffer bb = ByteBuffer.wrap(buf);
    InetSocketAddress source = (InetSocketAddress) channel.receive(bb);
    return new Datagram(bb.position(), source);
  }

  @Override
  public void send(byte[] buf, int off, int len, InetSocketAddress target) throws IOException {
    channel.send(ByteBuffer.wrap(buf, off, len), target);
  }

  @Override
  public int localPort() {
    return port;
  }

  @Override
  public void close() throws IOException {
    channel.close();
  }
}
