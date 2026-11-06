// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.server;

import com.skanavi.javaguard.core.Device;
import com.skanavi.javaguard.core.PeerConfig;
import com.skanavi.javaguard.core.UdpBind;
import com.skanavi.javaguard.crypto.PrivateKey;
import com.skanavi.javaguard.crypto.PublicKey;
import com.skanavi.javaguard.netstack.Netstack;
import com.skanavi.javaguard.netstack.TcpSocket;
import java.io.Closeable;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Duration;

/** A javaguard peer of a {@link TunnelHost} under test. */
final class TunnelClient implements Closeable {
  static final String HOST_IP = "10.60.0.1";

  final PrivateKey key = PrivateKey.generate();
  final String ip;
  private Device device;
  private Netstack stack;

  TunnelClient(String ip) {
    this.ip = ip;
  }

  PublicKey publicKey() {
    return key.publicKey();
  }

  String peerSection() {
    return "[Peer]\nPublicKey = " + publicKey().toBase64() + "\nAllowedIPs = " + ip + "/32\n";
  }

  static String config(PrivateKey hostKey, int port, TunnelClient... clients) {
    StringBuilder s =
        new StringBuilder("[Interface]\nPrivateKey = ")
            .append(hostKey.toBase64())
            .append("\nListenPort = ")
            .append(port)
            .append("\nAddress = ")
            .append(HOST_IP)
            .append("/24\n");
    for (TunnelClient c : clients) {
      s.append(c.peerSection());
    }
    return s.toString();
  }

  static int freeUdpPort() throws IOException {
    try (DatagramSocket s = new DatagramSocket(0)) {
      return s.getLocalPort();
    }
  }

  /** Starts this client, peered with a host at {@code port} on this machine. */
  void start(PublicKey host, int port) throws IOException {
    stack = Netstack.builder().address(ip + "/24").build();
    device = Device.builder().privateKey(key).bind(UdpBind.open(0)).tun(stack).build();
    device.addPeer(
        PeerConfig.builder(host)
            .endpoint(new InetSocketAddress(InetAddress.getLoopbackAddress(), port))
            .allowedIp(HOST_IP + "/32")
            .build());
    device.start();
  }

  TcpSocket connect(int port, Duration timeout) throws IOException {
    return stack.connectTcp(new InetSocketAddress(InetAddress.ofLiteral(HOST_IP), port), timeout);
  }

  @Override
  public void close() throws IOException {
    if (device != null) {
      device.close();
    }
  }
}
