// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core;

import com.skanavi.javaguard.crypto.PrivateKey;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/** Deterministic multi-device simulation on virtual time and an in-memory network. */
final class Simulation {
  final VirtualClock clock = new VirtualClock();
  final SimNetwork network = new SimNetwork();

  /** A simulated device with its tun pipe and inner address. */
  final class Node {
    final Device device;
    final PacketPipe pipe;
    final SimNetwork.SimBind bind;
    final byte[] innerIp;

    Node(String outer, String inner) {
      this.innerIp = InetAddress.ofLiteral(inner).getAddress();
      this.bind = network.bind(new InetSocketAddress(InetAddress.ofLiteral(outer), 51820));
      this.pipe = new PacketPipe(1420);
      this.device =
          Device.builder()
              .privateKey(PrivateKey.generate())
              .bind(bind)
              .tun(pipe)
              .timeSource(clock)
              .scheduler(clock)
              .manual(Runnable::run)
              .build();
      bind.device = device;
    }

    /** Adds {@code other} as a peer, routing its inner address, optionally knowing its endpoint. */
    Peer connect(Node other, boolean knowEndpoint) {
      return device.addPeer(
          PeerConfig.builder(other.device.publicKey())
              .allowedIp(InetAddress.ofLiteral(other.innerHost()).getHostAddress() + "/32")
              .endpoint(knowEndpoint ? other.bind.address() : null)
              .build());
    }

    Peer peer(Node other) {
      return device.peer(other.device.publicKey());
    }

    String innerHost() {
      try {
        return InetAddress.getByAddress(innerIp).getHostAddress();
      } catch (java.net.UnknownHostException e) {
        throw new AssertionError(e);
      }
    }

    /** Sends an IPv4 packet with {@code payload} from this node's inner address to {@code to}. */
    void send(Node to, String payload) {
      sendFrom(innerIp, to, payload);
    }

    void sendFrom(byte[] source, Node to, String payload) {
      byte[] packet = Ipv4.packet(source, to.innerIp, payload.getBytes());
      device.processOutbound(packet, 0, packet.length);
    }

    /** Payloads of all packets that came out of this node's tun so far. */
    List<String> received() {
      List<String> out = new ArrayList<>();
      byte[] p;
      while ((p = pipe.receive()) != null) {
        out.add(Ipv4.payload(p));
      }
      return out;
    }
  }

  Node node(String outer, String inner) {
    return new Node(outer, inner);
  }

  /** Connects two nodes to each other; {@code a} knows {@code b}'s endpoint, and vice versa. */
  void link(Node a, Node b) {
    a.connect(b, true);
    b.connect(a, true);
  }

  /** Delivers in-flight packets and fires timers until {@code d} of virtual time has passed. */
  void run(Duration d) {
    long end = clock.nanoTime() + d.toNanos();
    network.deliverAll();
    while (clock.runNext(end)) {
      network.deliverAll();
    }
    clock.setNanos(end);
    network.deliverAll();
  }

  long count(int type, SimNetwork.SimBind from) {
    return network.delivered.stream()
        .filter(p -> p.type() == type && p.source().equals(from.address()))
        .count();
  }
}
