// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core;

import java.net.InetSocketAddress;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

/** An in-memory UDP network with zero latency, loss filters and a packet log. */
final class SimNetwork {
  /** A datagram in flight. */
  record Packet(InetSocketAddress source, InetSocketAddress target, byte[] data) {
    int type() {
      return data.length >= 4 ? data[0] : -1;
    }
  }

  /** A bind attached to this network. Its address can change to simulate roaming or NAT. */
  final class SimBind implements Bind {
    private InetSocketAddress address;
    Device device;

    SimBind(InetSocketAddress address) {
      this.address = address;
    }

    InetSocketAddress address() {
      return address;
    }

    void moveTo(InetSocketAddress newAddress) {
      binds.remove(address);
      address = newAddress;
      binds.put(newAddress, this);
    }

    @Override
    public Datagram receive(byte[] buf) {
      throw new UnsupportedOperationException("simulated binds are driven by SimNetwork");
    }

    @Override
    public void send(byte[] buf, int off, int len, InetSocketAddress target) {
      byte[] copy = new byte[len];
      System.arraycopy(buf, off, copy, 0, len);
      inFlight.add(new Packet(address, target, copy));
    }

    @Override
    public int localPort() {
      return address.getPort();
    }

    @Override
    public void close() {}
  }

  private final Map<InetSocketAddress, SimBind> binds = new HashMap<>();
  private final ArrayDeque<Packet> inFlight = new ArrayDeque<>();
  final List<Packet> delivered = new ArrayList<>();
  private Predicate<Packet> drop = p -> false;

  SimBind bind(InetSocketAddress address) {
    SimBind b = new SimBind(address);
    binds.put(address, b);
    return b;
  }

  /** Drops every packet matching {@code filter} from now on (replaces any previous filter). */
  void drop(Predicate<Packet> filter) {
    this.drop = filter;
  }

  void heal() {
    this.drop = p -> false;
  }

  /** Re-sends a previously delivered packet. */
  void inject(Packet p) {
    inFlight.add(p);
  }

  /** Delivers everything in flight, including packets sent in response, until quiet. */
  void deliverAll() {
    for (int guard = 0; !inFlight.isEmpty(); guard++) {
      if (guard > 100_000) {
        throw new AssertionError("network did not settle");
      }
      Packet p = inFlight.poll();
      if (drop.test(p)) {
        continue;
      }
      SimBind target = binds.get(p.target());
      if (target == null || target.device == null) {
        continue;
      }
      delivered.add(p);
      target.device.processDatagram(p.data(), 0, p.data().length, p.source());
    }
  }
}
