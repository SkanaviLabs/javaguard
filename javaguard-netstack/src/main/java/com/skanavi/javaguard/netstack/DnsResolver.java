// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.netstack;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * A stub DNS resolver that queries the configured servers over UDP through the tunnel. Each query
 * uses a fresh random source port and a random ID, and only accepts an answer from the server it
 * asked. IP literals are returned without a query. Truncated (TCP-only) answers are not supported
 * yet. Thread-safe.
 */
public final class DnsResolver {
  private static final int DNS_PORT = 53;
  private static final int ATTEMPTS_PER_SERVER = 2;

  private final Netstack stack;
  private final List<InetAddress> servers;
  private final List<String> searchDomains;
  private final SecureRandom random = new SecureRandom();
  private volatile Duration timeout = Duration.ofSeconds(2);

  DnsResolver(Netstack stack, List<InetAddress> servers, List<String> searchDomains) {
    this.stack = stack;
    this.servers = List.copyOf(servers);
    this.searchDomains = List.copyOf(searchDomains);
  }

  /** The servers queried, in order. */
  public List<InetAddress> servers() {
    return servers;
  }

  /** Sets the per-attempt timeout (default 2 s; each server is tried twice). */
  public void timeout(Duration timeout) {
    this.timeout = timeout;
  }

  /**
   * Resolves {@code host} to its IPv4 then IPv6 addresses. Names without a dot try the search
   * domains first; other names try the name as given first. A trailing dot disables the search.
   *
   * @throws UnknownHostException if no addresses were found or no server answered
   */
  public List<InetAddress> resolve(String host) throws UnknownHostException {
    try {
      return List.of(InetAddress.ofLiteral(host));
    } catch (IllegalArgumentException notALiteral) {
      // fall through to DNS
    }
    if (servers.isEmpty()) {
      throw new UnknownHostException(host + ": no DNS servers configured");
    }
    UnknownHostException failure = null;
    for (String name : candidates(host)) {
      failure = null;
      List<InetAddress> addresses = new ArrayList<>();
      try {
        addresses.addAll(query(name, DnsMessage.TYPE_A));
      } catch (UnknownHostException e) {
        failure = e;
      }
      addresses.addAll(queryQuietly(name, DnsMessage.TYPE_AAAA));
      if (!addresses.isEmpty()) {
        return List.copyOf(addresses);
      }
      if (failure == null) {
        failure = new UnknownHostException(host + ": no addresses");
      }
    }
    throw failure;
  }

  private List<InetAddress> queryQuietly(String name, int type) {
    try {
      return query(name, type);
    } catch (UnknownHostException e) {
      return List.of();
    }
  }

  private List<String> candidates(String host) {
    List<String> out = new ArrayList<>();
    if (host.endsWith(".")) {
      out.add(host.substring(0, host.length() - 1));
      return out;
    }
    List<String> searched = new ArrayList<>();
    for (String d : searchDomains) {
      searched.add(host + "." + d);
    }
    if (host.contains(".")) {
      out.add(host);
      out.addAll(searched);
    } else {
      out.addAll(searched);
      out.add(host);
    }
    return out;
  }

  /** Queries the servers in turn; an empty list means the name exists without such records. */
  private List<InetAddress> query(String name, int type) throws UnknownHostException {
    byte[] probe = DnsMessage.query(0, name, type); // validates the name up front
    String lastError = "no response";
    for (InetAddress server : servers) {
      InetSocketAddress target = new InetSocketAddress(server, DNS_PORT);
      for (int attempt = 0; attempt < ATTEMPTS_PER_SERVER; attempt++) {
        int id = random.nextInt(0x10000);
        byte[] query = probe.clone();
        query[0] = (byte) (id >>> 8);
        query[1] = (byte) id;
        try (UdpSocket socket = stack.openUdp()) {
          socket.send(target, query);
          long deadline = System.nanoTime() + timeout.toNanos();
          while (true) {
            long left = deadline - System.nanoTime();
            if (left <= 0) {
              break;
            }
            UdpSocket.Datagram d = socket.receive(Duration.ofNanos(left));
            if (d == null) {
              break;
            }
            if (!d.source().equals(target)) {
              continue;
            }
            DnsMessage.Response r = DnsMessage.parse(d.data(), id, name, type);
            if (r == null) {
              continue;
            }
            if (r.rcode() == DnsMessage.RCODE_NXDOMAIN) {
              throw new UnknownHostException(name + ": no such domain");
            }
            if (r.rcode() != DnsMessage.RCODE_OK) {
              lastError = "server " + server.getHostAddress() + " returned rcode " + r.rcode();
              attempt = ATTEMPTS_PER_SERVER; // try the next server
              break;
            }
            if (r.truncated() && r.addresses().isEmpty()) {
              throw new UnknownHostException(
                  name + ": truncated DNS answer (TCP not supported yet)");
            }
            return r.addresses();
          }
        } catch (IOException e) {
          lastError = e.toString();
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
          throw new UnknownHostException(name + ": interrupted");
        }
      }
    }
    throw new UnknownHostException(name + ": " + lastError);
  }
}
