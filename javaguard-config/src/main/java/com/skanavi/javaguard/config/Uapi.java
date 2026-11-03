// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.config;

// Portions derived from wireguard-go (https://git.zx2c4.com/wireguard-go/),
// Copyright (C) 2017-2025 WireGuard LLC. MIT.

import com.skanavi.javaguard.core.Addresses;
import com.skanavi.javaguard.core.Bind;
import com.skanavi.javaguard.core.Device;
import com.skanavi.javaguard.core.IpPrefix;
import com.skanavi.javaguard.core.Peer;
import com.skanavi.javaguard.core.PeerConfig;
import com.skanavi.javaguard.crypto.PresharedKey;
import com.skanavi.javaguard.crypto.PrivateKey;
import com.skanavi.javaguard.crypto.PublicKey;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.Writer;
import java.net.BindException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * The cross-platform userspace configuration protocol ({@code get=1} / {@code set=1}, see
 * wireguard.com/xplatform) for one {@link Device}. Transport-independent; {@link UapiServer} serves
 * it on a Unix domain socket.
 *
 * <p>Errors are reported as positive Linux {@code errno} values. {@code fwmark} can only be 0,
 * since a JVM cannot mark sockets. Thread-safe: operations are serialized.
 */
public final class Uapi {
  /** Opens a UDP bind on a port, for {@code listen_port} changes. */
  @FunctionalInterface
  public interface BindFactory {
    /** Opens a bind on {@code port}. */
    Bind open(int port) throws IOException;
  }

  static final int EIO = 5;
  static final int EINVAL = 22;
  static final int EPROTO = 71;
  static final int EADDRINUSE = 98;

  private static final int MAX_REQUEST_LINES = 100_000;
  private static final int MAX_LINE_LENGTH = 64 * 1024;

  private final Device device;
  private final BindFactory bindFactory;

  /** Creates a protocol handler for {@code device}; {@code listen_port} changes use the factory. */
  public Uapi(Device device, BindFactory bindFactory) {
    this.device = device;
    this.bindFactory = bindFactory;
  }

  /**
   * Serves requests from {@code in} until end of stream, writing responses to {@code out}. An
   * unknown operation is answered with {@code errno} and ends the exchange.
   */
  public void serve(BufferedReader in, Writer out) throws IOException {
    String op;
    while ((op = readLine(in)) != null) {
      if (op.isEmpty()) {
        continue;
      }
      List<String> body = readUntilBlank(in);
      switch (op) {
        case "get=1" -> {
          out.write(body == null || !body.isEmpty() ? errno(EPROTO) : get());
        }
        case "set=1" -> out.write(body == null ? errno(EPROTO) : errno(set(body)));
        default -> {
          out.write(errno(EINVAL));
          out.flush();
          return;
        }
      }
      out.flush();
    }
  }

  /** The {@code get=1} response, including the trailing {@code errno=0} and blank line. */
  public synchronized String get() {
    StringBuilder sb = new StringBuilder();
    sb.append("private_key=").append(device.privateKey().toHex()).append('\n');
    sb.append("listen_port=").append(device.listenPort()).append('\n');
    for (Peer p : device.peers()) {
      sb.append("public_key=").append(p.publicKey().toHex()).append('\n');
      sb.append("preshared_key=").append(p.presharedKey().toHex()).append('\n');
      sb.append("protocol_version=1\n");
      p.endpoint().ifPresent(e -> sb.append("endpoint=").append(Addresses.format(e)).append('\n'));
      Instant hs = p.lastHandshake().orElse(Instant.EPOCH);
      sb.append("last_handshake_time_sec=").append(hs.getEpochSecond()).append('\n');
      sb.append("last_handshake_time_nsec=").append(hs.getNano()).append('\n');
      sb.append("tx_bytes=").append(p.txBytes()).append('\n');
      sb.append("rx_bytes=").append(p.rxBytes()).append('\n');
      sb.append("persistent_keepalive_interval=")
          .append(p.persistentKeepalive().toSeconds())
          .append('\n');
      for (IpPrefix ip : p.allowedIps()) {
        sb.append("allowed_ip=").append(ip).append('\n');
      }
    }
    return sb.append("errno=0\n\n").toString();
  }

  /**
   * Applies a {@code set=1} request body (without the operation line and blank terminator). Changes
   * before an invalid line stay applied, as in the reference implementation.
   *
   * @return 0 on success, otherwise an errno value
   */
  public synchronized int set(List<String> lines) {
    PeerChange peer = null;
    Set<PublicKey> seen = new HashSet<>();
    try {
      for (String line : lines) {
        int eq = line.indexOf('=');
        if (eq <= 0) {
          return EPROTO;
        }
        String key = line.substring(0, eq);
        String value = line.substring(eq + 1);
        if (key.equals("public_key")) {
          PublicKey pk = PublicKey.fromHex(value);
          if (!seen.add(pk)) {
            return EINVAL;
          }
          if (peer != null) {
            peer.apply();
          }
          peer = new PeerChange(pk);
        } else if (peer == null) {
          setDevice(key, value);
        } else {
          peer.add(key, value);
        }
      }
      if (peer != null) {
        peer.apply();
      }
      return 0;
    } catch (IllegalArgumentException e) {
      return EINVAL;
    } catch (BindException e) {
      return EADDRINUSE;
    } catch (IOException e) {
      return EIO;
    }
  }

  private void setDevice(String key, String value) throws IOException {
    switch (key) {
      case "private_key" -> {
        PrivateKey k = PrivateKey.fromHex(value);
        if (k.isZero()) {
          throw new IllegalArgumentException("a javaguard device always has a private key");
        }
        device.privateKey(k);
      }
      case "listen_port" -> {
        int port = WgQuickConfig.parseInt(value, 0, 65535, "listen_port");
        if (port != 0 && port != device.listenPort()) {
          device.bind(bindFactory.open(port));
        }
      }
      case "fwmark" -> {
        if (WgQuickConfig.parseInt(value, 0, Integer.MAX_VALUE, "fwmark") != 0) {
          throw new IllegalArgumentException("fwmark is not supported");
        }
      }
      case "replace_peers" -> {
        requireTrue(value);
        for (Peer p : device.peers()) {
          device.removePeer(p.publicKey());
        }
      }
      default -> throw new IllegalArgumentException("unknown device key " + key);
    }
  }

  /** Buffered peer lines, applied once the whole peer block is known (for update_only). */
  private final class PeerChange {
    private final PublicKey key;
    private final List<String[]> ops = new ArrayList<>();
    private boolean remove;
    private boolean updateOnly;

    PeerChange(PublicKey key) {
      this.key = key;
    }

    void add(String k, String v) {
      switch (k) {
        case "remove" -> {
          requireTrue(v);
          remove = true;
        }
        case "update_only" -> {
          requireTrue(v);
          updateOnly = true;
        }
        case "protocol_version" -> {
          if (!v.equals("1")) {
            throw new IllegalArgumentException("unsupported protocol version " + v);
          }
        }
        case "preshared_key", "endpoint", "persistent_keepalive_interval", "allowed_ip" -> {
          validate(k, v);
          ops.add(new String[] {k, v});
        }
        case "replace_allowed_ips" -> {
          requireTrue(v);
          ops.add(new String[] {k, v});
        }
        default -> throw new IllegalArgumentException("unknown peer key " + k);
      }
    }

    private void validate(String k, String v) {
      switch (k) {
        case "preshared_key" -> PresharedKey.fromHex(v);
        case "endpoint" -> Addresses.parseEndpoint(v);
        case "persistent_keepalive_interval" ->
            WgQuickConfig.parseInt(v, 0, 65535, "persistent_keepalive_interval");
        default -> IpPrefix.parse(v.startsWith("-") ? v.substring(1) : v);
      }
    }

    void apply() {
      if (remove) {
        device.removePeer(key);
        return;
      }
      Peer p = device.peer(key);
      if (p == null) {
        if (updateOnly) {
          return;
        }
        p = device.addPeer(PeerConfig.builder(key).build());
      }
      for (String[] op : ops) {
        String v = op[1];
        switch (op[0]) {
          case "preshared_key" -> p.presharedKey(PresharedKey.fromHex(v));
          case "endpoint" -> p.endpoint(Addresses.parseEndpoint(v));
          case "persistent_keepalive_interval" ->
              p.persistentKeepalive(Duration.ofSeconds(Integer.parseInt(v)));
          case "replace_allowed_ips" -> p.allowedIps(List.of());
          default -> {
            if (v.startsWith("-")) {
              p.removeAllowedIp(IpPrefix.parse(v.substring(1)));
            } else {
              p.addAllowedIp(IpPrefix.parse(v));
            }
          }
        }
      }
    }
  }

  private static void requireTrue(String value) {
    if (!value.equals("true")) {
      throw new IllegalArgumentException("expected true, got " + value);
    }
  }

  /** Reads lines up to a blank line; {@code null} if the stream ends first or is too long. */
  private static List<String> readUntilBlank(BufferedReader in) throws IOException {
    List<String> lines = new ArrayList<>();
    String line;
    while ((line = readLine(in)) != null) {
      if (line.isEmpty()) {
        return lines;
      }
      if (lines.size() >= MAX_REQUEST_LINES) {
        return null;
      }
      lines.add(line);
    }
    return null;
  }

  /** Reads one line of at most 64 KiB; {@code null} at end of stream. */
  private static String readLine(BufferedReader in) throws IOException {
    StringBuilder sb = new StringBuilder();
    int c;
    while ((c = in.read()) >= 0) {
      if (c == '\n') {
        int end = sb.length();
        return end > 0 && sb.charAt(end - 1) == '\r' ? sb.substring(0, end - 1) : sb.toString();
      }
      if (sb.length() >= MAX_LINE_LENGTH) {
        throw new IOException("UAPI line longer than " + MAX_LINE_LENGTH + " characters");
      }
      sb.append((char) c);
    }
    return sb.length() == 0 ? null : sb.toString();
  }

  private static String errno(int code) {
    return "errno=" + code + "\n\n";
  }
}
