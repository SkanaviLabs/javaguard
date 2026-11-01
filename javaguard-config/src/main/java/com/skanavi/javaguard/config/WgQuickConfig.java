// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.config;

import com.skanavi.javaguard.core.Addresses;
import com.skanavi.javaguard.core.Device;
import com.skanavi.javaguard.core.IpPrefix;
import com.skanavi.javaguard.core.PeerConfig;
import com.skanavi.javaguard.crypto.PresharedKey;
import com.skanavi.javaguard.crypto.PrivateKey;
import com.skanavi.javaguard.crypto.PublicKey;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * A wg-quick style configuration: one {@code [Interface]} section and any number of {@code [Peer]}
 * sections.
 *
 * <p>Keys that make wg-quick change the operating system ({@code Table}, {@code PreUp}, {@code
 * PostUp}, {@code PreDown}, {@code PostDown}, {@code SaveConfig}) and {@code FwMark} have no
 * meaning for an embedded tunnel. {@link #parse(String)} rejects them; {@link #parseLenient(String,
 * List)} skips them and reports a warning instead. {@code Address} and {@code DNS} are kept for the
 * userspace network stack.
 *
 * @param iface the {@code [Interface]} section
 * @param peers the {@code [Peer]} sections, in file order
 */
public record WgQuickConfig(InterfaceSection iface, List<PeerSection> peers) {
  private static final Set<String> OS_KEYS =
      Set.of("fwmark", "table", "preup", "postup", "predown", "postdown", "saveconfig");

  /** Copies the peer list. */
  public WgQuickConfig {
    Objects.requireNonNull(iface, "iface");
    peers = List.copyOf(peers);
  }

  /**
   * The {@code [Interface]} section.
   *
   * @param privateKey the device private key
   * @param listenPort the UDP port, or {@code null} for a random one
   * @param addresses tunnel addresses ({@code Address}), for the network stack
   * @param dns DNS servers ({@code DNS} entries that are IP addresses)
   * @param dnsSearch DNS search domains ({@code DNS} entries that are not IP addresses)
   * @param mtu the tunnel MTU, or {@code null} for the default
   */
  public record InterfaceSection(
      PrivateKey privateKey,
      Integer listenPort,
      List<IpPrefix> addresses,
      List<InetAddress> dns,
      List<String> dnsSearch,
      Integer mtu) {
    /** Validates and copies lists. */
    public InterfaceSection {
      Objects.requireNonNull(privateKey, "privateKey");
      addresses = List.copyOf(addresses);
      dns = List.copyOf(dns);
      dnsSearch = List.copyOf(dnsSearch);
    }
  }

  /**
   * A {@code [Peer]} section.
   *
   * @param publicKey the peer public key
   * @param presharedKey the pre-shared key, {@link PresharedKey#NONE} if unset
   * @param endpoint the endpoint as written, resolved by {@link #resolve()}, or {@code null}
   * @param allowedIps the allowed IP prefixes
   * @param persistentKeepalive the keepalive interval, zero if off
   */
  public record PeerSection(
      PublicKey publicKey,
      PresharedKey presharedKey,
      Endpoint endpoint,
      List<IpPrefix> allowedIps,
      Duration persistentKeepalive) {
    /** Validates and copies lists. */
    public PeerSection {
      Objects.requireNonNull(publicKey, "publicKey");
      Objects.requireNonNull(presharedKey, "presharedKey");
      allowedIps = List.copyOf(allowedIps);
    }

    /** Resolves the endpoint (which may need DNS) and builds the core peer configuration. */
    public PeerConfig resolve() throws UnknownHostException {
      return new PeerConfig(
          publicKey,
          presharedKey,
          endpoint == null ? null : endpoint.resolve(),
          allowedIps,
          persistentKeepalive);
    }
  }

  /**
   * An unresolved endpoint as written in a file.
   *
   * @param host a host name or IP literal (IPv6 without brackets)
   * @param port the UDP port
   */
  public record Endpoint(String host, int port) {
    /** Parses {@code host:port} or {@code [v6]:port}. */
    public static Endpoint parse(String text) {
      String s = text.strip();
      String host;
      String port;
      if (s.startsWith("[")) {
        int close = s.indexOf(']');
        if (close < 0 || close + 1 >= s.length() || s.charAt(close + 1) != ':') {
          throw new IllegalArgumentException("invalid endpoint: " + text);
        }
        host = s.substring(1, close);
        port = s.substring(close + 2);
      } else {
        int colon = s.lastIndexOf(':');
        if (colon <= 0 || s.indexOf(':') != colon) {
          throw new IllegalArgumentException("invalid endpoint: " + text);
        }
        host = s.substring(0, colon);
        port = s.substring(colon + 1);
      }
      return new Endpoint(host, parseInt(port, 1, 65535, "endpoint port"));
    }

    /** Resolves the host, preferring the first address returned. */
    public InetSocketAddress resolve() throws UnknownHostException {
      return new InetSocketAddress(InetAddress.getByName(host), port);
    }

    @Override
    public String toString() {
      return (host.contains(":") ? "[" + host + "]" : host) + ":" + port;
    }
  }

  /** Parses a file; see {@link #parse(String)}. */
  public static WgQuickConfig parse(Path file) throws IOException, ConfigException {
    return parse(Files.readString(file, StandardCharsets.UTF_8));
  }

  /**
   * Parses configuration text, rejecting keys javaguard cannot honour.
   *
   * @throws ConfigException on any syntax error, unknown key, invalid value, or OS-level key
   */
  public static WgQuickConfig parse(String text) throws ConfigException {
    return new Parser(null).parse(text);
  }

  /**
   * Parses configuration text, skipping OS-level keys javaguard cannot honour and adding a message
   * for each to {@code warnings}.
   */
  public static WgQuickConfig parseLenient(String text, List<String> warnings)
      throws ConfigException {
    return new Parser(Objects.requireNonNull(warnings)).parse(text);
  }

  /** Resolves every peer; see {@link PeerSection#resolve()}. */
  public List<PeerConfig> resolvePeers() throws UnknownHostException {
    List<PeerConfig> out = new ArrayList<>();
    for (PeerSection p : peers) {
      out.add(p.resolve());
    }
    return out;
  }

  /** Adds every peer to {@code device}, resolving endpoints. */
  public void addPeersTo(Device device) throws UnknownHostException {
    for (PeerConfig p : resolvePeers()) {
      device.addPeer(p);
    }
  }

  /** Formats this configuration in wg-quick syntax, including the private key. */
  public String format() {
    StringBuilder sb = new StringBuilder("[Interface]\n");
    sb.append("PrivateKey = ").append(iface.privateKey().toBase64()).append('\n');
    if (iface.listenPort() != null) {
      sb.append("ListenPort = ").append(iface.listenPort()).append('\n');
    }
    if (!iface.addresses().isEmpty()) {
      sb.append("Address = ").append(join(iface.addresses())).append('\n');
    }
    if (!iface.dns().isEmpty() || !iface.dnsSearch().isEmpty()) {
      List<String> entries = new ArrayList<>();
      iface.dns().forEach(a -> entries.add(Addresses.format(a)));
      entries.addAll(iface.dnsSearch());
      sb.append("DNS = ").append(String.join(", ", entries)).append('\n');
    }
    if (iface.mtu() != null) {
      sb.append("MTU = ").append(iface.mtu()).append('\n');
    }
    for (PeerSection p : peers) {
      sb.append("\n[Peer]\n");
      sb.append("PublicKey = ").append(p.publicKey().toBase64()).append('\n');
      if (!p.presharedKey().isZero()) {
        sb.append("PresharedKey = ").append(p.presharedKey().toBase64()).append('\n');
      }
      if (!p.allowedIps().isEmpty()) {
        sb.append("AllowedIPs = ").append(join(p.allowedIps())).append('\n');
      }
      if (p.endpoint() != null) {
        sb.append("Endpoint = ").append(p.endpoint()).append('\n');
      }
      if (!p.persistentKeepalive().isZero()) {
        sb.append("PersistentKeepalive = ")
            .append(p.persistentKeepalive().toSeconds())
            .append('\n');
      }
    }
    return sb.toString();
  }

  private static String join(List<?> items) {
    List<String> s = new ArrayList<>();
    items.forEach(i -> s.add(i.toString()));
    return String.join(", ", s);
  }

  static int parseInt(String value, int min, int max, String what) {
    try {
      int v = Integer.parseInt(value.strip());
      if (v < min || v > max) {
        throw new IllegalArgumentException(what + " must be " + min + ".." + max);
      }
      return v;
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException("invalid " + what + ": " + value, e);
    }
  }

  private static final class Parser {
    private final List<String> warnings;
    private String section;
    private int lineNo;

    // [Interface] state
    private boolean sawInterface;
    private PrivateKey privateKey;
    private Integer listenPort;
    private final List<IpPrefix> addresses = new ArrayList<>();
    private final List<InetAddress> dns = new ArrayList<>();
    private final List<String> dnsSearch = new ArrayList<>();
    private Integer mtu;

    // current [Peer] state
    private final List<PeerSection> peers = new ArrayList<>();
    private int peerLine;
    private PublicKey publicKey;
    private PresharedKey presharedKey;
    private Endpoint endpoint;
    private List<IpPrefix> allowedIps;
    private Duration keepalive;

    Parser(List<String> warnings) {
      this.warnings = warnings;
    }

    WgQuickConfig parse(String text) throws ConfigException {
      String[] lines = text.split("\r?\n", -1);
      for (lineNo = 1; lineNo <= lines.length; lineNo++) {
        String line = lines[lineNo - 1];
        int hash = line.indexOf('#');
        if (hash >= 0) {
          line = line.substring(0, hash);
        }
        line = line.strip();
        if (line.isEmpty()) {
          continue;
        }
        try {
          if (line.startsWith("[")) {
            startSection(line);
          } else {
            int eq = line.indexOf('=');
            if (eq <= 0) {
              throw new IllegalArgumentException("expected Key = Value");
            }
            String key = line.substring(0, eq).strip().toLowerCase(Locale.ROOT);
            String value = line.substring(eq + 1).strip();
            if (section == null) {
              throw new IllegalArgumentException("key outside of a section");
            } else if (section.equals("interface")) {
              interfaceKey(key, value);
            } else {
              peerKey(key, value);
            }
          }
        } catch (IllegalArgumentException e) {
          throw new ConfigException(lineNo, e.getMessage());
        }
      }
      finishPeer();
      if (!sawInterface) {
        throw new ConfigException(0, "missing [Interface] section");
      }
      if (privateKey == null) {
        throw new ConfigException(0, "[Interface] has no PrivateKey");
      }
      return new WgQuickConfig(
          new InterfaceSection(privateKey, listenPort, addresses, dns, dnsSearch, mtu), peers);
    }

    private void startSection(String line) throws ConfigException {
      if (!line.endsWith("]")) {
        throw new IllegalArgumentException("malformed section header");
      }
      String name = line.substring(1, line.length() - 1).strip().toLowerCase(Locale.ROOT);
      finishPeer();
      switch (name) {
        case "interface" -> {
          if (sawInterface) {
            throw new IllegalArgumentException("duplicate [Interface] section");
          }
          sawInterface = true;
        }
        case "peer" -> {
          peerLine = lineNo;
          allowedIps = new ArrayList<>();
        }
        default -> throw new IllegalArgumentException("unknown section [" + name + "]");
      }
      section = name;
    }

    private void interfaceKey(String key, String value) {
      switch (key) {
        case "privatekey" -> privateKey = PrivateKey.fromBase64(value);
        case "listenport" -> listenPort = parseInt(value, 0, 65535, "ListenPort");
        case "address" -> list(value).forEach(v -> addresses.add(IpPrefix.parse(v)));
        case "dns" ->
            list(value)
                .forEach(
                    v -> {
                      try {
                        dns.add(InetAddress.ofLiteral(v));
                      } catch (IllegalArgumentException e) {
                        dnsSearch.add(v);
                      }
                    });
        case "mtu" -> mtu = parseInt(value, 576, 65535, "MTU");
        default -> unsupported(key);
      }
    }

    private void peerKey(String key, String value) {
      switch (key) {
        case "publickey" -> publicKey = PublicKey.fromBase64(value);
        case "presharedkey" -> presharedKey = PresharedKey.fromBase64(value);
        case "endpoint" -> endpoint = Endpoint.parse(value);
        case "allowedips" -> list(value).forEach(v -> allowedIps.add(IpPrefix.parse(v)));
        case "persistentkeepalive" ->
            keepalive =
                value.equalsIgnoreCase("off")
                    ? Duration.ZERO
                    : Duration.ofSeconds(parseInt(value, 0, 65535, "PersistentKeepalive"));
        default -> unsupported(key);
      }
    }

    private void unsupported(String key) {
      if (!OS_KEYS.contains(key)) {
        throw new IllegalArgumentException("unknown key '" + key + "' in [" + section + "]");
      }
      String message = key + " is not supported: javaguard does not configure the operating system";
      if (warnings == null) {
        throw new IllegalArgumentException(message);
      }
      warnings.add("line " + lineNo + ": " + message + "; ignored");
    }

    private void finishPeer() throws ConfigException {
      if (!"peer".equals(section)) {
        return;
      }
      if (publicKey == null) {
        throw new ConfigException(peerLine, "[Peer] has no PublicKey");
      }
      peers.add(
          new PeerSection(
              publicKey,
              presharedKey == null ? PresharedKey.NONE : presharedKey,
              endpoint,
              allowedIps,
              keepalive == null ? Duration.ZERO : keepalive));
      publicKey = null;
      presharedKey = null;
      endpoint = null;
      allowedIps = null;
      keepalive = null;
      section = null;
    }

    private static List<String> list(String value) {
      List<String> out = new ArrayList<>();
      for (String part : value.split(",")) {
        String p = part.strip();
        if (!p.isEmpty()) {
          out.add(p);
        }
      }
      return out;
    }
  }
}
