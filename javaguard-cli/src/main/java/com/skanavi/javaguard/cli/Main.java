// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.cli;

import com.skanavi.javaguard.config.ConfigException;
import com.skanavi.javaguard.config.UapiServer;
import com.skanavi.javaguard.config.WgQuickConfig;
import com.skanavi.javaguard.core.Device;
import com.skanavi.javaguard.core.IpPrefix;
import com.skanavi.javaguard.core.PacketPipe;
import com.skanavi.javaguard.core.PeerConfig;
import com.skanavi.javaguard.core.Tun;
import com.skanavi.javaguard.core.UdpBind;
import com.skanavi.javaguard.crypto.PresharedKey;
import com.skanavi.javaguard.crypto.PrivateKey;
import com.skanavi.javaguard.netstack.Netstack;
import com.skanavi.javaguard.proxy.LocalProxy;
import com.skanavi.javaguard.tun.HostNetwork;
import com.skanavi.javaguard.tun.LinuxTun;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/** Entry point of the {@code javaguard} command. */
public final class Main {
  private static final String USAGE =
      """
      Usage: javaguard <command> [options]

      Commands:
        genkey                 print a new private key (base64)
        genpsk                 print a new pre-shared key (base64)
        pubkey                 read a private key on stdin, print its public key
        up <file.conf>         run a device from a wg-quick style configuration
          --name <name>        interface name (default: file name without .conf)
          --socket <path>      UAPI socket (default: /var/run/wireguard/<name>.sock)
          --no-uapi            do not serve the UAPI socket
          --lenient            ignore keys this mode cannot honour instead of failing
          --proxy [host:]port  serve a SOCKS5/HTTP proxy into the tunnel (needs Address);
                               binds 127.0.0.1 unless a host is given
          --proxy-auth u:p     require these proxy credentials
          --tun                create a real network interface instead of a userspace
                               stack (Linux; needs root or CAP_NET_ADMIN)
          --allow-hooks        with --tun, run PreUp/PostUp/PreDown/PostDown commands
        help                   show this text

      'up' runs until interrupted or until its UAPI socket is deleted. Use the
      standard wg(8) tool to inspect and change it: wg show <name>. If the
      configuration has an Address, a userspace network stack with that address
      answers pings inside the tunnel.

      With --tun, the interface gets the Address, MTU and DNS from the file, and a
      route for every AllowedIPs prefix (Table = off for none, or a table number).
      Routes that would carry all traffic (0.0.0.0/0, ::/0) are not supported yet.
      Every program on the host can then use the tunnel directly.
      """;

  private Main() {}

  /** Runs the command and exits with its status. */
  public static void main(String[] args) {
    System.exit(run(args, System.in, System.out, System.err));
  }

  static int run(String[] args, InputStream in, PrintStream out, PrintStream err) {
    if (args.length == 0) {
      err.print(USAGE);
      return 2;
    }
    try {
      return switch (args[0]) {
        case "genkey" -> {
          out.println(PrivateKey.generate().toBase64());
          yield 0;
        }
        case "genpsk" -> {
          out.println(PresharedKey.generate().toBase64());
          yield 0;
        }
        case "pubkey" -> {
          String text = new String(in.readAllBytes(), StandardCharsets.US_ASCII).strip();
          out.println(PrivateKey.fromBase64(text).publicKey().toBase64());
          yield 0;
        }
        case "up" -> up(args, err);
        case "help", "-h", "--help" -> {
          out.print(USAGE);
          yield 0;
        }
        default -> {
          err.println("javaguard: unknown command '" + args[0] + "'");
          err.print(USAGE);
          yield 2;
        }
      };
    } catch (IllegalArgumentException e) {
      err.println("javaguard: " + e.getMessage());
      return 1;
    } catch (ConfigException e) {
      err.println("javaguard: configuration error: " + e.getMessage());
      return 1;
    } catch (IOException e) {
      err.println("javaguard: " + e);
      return 1;
    }
  }

  private static int up(String[] args, PrintStream err) throws IOException, ConfigException {
    Path file = null;
    String name = null;
    Path socket = null;
    boolean uapi = true;
    boolean lenient = false;
    String proxySpec = null;
    String proxyAuth = null;
    boolean tunMode = false;
    boolean allowHooks = false;
    for (int i = 1; i < args.length; i++) {
      switch (args[i]) {
        case "--name" -> name = value(args, ++i, "--name");
        case "--socket" -> socket = Path.of(value(args, ++i, "--socket"));
        case "--no-uapi" -> uapi = false;
        case "--lenient" -> lenient = true;
        case "--proxy" -> proxySpec = value(args, ++i, "--proxy");
        case "--proxy-auth" -> proxyAuth = value(args, ++i, "--proxy-auth");
        case "--tun" -> tunMode = true;
        case "--allow-hooks" -> allowHooks = true;
        default -> {
          if (args[i].startsWith("-") || file != null) {
            throw new IllegalArgumentException("unexpected argument '" + args[i] + "'");
          }
          file = Path.of(args[i]);
        }
      }
    }
    if (file == null) {
      throw new IllegalArgumentException("up needs a configuration file");
    }
    if (name == null) {
      name = file.getFileName().toString().replaceFirst("\\.conf$", "");
    }
    if (!name.matches("[A-Za-z0-9_.=+-]{1,15}")) {
      throw new IllegalArgumentException("invalid interface name '" + name + "'");
    }

    if (tunMode) {
      if (!LinuxTun.isSupported()) {
        throw new IllegalArgumentException(
            "--tun is not supported on "
                + System.getProperty("os.name")
                + " "
                + System.getProperty("os.arch")
                + " yet; it needs Linux on x86_64 or aarch64");
      }
      if (proxySpec != null) {
        throw new IllegalArgumentException(
            "--proxy needs the userspace network stack and cannot be combined with --tun");
      }
    } else if (allowHooks) {
      throw new IllegalArgumentException("--allow-hooks only applies with --tun");
    }

    String text = Files.readString(file, StandardCharsets.UTF_8);
    List<String> warnings = new ArrayList<>();
    WgQuickConfig config =
        tunMode
            ? WgQuickConfig.parseForHost(text)
            : lenient ? WgQuickConfig.parseLenient(text, warnings) : WgQuickConfig.parse(text);
    if (tunMode) {
      checkHostKeys(config.host(), lenient, allowHooks, warnings);
    }
    warnings.forEach(w -> err.println("javaguard: warning: " + w));

    int mtu = config.iface().mtu() != null ? config.iface().mtu() : 1420;
    int port = config.iface().listenPort() != null ? config.iface().listenPort() : 0;
    if (proxySpec != null && config.iface().addresses().isEmpty()) {
      throw new IllegalArgumentException("--proxy needs an Address in [Interface]");
    }
    InetSocketAddress proxyBind = proxySpec == null ? null : parseBind(proxySpec);
    if (proxyAuth != null && !proxyAuth.contains(":")) {
      throw new IllegalArgumentException("--proxy-auth must be user:password");
    }
    List<PeerConfig> peers = config.resolvePeers();
    HostNetwork host = null;
    Tun tun;
    PacketPipe pipe = null;
    Netstack stack = null;
    if (tunMode) {
      host = hostNetwork(name, mtu, config, peers, allowHooks, err);
      host.preUp();
      tun = LinuxTun.open(name, mtu);
    } else if (config.iface().addresses().isEmpty()) {
      tun = pipe = new PacketPipe(mtu);
    } else {
      tun =
          stack =
              Netstack.builder()
                  .addresses(config.iface().addresses())
                  .dnsServers(config.iface().dns())
                  .searchDomains(config.iface().dnsSearch())
                  .mtu(mtu)
                  .build();
    }
    Device device;
    try {
      device =
          Device.builder()
              .privateKey(config.iface().privateKey())
              .bind(UdpBind.open(port))
              .tun(tun)
              .build();
    } catch (IOException | RuntimeException e) {
      tun.close();
      throw e;
    }
    UapiServer server = null;
    LocalProxy proxy = null;
    try {
      peers.forEach(device::addPeer);
      device.start();
      if (host != null) {
        host.up();
      }
      if (proxyBind != null) {
        LocalProxy.Builder pb = LocalProxy.builder(stack).bind(proxyBind);
        if (proxyAuth != null) {
          int c = proxyAuth.indexOf(':');
          pb.credentials(proxyAuth.substring(0, c), proxyAuth.substring(c + 1));
        }
        proxy = pb.build();
      }
      if (uapi) {
        server =
            UapiServer.start(
                device, UdpBind::open, socket != null ? socket : UapiServer.defaultPath(name));
      }
    } catch (IOException | RuntimeException e) {
      if (proxy != null) {
        proxy.close();
      }
      if (host != null) {
        host.down();
      }
      device.close();
      if (host != null) {
        host.postDown();
      }
      throw e;
    }

    Thread drain = pipe == null ? null : drain(pipe);
    UapiServer finalServer = server;
    LocalProxy finalProxy = proxy;
    HostNetwork finalHost = host;
    Runtime.getRuntime()
        .addShutdownHook(
            new Thread(
                () -> shutdown(device, finalServer, finalProxy, finalHost, drain),
                "javaguard-exit"));

    err.println(
        "javaguard: "
            + name
            + " up: public key "
            + device.publicKey().toBase64()
            + ", UDP port "
            + device.listenPort()
            + (server != null ? ", UAPI " + server.path() : ""));
    if (tunMode) {
      err.println(
          "javaguard: interface "
              + name
              + " up"
              + (config.iface().addresses().isEmpty() ? "" : " at " + config.iface().addresses()));
    } else if (pipe != null) {
      err.println(
          "javaguard: no Address configured, so no network stack: packets arriving through the"
              + " tunnel are discarded");
    } else {
      err.println("javaguard: network stack up at " + config.iface().addresses());
    }
    if (proxy != null) {
      err.println(
          "javaguard: SOCKS5/HTTP proxy on "
              + proxy.address().getAddress().getHostAddress()
              + ":"
              + proxy.address().getPort()
              + (proxyAuth == null ? "" : " (authentication required)"));
      if (!proxy.address().getAddress().isLoopbackAddress() && proxyAuth == null) {
        err.println(
            "javaguard: warning: the proxy is reachable from the network without a password");
      }
    }

    try {
      while (server == null || server.socketExists()) {
        Thread.sleep(1000);
      }
      err.println("javaguard: UAPI socket removed, shutting down");
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
    shutdown(device, server, proxy, host, drain);
    return 0;
  }

  /** Discards packets that come out of the tunnel when there is no network stack. */
  private static Thread drain(PacketPipe pipe) {
    return Thread.ofVirtual()
        .start(
            () -> {
              try {
                while (!Thread.currentThread().isInterrupted()) {
                  pipe.receive(Duration.ofSeconds(1));
                }
              } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
              }
            });
  }

  /** Rejects or skips OS-level keys that --tun mode does not support yet. */
  private static void checkHostKeys(
      WgQuickConfig.HostSettings h, boolean lenient, boolean allowHooks, List<String> warnings) {
    List<String> problems = new ArrayList<>();
    if (h.fwMark() != null) {
      problems.add("FwMark is not supported yet (it needs a mark on the UDP socket)");
    }
    if (h.saveConfig()) {
      problems.add("SaveConfig is not supported");
    }
    if (h.hasHooks() && !allowHooks) {
      problems.add(
          "the configuration has PreUp/PostUp/PreDown/PostDown commands; pass --allow-hooks to"
              + " run them");
    }
    if (!problems.isEmpty() && !lenient) {
      throw new IllegalArgumentException(String.join("; ", problems));
    }
    problems.forEach(p -> warnings.add(p + "; ignored"));
  }

  private static HostNetwork hostNetwork(
      String name,
      int mtu,
      WgQuickConfig config,
      List<PeerConfig> peers,
      boolean allowHooks,
      PrintStream err) {
    List<IpPrefix> routes = new ArrayList<>();
    List<InetAddress> endpoints = new ArrayList<>();
    for (PeerConfig p : peers) {
      routes.addAll(p.allowedIps());
      if (p.endpoint() != null) {
        endpoints.add(p.endpoint().getAddress());
      }
    }
    WgQuickConfig.HostSettings h = config.host();
    HostNetwork.Builder b =
        HostNetwork.builder(name)
            .mtu(mtu)
            .addresses(config.iface().addresses())
            .routes(routes)
            .endpoints(endpoints)
            .table(h.table())
            .dns(config.iface().dns(), config.iface().dnsSearch())
            .warnings(w -> err.println("javaguard: warning: " + w));
    if (allowHooks) {
      b.hooks(h.preUp(), h.postUp(), h.preDown(), h.postDown());
    }
    return b.build();
  }

  private static void shutdown(
      Device device, UapiServer server, LocalProxy proxy, HostNetwork host, Thread drain) {
    if (drain != null) {
      drain.interrupt();
    }
    try {
      if (proxy != null) {
        proxy.close();
      }
      if (server != null) {
        server.close();
      }
      if (host != null) {
        host.down();
      }
      device.close(); // closing a LinuxTun removes the interface and its routes
    } catch (IOException e) {
      // exiting anyway
    }
    if (host != null) {
      host.postDown();
    }
  }

  /** Parses {@code port}, {@code host:port} or {@code [v6]:port}; host defaults to loopback. */
  static InetSocketAddress parseBind(String spec) {
    try {
      if (spec.matches("\\d+")) {
        return new InetSocketAddress(InetAddress.getLoopbackAddress(), Integer.parseInt(spec));
      }
      int colon = spec.lastIndexOf(':');
      String host = spec.substring(0, colon);
      if (host.startsWith("[") && host.endsWith("]")) {
        host = host.substring(1, host.length() - 1);
      }
      return new InetSocketAddress(
          InetAddress.ofLiteral(host), Integer.parseInt(spec.substring(colon + 1)));
    } catch (RuntimeException e) {
      throw new IllegalArgumentException("invalid --proxy address '" + spec + "'", e);
    }
  }

  private static String value(String[] args, int i, String option) {
    if (i >= args.length) {
      throw new IllegalArgumentException(option + " needs a value");
    }
    return args[i];
  }
}
