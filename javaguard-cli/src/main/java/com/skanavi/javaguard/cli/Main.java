// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.cli;

import com.skanavi.javaguard.config.ConfigException;
import com.skanavi.javaguard.config.UapiServer;
import com.skanavi.javaguard.config.WgQuickConfig;
import com.skanavi.javaguard.core.Device;
import com.skanavi.javaguard.core.PacketPipe;
import com.skanavi.javaguard.core.Tun;
import com.skanavi.javaguard.core.UdpBind;
import com.skanavi.javaguard.crypto.PresharedKey;
import com.skanavi.javaguard.crypto.PrivateKey;
import com.skanavi.javaguard.netstack.Netstack;
import com.skanavi.javaguard.proxy.LocalProxy;
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
          --lenient            ignore OS-level keys (PostUp, Table, ...) instead of failing
          --proxy [host:]port  serve a SOCKS5/HTTP proxy into the tunnel (needs Address);
                               binds 127.0.0.1 unless a host is given
          --proxy-auth u:p     require these proxy credentials
        help                   show this text

      'up' runs until interrupted or until its UAPI socket is deleted. Use the
      standard wg(8) tool to inspect and change it: wg show <name>. If the
      configuration has an Address, a userspace network stack with that address
      answers pings inside the tunnel.
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
    for (int i = 1; i < args.length; i++) {
      switch (args[i]) {
        case "--name" -> name = value(args, ++i, "--name");
        case "--socket" -> socket = Path.of(value(args, ++i, "--socket"));
        case "--no-uapi" -> uapi = false;
        case "--lenient" -> lenient = true;
        case "--proxy" -> proxySpec = value(args, ++i, "--proxy");
        case "--proxy-auth" -> proxyAuth = value(args, ++i, "--proxy-auth");
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

    String text = Files.readString(file, StandardCharsets.UTF_8);
    List<String> warnings = new ArrayList<>();
    WgQuickConfig config =
        lenient ? WgQuickConfig.parseLenient(text, warnings) : WgQuickConfig.parse(text);
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
    Tun tun;
    PacketPipe pipe = null;
    Netstack stack = null;
    if (config.iface().addresses().isEmpty()) {
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
    Device device =
        Device.builder()
            .privateKey(config.iface().privateKey())
            .bind(UdpBind.open(port))
            .tun(tun)
            .build();
    UapiServer server = null;
    LocalProxy proxy = null;
    try {
      config.addPeersTo(device);
      device.start();
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
      device.close();
      throw e;
    }

    Thread drain = pipe == null ? null : drain(pipe);
    UapiServer finalServer = server;
    LocalProxy finalProxy = proxy;
    Runtime.getRuntime()
        .addShutdownHook(
            new Thread(() -> shutdown(device, finalServer, finalProxy, drain), "javaguard-exit"));

    err.println(
        "javaguard: "
            + name
            + " up: public key "
            + device.publicKey().toBase64()
            + ", UDP port "
            + device.listenPort()
            + (server != null ? ", UAPI " + server.path() : ""));
    if (pipe != null) {
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
    shutdown(device, server, proxy, drain);
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

  private static void shutdown(Device device, UapiServer server, LocalProxy proxy, Thread drain) {
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
      device.close();
    } catch (IOException e) {
      // exiting anyway
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
