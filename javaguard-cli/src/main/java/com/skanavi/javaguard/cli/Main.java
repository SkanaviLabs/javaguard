// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.cli;

import com.skanavi.javaguard.config.ConfigException;
import com.skanavi.javaguard.config.UapiServer;
import com.skanavi.javaguard.config.WgQuickConfig;
import com.skanavi.javaguard.core.Device;
import com.skanavi.javaguard.core.PacketPipe;
import com.skanavi.javaguard.core.UdpBind;
import com.skanavi.javaguard.crypto.PresharedKey;
import com.skanavi.javaguard.crypto.PrivateKey;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

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
        help                   show this text

      'up' runs until interrupted or until its UAPI socket is deleted. Use the
      standard wg(8) tool to inspect and change it: wg show <name>.
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
    for (int i = 1; i < args.length; i++) {
      switch (args[i]) {
        case "--name" -> name = value(args, ++i, "--name");
        case "--socket" -> socket = Path.of(value(args, ++i, "--socket"));
        case "--no-uapi" -> uapi = false;
        case "--lenient" -> lenient = true;
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
    PacketPipe pipe = new PacketPipe(mtu);
    Device device =
        Device.builder()
            .privateKey(config.iface().privateKey())
            .bind(UdpBind.open(port))
            .tun(pipe)
            .build();
    UapiServer server = null;
    try {
      config.addPeersTo(device);
      device.start();
      if (uapi) {
        server =
            UapiServer.start(
                device, UdpBind::open, socket != null ? socket : UapiServer.defaultPath(name));
      }
    } catch (IOException | RuntimeException e) {
      device.close();
      throw e;
    }

    AtomicLong discarded = new AtomicLong();
    Thread drain =
        Thread.ofVirtual()
            .start(
                () -> {
                  try {
                    while (!Thread.currentThread().isInterrupted()) {
                      if (pipe.receive(Duration.ofSeconds(1)) != null) {
                        discarded.incrementAndGet();
                      }
                    }
                  } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                  }
                });

    UapiServer finalServer = server;
    Runtime.getRuntime()
        .addShutdownHook(new Thread(() -> shutdown(device, finalServer, drain), "javaguard-exit"));

    err.println(
        "javaguard: "
            + name
            + " up: public key "
            + device.publicKey().toBase64()
            + ", UDP port "
            + device.listenPort()
            + (server != null ? ", UAPI " + server.path() : ""));
    err.println(
        "javaguard: no network stack is attached yet; packets arriving through the tunnel are"
            + " discarded");

    try {
      while (server == null || server.socketExists()) {
        Thread.sleep(1000);
      }
      err.println("javaguard: UAPI socket removed, shutting down");
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
    shutdown(device, server, drain);
    return 0;
  }

  private static void shutdown(Device device, UapiServer server, Thread drain) {
    drain.interrupt();
    try {
      if (server != null) {
        server.close();
      }
      device.close();
    } catch (IOException e) {
      // exiting anyway
    }
  }

  private static String value(String[] args, int i, String option) {
    if (i >= args.length) {
      throw new IllegalArgumentException(option + " needs a value");
    }
    return args[i];
  }
}
