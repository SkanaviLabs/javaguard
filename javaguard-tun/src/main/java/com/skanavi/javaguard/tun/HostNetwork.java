// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.tun;

import com.skanavi.javaguard.core.HostAddress;
import com.skanavi.javaguard.core.IpPrefix;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * Configures the host side of a TUN interface the way wg-quick does on Linux, by running {@code
 * ip}, {@code resolvectl} or {@code resolvconf}, and the configuration's hook commands:
 *
 * <ol>
 *   <li>{@link #preUp()}: {@code PreUp} hooks, before the interface exists;
 *   <li>{@link #up()}: MTU, addresses, link up, a route for every allowed IP, DNS, then {@code
 *       PostUp} hooks;
 *   <li>{@link #down()}: {@code PreDown} hooks, then DNS is reverted;
 *   <li>close the {@link LinuxTun}, which removes the interface with its addresses and routes;
 *   <li>{@link #postDown()}: {@code PostDown} hooks.
 * </ol>
 *
 * <p>Routes go into the main table unless {@code Table} names another; {@code Table = off} adds
 * none. Default routes ({@code 0.0.0.0/0}, {@code ::/0}) and routes that would carry a peer's own
 * endpoint into the tunnel are rejected unless {@code Table = off}: full-tunnel routing, which
 * needs a firewall mark on the UDP socket and policy rules, is not supported yet.
 *
 * <p>Hook commands run with {@code /bin/sh -c}, with {@code %i} replaced by the interface name.
 * They run with the privileges of this process, so only pass hooks from a trusted configuration.
 */
public final class HostNetwork {
  /** Runs host commands; replaceable for tests. */
  public interface CommandRunner {
    /**
     * Runs {@code command}, feeding it {@code input} (may be {@code null}) on stdin.
     *
     * @return the exit code and combined output
     */
    Result run(List<String> command, String input) throws IOException;

    /** Whether {@code program} is on the {@code PATH}. */
    boolean has(String program);

    /**
     * The result of a command.
     *
     * @param exitCode the exit status
     * @param output stdout and stderr, combined
     */
    record Result(int exitCode, String output) {}

    /** Runs real processes. */
    static CommandRunner system() {
      return new CommandRunner() {
        @Override
        public Result run(List<String> command, String input) throws IOException {
          Process p = new ProcessBuilder(command).redirectErrorStream(true).start();
          try (OutputStream in = p.getOutputStream()) {
            if (input != null) {
              in.write(input.getBytes(StandardCharsets.UTF_8));
            }
          }
          String out;
          try (InputStream o = p.getInputStream()) {
            out = new String(o.readAllBytes(), StandardCharsets.UTF_8).strip();
          }
          try {
            return new Result(p.waitFor(), out);
          } catch (InterruptedException e) {
            p.destroy();
            Thread.currentThread().interrupt();
            throw new IOException("interrupted running " + command.getFirst(), e);
          }
        }

        @Override
        public boolean has(String program) {
          for (String dir : System.getenv().getOrDefault("PATH", "").split(File.pathSeparator)) {
            if (!dir.isEmpty() && Files.isExecutable(Path.of(dir, program))) {
              return true;
            }
          }
          return false;
        }
      };
    }
  }

  private final String name;
  private final int mtu;
  private final List<HostAddress> addresses;
  private final List<IpPrefix> routes;
  private final String table;
  private final List<InetAddress> dns;
  private final List<String> dnsSearch;
  private final List<String> preUp;
  private final List<String> postUp;
  private final List<String> preDown;
  private final List<String> postDown;
  private final CommandRunner runner;
  private final Consumer<String> warnings;
  private String dnsTool; // what set DNS, for down()
  private boolean upDone;
  private boolean downDone;
  private boolean postDownDone;

  private HostNetwork(Builder b) {
    this.name = b.name;
    this.mtu = b.mtu;
    this.addresses = List.copyOf(b.addresses);
    this.routes = List.copyOf(new LinkedHashSet<>(b.routes));
    this.table = b.table;
    this.dns = List.copyOf(b.dns);
    this.dnsSearch = List.copyOf(b.dnsSearch);
    this.preUp = List.copyOf(b.preUp);
    this.postUp = List.copyOf(b.postUp);
    this.preDown = List.copyOf(b.preDown);
    this.postDown = List.copyOf(b.postDown);
    this.runner = b.runner;
    this.warnings = b.warnings;
  }

  /** Starts a configuration for interface {@code name}. */
  public static Builder builder(String name) {
    return new Builder(name);
  }

  /** Builds a {@link HostNetwork}. */
  public static final class Builder {
    private final String name;
    private int mtu = 1420;
    private final List<HostAddress> addresses = new ArrayList<>();
    private final List<IpPrefix> routes = new ArrayList<>();
    private final List<InetAddress> endpoints = new ArrayList<>();
    private String table;
    private final List<InetAddress> dns = new ArrayList<>();
    private final List<String> dnsSearch = new ArrayList<>();
    private final List<String> preUp = new ArrayList<>();
    private final List<String> postUp = new ArrayList<>();
    private final List<String> preDown = new ArrayList<>();
    private final List<String> postDown = new ArrayList<>();
    private CommandRunner runner = CommandRunner.system();
    private Consumer<String> warnings = w -> {};

    private Builder(String name) {
      IfReq.encodeName(name);
      if (name.isEmpty() || name.contains("%")) {
        throw new IllegalArgumentException("need the actual interface name, not '" + name + "'");
      }
      this.name = name;
    }

    /** The interface MTU (default 1420). */
    public Builder mtu(int mtu) {
      if (mtu < 576 || mtu > 65535) {
        throw new IllegalArgumentException("MTU out of range: " + mtu);
      }
      this.mtu = mtu;
      return this;
    }

    /** Addresses to assign ({@code Address}). */
    public Builder addresses(List<HostAddress> addresses) {
      this.addresses.addAll(addresses);
      return this;
    }

    /** Prefixes to route into the interface (every peer's {@code AllowedIPs}). */
    public Builder routes(List<IpPrefix> routes) {
      this.routes.addAll(routes);
      return this;
    }

    /** Peer endpoint addresses; routes that would capture them are rejected. */
    public Builder endpoints(List<InetAddress> endpoints) {
      this.endpoints.addAll(endpoints);
      return this;
    }

    /**
     * The routing table ({@code Table}): {@code null}, {@code auto} or {@code main} for the main
     * table, {@code off} for no routes, or a table number or name.
     */
    public Builder table(String table) {
      if (table != null && !table.matches("[A-Za-z0-9_.-]+")) {
        throw new IllegalArgumentException("invalid table '" + table + "'");
      }
      this.table = table;
      return this;
    }

    /** DNS servers and search domains ({@code DNS}). */
    public Builder dns(List<InetAddress> servers, List<String> search) {
      this.dns.addAll(servers);
      this.dnsSearch.addAll(search);
      return this;
    }

    /** Hook commands; see the class description. */
    public Builder hooks(
        List<String> preUp, List<String> postUp, List<String> preDown, List<String> postDown) {
      this.preUp.addAll(preUp);
      this.postUp.addAll(postUp);
      this.preDown.addAll(preDown);
      this.postDown.addAll(postDown);
      return this;
    }

    /** Runs commands with {@code runner} instead of real processes. */
    public Builder runner(CommandRunner runner) {
      this.runner = Objects.requireNonNull(runner);
      return this;
    }

    /** Receives warnings (DNS skipped, a down step failed). */
    public Builder warnings(Consumer<String> warnings) {
      this.warnings = Objects.requireNonNull(warnings);
      return this;
    }

    /**
     * Validates the configuration.
     *
     * @throws IllegalArgumentException for a default route or a route that captures an endpoint,
     *     unless the table is {@code off}
     */
    public HostNetwork build() {
      if (!"off".equals(table)) {
        for (IpPrefix r : new LinkedHashSet<>(routes)) {
          if (r.length() == 0) {
            throw new IllegalArgumentException(
                "AllowedIPs "
                    + r
                    + " would route all traffic into the tunnel; full-tunnel routing is not"
                    + " supported yet. Use narrower AllowedIPs, or Table = off and route it"
                    + " yourself");
          }
          for (InetAddress e : endpoints) {
            if (contains(r, e)) {
              throw new IllegalArgumentException(
                  "AllowedIPs "
                      + r
                      + " contains the endpoint "
                      + e.getHostAddress()
                      + ", so the tunnel's own packets would loop into it; full-tunnel routing is"
                      + " not supported yet. Use narrower AllowedIPs, or Table = off");
            }
          }
        }
      }
      return new HostNetwork(this);
    }
  }

  /** The interface name. */
  public String name() {
    return name;
  }

  /** Runs the {@code PreUp} hooks. Call before creating the interface. */
  public void preUp() throws IOException {
    for (String h : preUp) {
      hook("PreUp", h, true);
    }
  }

  /**
   * Configures the interface, sets DNS and runs the {@code PostUp} hooks.
   *
   * @throws IOException if a command fails; call {@link #down()} to undo what was done
   */
  public void up() throws IOException {
    upDone = true;
    ip("link", "set", "dev", name, "mtu", Integer.toString(mtu));
    for (HostAddress a : addresses) {
      ip(family(a.address()), "address", "add", a.toString(), "dev", name);
    }
    ip("link", "set", "dev", name, "up");
    for (IpPrefix r : routeCommandsOrder()) {
      List<String> cmd = new ArrayList<>(List.of(family(r.address()), "route", "replace"));
      cmd.add(r.toString());
      cmd.add("dev");
      cmd.add(name);
      if (table != null && !table.equals("auto") && !table.equals("main")) {
        cmd.add("table");
        cmd.add(table);
      }
      ip(cmd.toArray(String[]::new));
    }
    setDns();
    for (String h : postUp) {
      hook("PostUp", h, true);
    }
  }

  /**
   * Runs the {@code PreDown} hooks and reverts DNS. Failures are reported as warnings. Call before
   * closing the interface; does nothing if {@link #up()} was never called or this already ran.
   */
  public synchronized void down() {
    if (!upDone || downDone) {
      return;
    }
    downDone = true;
    for (String h : preDown) {
      quietly(() -> hook("PreDown", h, false));
    }
    if ("resolvectl".equals(dnsTool)) {
      quietly(() -> check(List.of("resolvectl", "revert", name), null));
    } else if ("resolvconf".equals(dnsTool)) {
      quietly(() -> check(List.of("resolvconf", "-d", name, "-f"), null));
    }
  }

  /**
   * Runs the {@code PostDown} hooks, after the interface is gone. Failures become warnings. Runs
   * once, and only after {@link #down()}.
   */
  public synchronized void postDown() {
    if (!downDone || postDownDone) {
      return;
    }
    postDownDone = true;
    for (String h : postDown) {
      quietly(() -> hook("PostDown", h, false));
    }
  }

  private List<IpPrefix> routeCommandsOrder() {
    if ("off".equals(table)) {
      return List.of();
    }
    // Most specific first, like wg-quick, so a route never briefly covers a narrower one.
    List<IpPrefix> sorted = new ArrayList<>(routes);
    sorted.sort((a, b) -> Integer.compare(b.length(), a.length()));
    return sorted;
  }

  private void setDns() throws IOException {
    if (dns.isEmpty() && dnsSearch.isEmpty()) {
      return;
    }
    if (runner.has("resolvectl")) {
      List<String> servers = new ArrayList<>(List.of("resolvectl", "dns", name));
      dns.forEach(a -> servers.add(a.getHostAddress()));
      check(servers, null);
      dnsTool = "resolvectl";
      if (!dnsSearch.isEmpty()) {
        List<String> domains = new ArrayList<>(List.of("resolvectl", "domain", name));
        domains.addAll(dnsSearch);
        check(domains, null);
      }
    } else if (runner.has("resolvconf")) {
      StringBuilder conf = new StringBuilder();
      dns.forEach(a -> conf.append("nameserver ").append(a.getHostAddress()).append('\n'));
      if (!dnsSearch.isEmpty()) {
        conf.append("search ").append(String.join(" ", dnsSearch)).append('\n');
      }
      check(List.of("resolvconf", "-a", name, "-m", "0", "-x"), conf.toString());
      dnsTool = "resolvconf";
    } else {
      warnings.accept(
          "DNS is set in the configuration but neither resolvectl nor resolvconf was found;"
              + " DNS settings were not applied");
    }
  }

  private void hook(String what, String command, boolean failHard) throws IOException {
    CommandRunner.Result r =
        runner.run(List.of("/bin/sh", "-c", command.replace("%i", name)), null);
    if (r.exitCode() != 0) {
      String message = what + " hook failed (exit " + r.exitCode() + "): " + command;
      if (failHard) {
        throw new IOException(message + (r.output().isEmpty() ? "" : "\n" + r.output()));
      }
      warnings.accept(message);
    }
  }

  private void ip(String... args) throws IOException {
    List<String> cmd = new ArrayList<>();
    cmd.add("ip");
    cmd.addAll(List.of(args));
    check(cmd, null);
  }

  private void check(List<String> cmd, String input) throws IOException {
    CommandRunner.Result r = runner.run(cmd, input);
    if (r.exitCode() != 0) {
      throw new IOException(
          String.join(" ", cmd)
              + " failed (exit "
              + r.exitCode()
              + ")"
              + (r.output().isEmpty() ? "" : ": " + r.output()));
    }
  }

  private interface Step {
    void run() throws IOException;
  }

  private void quietly(Step step) {
    try {
      step.run();
    } catch (IOException e) {
      warnings.accept(e.getMessage());
    }
  }

  private static String family(InetAddress a) {
    return a.getAddress().length == 4 ? "-4" : "-6";
  }

  /** Whether {@code prefix} contains {@code address} (same family only). */
  static boolean contains(IpPrefix prefix, InetAddress address) {
    byte[] p = prefix.address().getAddress();
    byte[] a = address.getAddress();
    if (p.length != a.length) {
      return false;
    }
    int bits = prefix.length();
    for (int i = 0; i < p.length && bits > 0; i++, bits -= 8) {
      int mask = bits >= 8 ? 0xFF : (0xFF << (8 - bits)) & 0xFF;
      if (((p[i] ^ a[i]) & mask) != 0) {
        return false;
      }
    }
    return true;
  }
}
