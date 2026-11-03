// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.tun;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.skanavi.javaguard.core.HostAddress;
import com.skanavi.javaguard.core.IpPrefix;
import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class HostNetworkTest {
  /** Records commands; fails those whose text contains {@code failOn}. */
  private static final class FakeRunner implements HostNetwork.CommandRunner {
    final List<String> commands = new ArrayList<>();
    final List<String> inputs = new ArrayList<>();
    final Set<String> programs;
    String failOn;

    FakeRunner(String... programs) {
      this.programs = Set.of(programs);
    }

    @Override
    public Result run(List<String> command, String input) {
      String line = String.join(" ", command);
      commands.add(line);
      inputs.add(input);
      return failOn != null && line.contains(failOn) ? new Result(2, "boom") : new Result(0, "");
    }

    @Override
    public boolean has(String program) {
      return programs.contains(program);
    }
  }

  private final List<String> warnings = new ArrayList<>();

  private HostNetwork.Builder builder(FakeRunner runner) {
    return HostNetwork.builder("wg0")
        .runner(runner)
        .warnings(warnings::add)
        .mtu(1380)
        .addresses(List.of(HostAddress.parse("10.0.0.2/24"), HostAddress.parse("fd00::2/64")))
        .routes(
            List.of(
                IpPrefix.parse("10.0.0.0/24"),
                IpPrefix.parse("192.168.0.0/16"),
                IpPrefix.parse("10.0.0.0/24"),
                IpPrefix.parse("fd00::/64")))
        .endpoints(List.of(InetAddress.ofLiteral("203.0.113.5")));
  }

  @Test
  void configuresTheInterfaceLikeWgQuick() throws IOException {
    FakeRunner runner = new FakeRunner();
    HostNetwork net = builder(runner).build();
    net.preUp();
    net.up();
    assertThat(runner.commands)
        .containsExactly(
            "ip link set dev wg0 mtu 1380",
            "ip -4 address add 10.0.0.2/24 dev wg0",
            "ip -6 address add fd00::2/64 dev wg0",
            "ip link set dev wg0 up",
            "ip -6 route replace fd00::/64 dev wg0",
            "ip -4 route replace 10.0.0.0/24 dev wg0",
            "ip -4 route replace 192.168.0.0/16 dev wg0");
    net.down();
    net.postDown();
    assertThat(runner.commands).hasSize(7);
    assertThat(warnings).isEmpty();
  }

  @Test
  void usesTheNamedTableOrNoRoutes() throws IOException {
    FakeRunner runner = new FakeRunner();
    builder(runner).table("1234").build().up();
    assertThat(runner.commands).contains("ip -4 route replace 10.0.0.0/24 dev wg0 table 1234");

    FakeRunner off = new FakeRunner();
    builder(off).table("off").build().up();
    assertThat(off.commands).noneMatch(c -> c.contains("route"));

    FakeRunner main = new FakeRunner();
    builder(main).table("auto").build().up();
    assertThat(main.commands).contains("ip -4 route replace 10.0.0.0/24 dev wg0");
  }

  @Test
  void rejectsFullTunnelAndEndpointLoopsUnlessTableIsOff() {
    FakeRunner runner = new FakeRunner();
    assertThatThrownBy(() -> builder(runner).routes(List.of(IpPrefix.parse("0.0.0.0/0"))).build())
        .hasMessageContaining("full-tunnel");
    assertThatThrownBy(() -> builder(runner).routes(List.of(IpPrefix.parse("::/0"))).build())
        .hasMessageContaining("full-tunnel");
    assertThatThrownBy(() -> builder(runner).routes(List.of(IpPrefix.parse("128.0.0.0/1"))).build())
        .hasMessageContaining("contains the endpoint 203.0.113.5");
    builder(runner).table("off").routes(List.of(IpPrefix.parse("0.0.0.0/0"))).build();
  }

  @Test
  void prefersResolvectlThenResolvconfThenWarns() throws IOException {
    FakeRunner resolved = new FakeRunner("resolvectl", "resolvconf");
    HostNetwork a =
        builder(resolved)
            .dns(List.of(InetAddress.ofLiteral("10.0.0.1")), List.of("corp.example"))
            .build();
    a.up();
    a.down();
    assertThat(resolved.commands)
        .contains(
            "resolvectl dns wg0 10.0.0.1",
            "resolvectl domain wg0 corp.example",
            "resolvectl revert wg0");

    FakeRunner resolvconf = new FakeRunner("resolvconf");
    HostNetwork b =
        builder(resolvconf)
            .dns(List.of(InetAddress.ofLiteral("10.0.0.1")), List.of("corp.example"))
            .build();
    b.up();
    b.down();
    int i = resolvconf.commands.indexOf("resolvconf -a wg0 -m 0 -x");
    assertThat(resolvconf.inputs.get(i)).isEqualTo("nameserver 10.0.0.1\nsearch corp.example\n");
    assertThat(resolvconf.commands).contains("resolvconf -d wg0 -f");

    FakeRunner neither = new FakeRunner();
    builder(neither).dns(List.of(InetAddress.ofLiteral("10.0.0.1")), List.of()).build().up();
    assertThat(neither.commands).noneMatch(c -> c.startsWith("resolv"));
    assertThat(warnings).singleElement().asString().contains("DNS");
  }

  @Test
  void runsHooksInWgQuickOrderWithTheInterfaceName() throws IOException {
    FakeRunner runner = new FakeRunner();
    HostNetwork net =
        builder(runner)
            .hooks(
                List.of("echo pre %i"),
                List.of("echo post %i"),
                List.of("echo predown"),
                List.of("echo postdown"))
            .build();
    net.preUp();
    net.up();
    net.down();
    net.down(); // idempotent
    net.postDown();
    assertThat(runner.commands.getFirst()).isEqualTo("/bin/sh -c echo pre wg0");
    assertThat(runner.commands.subList(runner.commands.size() - 3, runner.commands.size()))
        .containsExactly(
            "/bin/sh -c echo post wg0", "/bin/sh -c echo predown", "/bin/sh -c echo postdown");
  }

  @Test
  void failingUpStepsThrowAndFailingDownStepsWarn() {
    FakeRunner runner = new FakeRunner();
    runner.failOn = "192.168.0.0/16";
    HostNetwork net =
        builder(runner).hooks(List.of(), List.of(), List.of("false"), List.of()).build();
    assertThatThrownBy(net::up)
        .isInstanceOf(IOException.class)
        .hasMessageContaining("ip -4 route replace 192.168.0.0/16 dev wg0 failed (exit 2): boom");

    runner.failOn = "false";
    net.down();
    assertThat(warnings).singleElement().asString().contains("PreDown hook failed");

    FakeRunner hooks = new FakeRunner();
    hooks.failOn = "exit 3";
    HostNetwork h =
        builder(hooks).hooks(List.of("exit 3"), List.of(), List.of(), List.of()).build();
    assertThatThrownBy(h::preUp).hasMessageContaining("PreUp hook failed");
  }

  @Test
  void prefixContainment() {
    assertThat(
            HostNetwork.contains(IpPrefix.parse("10.0.0.0/8"), InetAddress.ofLiteral("10.1.2.3")))
        .isTrue();
    assertThat(
            HostNetwork.contains(IpPrefix.parse("10.0.0.0/9"), InetAddress.ofLiteral("10.128.0.1")))
        .isFalse();
    assertThat(HostNetwork.contains(IpPrefix.parse("fd00::/16"), InetAddress.ofLiteral("10.0.0.1")))
        .isFalse();
    assertThat(HostNetwork.contains(IpPrefix.parse("fd00::/16"), InetAddress.ofLiteral("fd00::9")))
        .isTrue();
  }

  @Test
  void linuxTunRefusesUnsupportedPlatforms() {
    if (!LinuxTun.isSupported()) {
      assertThatThrownBy(() -> LinuxTun.open("wg0", 1420))
          .isInstanceOf(UnsupportedOperationException.class)
          .hasMessageContaining("Linux");
    }
  }
}
