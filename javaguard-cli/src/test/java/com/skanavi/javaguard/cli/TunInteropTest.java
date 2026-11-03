// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.cli;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.skanavi.javaguard.core.interop.Docker;
import com.skanavi.javaguard.core.interop.WireGuardContainer;
import com.skanavi.javaguard.core.interop.WireGuardContainer.Implementation;
import com.skanavi.javaguard.crypto.PrivateKey;
import java.io.IOException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * Runs {@code javaguard up --tun} in a Linux container, which creates a real interface {@code wg0},
 * peered with a reference WireGuard implementation in a second container. Ordinary tools ({@code
 * ping}, {@code curl}, {@code socat}) use the tunnel through the host's own network stack.
 */
@Tag("interop")
class TunInteropTest {
  private static final String IMAGE = "javaguard-tun-test:1";
  private static final String DOCKERFILE =
      """
      FROM eclipse-temurin:25-jre
      RUN apt-get update && apt-get install -y --no-install-recommends \\
          iproute2 iputils-ping curl socat wireguard-tools procps \\
          && rm -rf /var/lib/apt/lists/*
      """;
  private static final int FILE_MIB = 64;

  private final PrivateKey javaguardKey = PrivateKey.generate();
  private WireGuardContainer peer;
  private String container;

  @BeforeAll
  static void requireDockerAndDistribution() throws IOException {
    assumeTrue(Docker.available(), "Docker is not available");
    assumeTrue(System.getProperty("javaguard.cli.install") != null, "run via interopTest");
    Docker.buildImage();
    Docker.buildImage(IMAGE, DOCKERFILE);
  }

  @AfterEach
  void removeContainers() throws IOException {
    if (container != null) {
      System.out.println("--- javaguard log ---\n" + exec("cat /tmp/javaguard.log || true"));
      Docker.exec(null, "docker", "rm", "-f", container);
    }
    if (peer != null) {
      peer.close();
    }
  }

  @ParameterizedTest
  @EnumSource(Implementation.class)
  void unmodifiedProgramsUseTheTunnel(Implementation impl) throws Exception {
    String sha = startPeerAndServices(impl);
    startJavaguard("--tun --allow-hooks");

    // The interface is configured from the file.
    assertThat(exec("ip -o link show wg0")).contains("mtu 1420").contains("UP");
    assertThat(exec("ip -o addr show dev wg0")).contains("10.9.0.1/24").contains("fd00:9::1/64");
    assertThat(exec("ip route show dev wg0")).contains("10.9.0.0/24").contains("10.99.0.0/16");
    assertThat(exec("ip -6 route show dev wg0")).contains("fd00:9::/64");
    assertThat(exec("cat /tmp/javaguard.log"))
        .contains("neither resolvectl nor resolvconf was found");
    assertThat(exec("cat /tmp/hook-up")).isEqualTo("wg0");

    // ICMP both ways, IPv4 and IPv6.
    exec("ping -c 3 -W 3 10.9.0.2");
    exec("ping -6 -c 3 -W 3 fd00:9::2");
    peer.exec("ping -c 2 -W 3 10.9.0.1");

    // TCP: a plain curl download, verified.
    assertThat(exec("curl -sf http://10.9.0.2:8080/f | sha256sum | cut -d' ' -f1")).isEqualTo(sha);
    // UDP: an echo through socat.
    assertThat(exec("echo ping-udp | socat -t 3 - UDP4:10.9.0.2:7000")).isEqualTo("ping-udp");

    // wg(8) still works over the UAPI socket.
    assertThat(exec("wg show wg0 latest-handshakes")).doesNotEndWith("\t0");

    // SIGTERM removes the interface and its routes and runs PostDown.
    exec("pkill -TERM -f 'com[.]skanavi[.]javaguard[.]cli'");
    waitFor("! ip link show wg0 2>/dev/null");
    assertThat(exec("ip route")).doesNotContain("10.9.0.0/24").doesNotContain("10.99.0.0");
    waitFor("test -f /tmp/hook-down");
    assertThat(exec("cat /tmp/javaguard.log")).doesNotContain("Exception");
  }

  @Test
  void refusesFullTunnelAndUnapprovedHooks() throws Exception {
    startPeerAndServices(Implementation.KERNEL);
    container = startContainer();
    String endpoint = peer.bridgeAddress() + ":51820";
    writeConfig("0.0.0.0/0", endpoint);
    assertThat(execStatus("/opt/javaguard/bin/javaguard up /etc/wireguard/wg0.conf --tun"))
        .contains("pass --allow-hooks");
    assertThat(
            execStatus(
                "/opt/javaguard/bin/javaguard up /etc/wireguard/wg0.conf --tun --allow-hooks"))
        .contains("full-tunnel routing is not supported yet");
    assertThat(exec("ip link show wg0 2>&1 || true")).contains("does not exist");
  }

  /**
   * Downloads the same file through the kernel interface and through the userspace netstack's SOCKS
   * proxy, and prints both rates. Informational; asserts only that both completed.
   */
  @Test
  void throughputComparedWithNetstack() throws Exception {
    String sha = startPeerAndServices(Implementation.KERNEL);
    startJavaguard("--tun --allow-hooks");
    String tun = exec("curl -sf -o /tmp/f -w '%{speed_download}' http://10.9.0.2:8080/f");
    assertThat(exec("sha256sum /tmp/f | cut -d' ' -f1")).isEqualTo(sha);
    exec("pkill -TERM -f 'com[.]skanavi[.]javaguard[.]cli'");
    waitFor("! ip link show wg0 2>/dev/null");

    exec("rm -f /tmp/javaguard.log /var/run/wireguard/wg0.sock");
    Docker.run(
        "docker",
        "exec",
        "-d",
        container,
        "sh",
        "-c",
        "/opt/javaguard/bin/javaguard up /etc/wireguard/wg0.conf --lenient --proxy 1080"
            + " > /tmp/javaguard.log 2>&1");
    waitFor("grep -q 'proxy on' /tmp/javaguard.log");
    String netstack =
        exec(
            "curl -sf --socks5-hostname 127.0.0.1:1080 -o /tmp/f -w '%{speed_download}'"
                + " http://10.9.0.2:8080/f");
    assertThat(exec("sha256sum /tmp/f | cut -d' ' -f1")).isEqualTo(sha);
    System.out.printf(
        "%d MiB download: kernel TUN %.0f Mbit/s, netstack + SOCKS %.0f Mbit/s%n",
        FILE_MIB, mbps(tun), mbps(netstack));
  }

  /** Rekeys need over two minutes; run with -PlongInterop=true. */
  @Test
  void survivesRekeys() throws Exception {
    assumeTrue(Boolean.getBoolean("javaguard.interop.long"), "long interop test");
    startPeerAndServices(Implementation.KERNEL);
    startJavaguard("--tun --allow-hooks");
    exec("ping -c 1 -W 3 10.9.0.2");
    String first = exec("wg show wg0 latest-handshakes");
    // The initiator rekeys after REKEY_AFTER_TIME (120 s) of use; keep traffic flowing.
    exec("ping -q -i 0.5 -w 140 10.9.0.2 >/dev/null || true");
    String second = exec("wg show wg0 latest-handshakes");
    assertThat(second).isNotEqualTo(first);
    exec("ping -c 3 -W 3 10.9.0.2");
  }

  private static double mbps(String bytesPerSecond) {
    return Double.parseDouble(bytesPerSecond.replace(',', '.')) * 8 / 1e6;
  }

  /** Starts the peer with an HTTP file server and a UDP echo on 10.9.0.2; returns the file hash. */
  private String startPeerAndServices(Implementation impl) throws IOException {
    peer = new WireGuardContainer(impl, javaguardKey.publicKey(), null);
    peer.exec(
        "mkdir -p /srv && head -c "
            + (FILE_MIB << 20)
            + " /dev/urandom > /srv/f; (busybox-extras httpd -p 10.9.0.2:8080 -h /srv"
            + " || busybox httpd -p 10.9.0.2:8080 -h /srv);"
            + " (socat UDP4-LISTEN:7000,bind=10.9.0.2,fork EXEC:cat >/dev/null 2>&1 &)");
    return peer.exec("sha256sum /srv/f | cut -d' ' -f1");
  }

  private String startContainer() throws IOException {
    return Docker.run(
        "docker",
        "run",
        "-d",
        "--rm",
        "--cap-add",
        "NET_ADMIN",
        "--device",
        "/dev/net/tun",
        "--sysctl",
        "net.ipv6.conf.all.disable_ipv6=0",
        "-v",
        System.getProperty("javaguard.cli.install") + ":/opt/javaguard:ro",
        IMAGE,
        "sleep",
        "900");
  }

  private void startJavaguard(String options) throws Exception {
    container = startContainer();
    writeConfig("10.9.0.0/24, 10.99.0.0/16, fd00:9::/64", peer.bridgeAddress() + ":51820");
    Docker.run(
        "docker",
        "exec",
        "-d",
        container,
        "sh",
        "-c",
        "/opt/javaguard/bin/javaguard up /etc/wireguard/wg0.conf "
            + options
            + " > /tmp/javaguard.log 2>&1");
    waitFor("grep -q 'interface wg0 up' /tmp/javaguard.log");
  }

  private void writeConfig(String allowedIps, String endpoint) throws IOException {
    write(
        "/etc/wireguard/wg0.conf",
        "[Interface]\nPrivateKey = "
            + javaguardKey.toBase64()
            + "\nAddress = 10.9.0.1/24, fd00:9::1/64\nDNS = 10.9.0.2\n"
            + "PostUp = printf %i > /tmp/hook-up\nPostDown = touch /tmp/hook-down\n\n"
            + "[Peer]\nPublicKey = "
            + peer.publicKey().toBase64()
            + "\nAllowedIPs = "
            + allowedIps
            + "\nEndpoint = "
            + endpoint
            + "\n");
  }

  private String exec(String shell) throws IOException {
    return Docker.run("docker", "exec", container, "sh", "-ec", shell);
  }

  /** Runs a command expected to fail; returns its output. */
  private String execStatus(String shell) throws IOException {
    Docker.Result r = Docker.exec(null, "docker", "exec", container, "sh", "-c", shell + " 2>&1");
    assertThat(r.exitCode()).as(shell).isNotZero();
    return r.output();
  }

  private void write(String path, String content) throws IOException {
    Docker.runWithInput(
        content,
        "docker",
        "exec",
        "-i",
        container,
        "sh",
        "-c",
        "mkdir -p $(dirname " + path + ") && cat > " + path);
  }

  private void waitFor(String condition) throws Exception {
    for (int i = 0; i < 60; i++) {
      if (Docker.exec(null, "docker", "exec", container, "sh", "-c", condition).exitCode() == 0) {
        return;
      }
      Thread.sleep(500);
    }
    throw new AssertionError(
        "timed out waiting for: " + condition + "\n" + exec("cat /tmp/javaguard.log || true"));
  }
}
