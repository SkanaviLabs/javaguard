// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.cli;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.skanavi.javaguard.core.interop.Docker;
import com.skanavi.javaguard.crypto.PrivateKey;
import com.skanavi.javaguard.crypto.PublicKey;
import java.io.IOException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * Runs {@code javaguard up} in a Linux container and drives it with the stock {@code wg(8)} tool
 * over the UAPI socket, next to a kernel WireGuard interface that handshakes with it.
 */
@Tag("interop")
class WgToolInteropTest {
  private static final String IMAGE = "javaguard-cli-test:1";
  private static final String DOCKERFILE =
      "FROM eclipse-temurin:25-jre-alpine\nRUN apk add --no-cache wireguard-tools-wg\n";

  private final PrivateKey javaguardKey = PrivateKey.generate();
  private final PrivateKey kernelKey = PrivateKey.generate();
  private String container;

  @BeforeAll
  static void requireDockerAndDistribution() throws IOException {
    assumeTrue(Docker.available(), "Docker is not available");
    assumeTrue(System.getProperty("javaguard.cli.install") != null, "run via interopTest");
    Docker.buildImage(IMAGE, DOCKERFILE);
  }

  @AfterEach
  void removeContainer() throws IOException {
    if (container != null) {
      System.out.println("--- javaguard log ---\n" + exec("cat /tmp/javaguard.log || true"));
      Docker.exec(null, "docker", "rm", "-f", container);
    }
  }

  @Test
  void wgToolInspectsAndReconfiguresARunningDevice() throws Exception {
    container =
        Docker.run(
            "docker",
            "run",
            "-d",
            "--rm",
            "--cap-add",
            "NET_ADMIN",
            "-v",
            System.getProperty("javaguard.cli.install") + ":/opt/javaguard:ro",
            IMAGE,
            "sleep",
            "600");
    PublicKey jg = javaguardKey.publicKey();
    PublicKey kernel = kernelKey.publicKey();
    write(
        "/etc/wireguard/wg0.conf",
        "[Interface]\nPrivateKey = "
            + javaguardKey.toBase64()
            + "\nListenPort = 51820\n\n"
            + "[Peer]\nPublicKey = "
            + kernel.toBase64()
            + "\nAllowedIPs = 10.9.0.2/32\n"
            + "Endpoint = 127.0.0.1:51821\n");
    Docker.run(
        "docker",
        "exec",
        "-d",
        container,
        "sh",
        "-c",
        "/opt/javaguard/bin/javaguard up /etc/wireguard/wg0.conf > /tmp/javaguard.log 2>&1");
    waitFor("test -S /var/run/wireguard/wg0.sock");

    // wg show reads the device through UAPI.
    assertThat(exec("wg show wg0"))
        .contains("interface: wg0")
        .contains("public key: " + jg.toBase64())
        .contains("listening port: 51820")
        .contains("peer: " + kernel.toBase64())
        .contains("endpoint: 127.0.0.1:51821")
        .contains("allowed ips: 10.9.0.2/32");
    assertThat(exec("wg show wg0 private-key")).isEqualTo(javaguardKey.toBase64());

    // wg set adds, changes and removes peers.
    PublicKey extra = PrivateKey.generate().publicKey();
    exec(
        "wg set wg0 peer "
            + extra.toBase64()
            + " allowed-ips 10.99.0.0/24,fd00::/64 persistent-keepalive 25 endpoint [2001:db8::1]:51820");
    assertThat(exec("wg show wg0 allowed-ips"))
        .contains(extra.toBase64() + "\t10.99.0.0/24 fd00::/64");
    assertThat(exec("wg show wg0 persistent-keepalive")).contains(extra.toBase64() + "\t25");
    assertThat(exec("wg showconf wg0"))
        .contains("PublicKey = " + extra.toBase64())
        .contains("AllowedIPs = 10.99.0.0/24, fd00::/64")
        .contains("Endpoint = [2001:db8::1]:51820");
    exec("wg set wg0 peer " + extra.toBase64() + " remove");
    assertThat(exec("wg show wg0 peers")).isEqualTo(kernel.toBase64());

    // A kernel interface in the same container handshakes with javaguard; wg sees the stats.
    write("/k1", kernelKey.toBase64() + "\n");
    exec(
        "ip link add wg1 type wireguard; wg set wg1 listen-port 51821 private-key /k1 peer "
            + jg.toBase64()
            + " allowed-ips 10.9.0.1/32 endpoint 127.0.0.1:51820;"
            + " ip addr add 10.9.0.2/24 dev wg1; ip link set wg1 up");
    Docker.exec(null, "docker", "exec", container, "ping", "-c", "3", "-W", "2", "10.9.0.1");
    String handshakes = exec("wg show wg0 latest-handshakes");
    assertThat(handshakes).startsWith(kernel.toBase64() + "\t").doesNotEndWith("\t0");
    String[] transfer = exec("wg show wg0 transfer").split("\t");
    assertThat(Long.parseLong(transfer[1])).as("rx bytes").isPositive();
    assertThat(exec("wg show wg1 latest-handshakes")).doesNotEndWith("\t0");

    // Changing the listen port rebinds the UDP socket.
    exec("wg set wg0 listen-port 51830");
    assertThat(exec("wg show wg0 listen-port")).isEqualTo("51830");

    // wg setconf replaces the peer list.
    PublicKey only = PrivateKey.generate().publicKey();
    write(
        "/etc/wireguard/replace.conf",
        "[Interface]\nPrivateKey = "
            + javaguardKey.toBase64()
            + "\nListenPort = 51830\n\n"
            + "[Peer]\nPublicKey = "
            + only.toBase64()
            + "\nAllowedIPs = 10.50.0.0/16\n");
    exec("wg setconf wg0 /etc/wireguard/replace.conf");
    assertThat(exec("wg show wg0 peers")).isEqualTo(only.toBase64());

    // Deleting the socket asks the daemon to exit.
    exec("rm /var/run/wireguard/wg0.sock");
    waitFor(
        "! pgrep -f 'com[.]skanavi[.]javaguard[.]cli'"); // [.] keeps pgrep from matching this shell
  }

  private String exec(String shell) throws IOException {
    return Docker.run("docker", "exec", container, "sh", "-ec", shell);
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
    throw new AssertionError("timed out waiting for: " + condition);
  }
}
