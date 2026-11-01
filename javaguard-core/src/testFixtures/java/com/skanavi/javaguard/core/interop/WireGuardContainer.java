// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core.interop;

import com.skanavi.javaguard.crypto.PrivateKey;
import com.skanavi.javaguard.crypto.PublicKey;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;

/**
 * A Docker container running a reference WireGuard implementation as interface {@code wg0} with
 * address 10.9.0.2/24, listening on UDP 51820 (published on a random loopback port), with one peer
 * (javaguard) allowed 10.9.0.1/32.
 */
public final class WireGuardContainer implements AutoCloseable {
  /** The WireGuard implementation running in the container. */
  public enum Implementation {
    /** The Linux kernel module of the Docker host VM. */
    KERNEL("ip link add wg0 type wireguard"),
    /** The Go userspace implementation over /dev/net/tun. */
    WIREGUARD_GO("wireguard-go wg0");

    final String createInterface;

    Implementation(String createInterface) {
      this.createInterface = createInterface;
    }
  }

  /** The container's tunnel address. */
  public static final byte[] CONTAINER_IP = {10, 9, 0, 2};

  /** javaguard's tunnel address. */
  public static final byte[] JAVAGUARD_IP = {10, 9, 0, 1};

  /** The container's IPv6 tunnel address. */
  public static final String CONTAINER_IP6 = "fd00:9::2";

  /** javaguard's IPv6 tunnel address. */
  public static final String JAVAGUARD_IP6 = "fd00:9::1";

  private final String id;
  private final PrivateKey key = PrivateKey.generate();

  /**
   * Starts a container peered with {@code javaguard}.
   *
   * @param endpoint where the container sends to javaguard, e.g. {@code host.docker.internal:1234},
   *     or {@code null} to wait for javaguard to contact it
   */
  public WireGuardContainer(Implementation impl, PublicKey javaguard, String endpoint)
      throws IOException {
    id =
        Docker.run(
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
            "--add-host",
            "host.docker.internal:host-gateway",
            "-p",
            "127.0.0.1::51820/udp",
            Docker.IMAGE,
            "sleep",
            "600");
    try {
      Docker.runWithInput(
          key.toBase64() + "\n", "docker", "exec", "-i", id, "sh", "-c", "cat > /k");
      String peer =
          "peer "
              + javaguard.toBase64()
              + " allowed-ips 10.9.0.1/32,fd00:9::1/128"
              + (endpoint == null ? "" : " endpoint " + endpoint);
      exec(
          impl.createInterface
              + "; wg set wg0 listen-port 51820 private-key /k "
              + peer
              + "; ip addr add 10.9.0.2/24 dev wg0; ip -6 addr add fd00:9::2/64 dev wg0; ip link set wg0 up");
    } catch (IOException | RuntimeException | Error e) {
      close();
      throw e;
    }
  }

  /** The container's WireGuard public key. */
  public PublicKey publicKey() {
    return key.publicKey();
  }

  /** The container's WireGuard UDP endpoint as reachable from this host. */
  public InetSocketAddress endpoint() throws IOException {
    String mapped = Docker.run("docker", "port", id, "51820/udp").lines().findFirst().orElseThrow();
    return new InetSocketAddress(
        InetAddress.getLoopbackAddress(),
        Integer.parseInt(mapped.substring(mapped.lastIndexOf(':') + 1)));
  }

  /** Runs a shell command in the container, failing on non-zero exit; returns its output. */
  public String exec(String shell) throws IOException {
    return Docker.run("docker", "exec", id, "sh", "-ec", shell);
  }

  /** Runs a shell command in the container and returns its result without checking it. */
  public Docker.Result tryExec(String shell) throws IOException {
    return Docker.exec(null, "docker", "exec", id, "sh", "-c", shell);
  }

  @Override
  public void close() throws IOException {
    Docker.exec(null, "docker", "rm", "-f", id);
  }
}
