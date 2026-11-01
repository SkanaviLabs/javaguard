// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core.interop;

import static com.skanavi.javaguard.core.interop.WireGuardContainer.CONTAINER_IP;
import static com.skanavi.javaguard.core.interop.WireGuardContainer.JAVAGUARD_IP;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.skanavi.javaguard.core.Device;
import com.skanavi.javaguard.core.PacketPipe;
import com.skanavi.javaguard.core.Peer;
import com.skanavi.javaguard.core.PeerConfig;
import com.skanavi.javaguard.core.UdpBind;
import com.skanavi.javaguard.core.interop.WireGuardContainer.Implementation;
import com.skanavi.javaguard.crypto.PrivateKey;
import java.io.IOException;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * Runs a full {@link Device} (UDP bind, I/O threads, timers) against reference implementations in
 * Docker, exchanging ICMP traffic with the container's IP stack through a {@link PacketPipe}.
 */
@Tag("interop")
class DeviceInteropTest {
  @BeforeAll
  static void requireDocker() throws IOException {
    assumeTrue(Docker.available(), "Docker is not available");
    Docker.buildImage();
  }

  @ParameterizedTest
  @EnumSource(Implementation.class)
  void deviceInitiatesAndPingsPeer(Implementation impl) throws Exception {
    PrivateKey key = PrivateKey.generate();
    PacketPipe pipe = new PacketPipe(1420);
    try (WireGuardContainer peer = new WireGuardContainer(impl, key.publicKey(), null);
        Device device = Device.builder().privateKey(key).bind(UdpBind.open(0)).tun(pipe).build()) {
      device.addPeer(
          PeerConfig.builder(peer.publicKey())
              .endpoint(peer.endpoint())
              .allowedIp("10.9.0.0/24")
              .build());
      device.start();

      for (int seq = 1; seq <= 20; seq++) {
        byte[] payload = new byte[64 + seq * 50]; // vary sizes to exercise padding
        assertThat(pipe.send(Packets.icmpEcho(JAVAGUARD_IP, CONTAINER_IP, 8, 0x4a47, seq, payload)))
            .isTrue();
        byte[] reply = awaitIcmp(pipe, 0, Duration.ofSeconds(seq == 1 ? 10 : 3));
        assertThat(reply).as("echo reply %d", seq).isNotNull();
        assertThat(((reply[26] & 0xff) << 8) | (reply[27] & 0xff)).isEqualTo(seq);
      }
      Peer p = device.peer(peer.publicKey());
      assertThat(p.lastHandshake()).isPresent();
      assertThat(p.rxBytes()).isPositive();
      assertThat(peer.exec("wg show wg0 transfer")).doesNotEndWith("\t0");
    }
  }

  @ParameterizedTest
  @EnumSource(Implementation.class)
  void peerInitiatesAndPingsDevice(Implementation impl) throws Exception {
    PrivateKey key = PrivateKey.generate();
    PacketPipe pipe = new PacketPipe(1420);
    UdpBind bind = UdpBind.open(0);
    try (WireGuardContainer peer =
            new WireGuardContainer(
                impl, key.publicKey(), "host.docker.internal:" + bind.localPort());
        Device device = Device.builder().privateKey(key).bind(bind).tun(pipe).build()) {
      device.addPeer(PeerConfig.builder(peer.publicKey()).allowedIp("10.9.0.2/32").build());
      device.start();

      AtomicBoolean running = new AtomicBoolean(true);
      Thread responder =
          Thread.ofVirtual()
              .start(
                  () -> {
                    while (running.get()) {
                      try {
                        byte[] p = pipe.receive(Duration.ofMillis(100));
                        if (p != null && Packets.isIcmp(p, 8, CONTAINER_IP)) {
                          pipe.send(Packets.echoReply(p));
                        }
                      } catch (InterruptedException e) {
                        return;
                      }
                    }
                  });
      try {
        Docker.Result ping =
            CompletableFuture.supplyAsync(
                    () -> {
                      try {
                        return peer.tryExec("ping -c 10 -i 0.2 -W 10 -s 1000 10.9.0.1");
                      } catch (IOException e) {
                        throw new RuntimeException(e);
                      }
                    })
                .get(60, TimeUnit.SECONDS);
        assertThat(ping.exitCode()).as(ping.output()).isZero();
        assertThat(ping.output()).contains("10 packets received");
      } finally {
        running.set(false);
        responder.join();
      }
      assertThat(device.peer(peer.publicKey()).endpoint()).isPresent();
    }
  }

  /** Pings continuously across several rekeys. Opt-in: {@code -PlongInterop=true}. */
  @ParameterizedTest
  @EnumSource(Implementation.class)
  void trafficSurvivesRekeying(Implementation impl) throws Exception {
    assumeTrue(Boolean.getBoolean("javaguard.interop.long"), "long interop tests disabled");
    PrivateKey key = PrivateKey.generate();
    PacketPipe pipe = new PacketPipe(1420);
    try (WireGuardContainer peer = new WireGuardContainer(impl, key.publicKey(), null);
        Device device = Device.builder().privateKey(key).bind(UdpBind.open(0)).tun(pipe).build()) {
      Peer p =
          device.addPeer(
              PeerConfig.builder(peer.publicKey())
                  .endpoint(peer.endpoint())
                  .allowedIp("10.9.0.2/32")
                  .build());
      device.start();
      java.util.Set<java.time.Instant> handshakes = new java.util.HashSet<>();
      int lost = 0;
      for (int seq = 1; seq <= 260; seq++) {
        pipe.send(Packets.icmpEcho(JAVAGUARD_IP, CONTAINER_IP, 8, 0x4a47, seq, new byte[100]));
        if (awaitIcmp(pipe, 0, Duration.ofSeconds(seq == 1 ? 10 : 2)) == null) {
          lost++;
        }
        p.lastHandshake().ifPresent(handshakes::add);
        Thread.sleep(1000);
      }
      assertThat(lost).as("lost echo replies").isZero();
      assertThat(handshakes).as("distinct handshakes").hasSizeGreaterThanOrEqualTo(3);
    }
  }

  private static byte[] awaitIcmp(PacketPipe pipe, int type, Duration timeout)
      throws InterruptedException {
    long deadline = System.nanoTime() + timeout.toNanos();
    while (System.nanoTime() < deadline) {
      byte[] p = pipe.receive(Duration.ofMillis(100));
      if (p != null && Packets.isIcmp(p, type, CONTAINER_IP)) {
        return p;
      }
    }
    return null;
  }
}
