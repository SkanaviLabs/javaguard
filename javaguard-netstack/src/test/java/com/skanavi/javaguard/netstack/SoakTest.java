// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.netstack;

import static org.assertj.core.api.Assertions.assertThat;

import com.skanavi.javaguard.core.Device;
import com.skanavi.javaguard.core.Peer;
import com.skanavi.javaguard.core.PeerConfig;
import com.skanavi.javaguard.core.UdpBind;
import com.skanavi.javaguard.crypto.PrivateKey;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * Long-running stability check: two devices over loopback UDP with netstacks, carrying a steady mix
 * of TCP transfers (each verified by SHA-256), DNS lookups and pings across many rekeys. Samples
 * heap after GC, thread count and connection count, and fails on errors, corrupted data or growth
 * that suggests a leak. Run with {@code ./gradlew :javaguard-netstack:soakTest -PsoakMinutes=N}
 * (default 10; use 1440 for the 24-hour soak).
 */
@Tag("soak")
class SoakTest {
  @Test
  void steadyTrafficAcrossRekeysDoesNotLeak() throws Exception {
    long minutes = Long.getLong("javaguard.soak.minutes", 10);
    InetAddress lo = InetAddress.getLoopbackAddress();
    PrivateKey ka = PrivateKey.generate();
    PrivateKey kb = PrivateKey.generate();
    Netstack sa =
        Netstack.builder()
            .address("10.8.0.1/24")
            .dns("10.8.0.2")
            .tcpTimeWait(Duration.ofSeconds(5))
            .build();
    Netstack sb =
        Netstack.builder().address("10.8.0.2/24").tcpTimeWait(Duration.ofSeconds(5)).build();
    try (Device a =
            Device.builder()
                .privateKey(ka)
                .bind(UdpBind.open(new InetSocketAddress(lo, 0)))
                .tun(sa)
                .build();
        Device b =
            Device.builder()
                .privateKey(kb)
                .bind(UdpBind.open(new InetSocketAddress(lo, 0)))
                .tun(sb)
                .build()) {
      Peer toB =
          a.addPeer(
              PeerConfig.builder(kb.publicKey())
                  .endpoint(new InetSocketAddress(lo, b.listenPort()))
                  .allowedIp("10.8.0.2/32")
                  .build());
      b.addPeer(PeerConfig.builder(ka.publicKey()).allowedIp("10.8.0.1/32").build());
      a.start();
      b.start();

      // Server side: TCP sink that echoes a SHA-256 of what it received, and DNS.
      TcpListener listener = sb.listenTcp(9000);
      Thread.ofVirtual()
          .start(
              () -> {
                try {
                  while (true) {
                    TcpSocket s = listener.accept();
                    Thread.ofVirtual()
                        .start(
                            () -> {
                              try (s) {
                                byte[] got = s.inputStream().readAllBytes();
                                s.outputStream()
                                    .write(MessageDigest.getInstance("SHA-256").digest(got));
                                s.shutdownOutput();
                              } catch (Exception e) {
                                // counted on the client side
                              }
                            });
                  }
                } catch (Exception e) {
                  // closed
                }
              });
      UdpSocket dns = sb.openUdp(53);
      Thread.ofVirtual()
          .start(
              () -> {
                try {
                  while (true) {
                    UdpSocket.Datagram q = dns.receive(Duration.ofSeconds(60));
                    if (q != null) {
                      dns.send(
                          q.source(),
                          DnsResolverTest.answer(
                              q.data(), Map.of("svc.soak", List.of("A 10.8.0.2")), 3));
                    }
                  }
                } catch (Exception e) {
                  // closed
                }
              });

      AtomicLong transfers = new AtomicLong();
      AtomicLong bytes = new AtomicLong();
      AtomicLong errors = new AtomicLong();
      List<String> errorSamples = new ArrayList<>();
      Set<Instant> handshakes = new HashSet<>();
      MemoryMXBean memory = ManagementFactory.getMemoryMXBean();
      List<long[]> samples = new ArrayList<>(); // {heapUsed, threads, tcpConnections}
      long end = System.nanoTime() + Duration.ofMinutes(minutes).toNanos();
      long nextSample = System.nanoTime();
      Random random = new Random(1);
      InetSocketAddress server = new InetSocketAddress(InetAddress.ofLiteral("10.8.0.2"), 9000);
      while (System.nanoTime() < end) {
        int size = 1 + random.nextInt(2 << 20);
        byte[] data = new byte[size];
        random.nextBytes(data);
        try (TcpSocket s = sa.connectTcp(server, Duration.ofSeconds(10))) {
          s.readTimeout(Duration.ofSeconds(30));
          s.outputStream().write(data);
          s.shutdownOutput();
          byte[] digest = s.inputStream().readAllBytes();
          if (!MessageDigest.isEqual(digest, MessageDigest.getInstance("SHA-256").digest(data))) {
            throw new AssertionError("corrupted transfer of " + size + " bytes");
          }
          transfers.incrementAndGet();
          bytes.addAndGet(size);
          if (!sa.dns().resolve("svc.soak").contains(InetAddress.ofLiteral("10.8.0.2"))) {
            throw new AssertionError("wrong DNS answer");
          }
          if (sa.ping(InetAddress.ofLiteral("10.8.0.2"), Duration.ofSeconds(5)).isEmpty()) {
            throw new AssertionError("ping lost");
          }
        } catch (Exception | AssertionError e) {
          errors.incrementAndGet();
          synchronized (errorSamples) {
            if (errorSamples.size() < 10) {
              errorSamples.add(e.toString());
            }
          }
        }
        toB.lastHandshake().ifPresent(handshakes::add);
        if (System.nanoTime() >= nextSample) {
          System.gc();
          long heap = memory.getHeapMemoryUsage().getUsed();
          long threads = ManagementFactory.getThreadMXBean().getThreadCount();
          long tcp = sa.tcpConnectionCount() + sb.tcpConnectionCount();
          samples.add(new long[] {heap, threads, tcp});
          System.out.printf(
              "t=%ds transfers=%d bytes=%dMiB errors=%d handshakes=%d heap=%dMiB threads=%d tcp=%d%n",
              samples.size() * 30 - 30,
              transfers.get(),
              bytes.get() >> 20,
              errors.get(),
              handshakes.size(),
              heap >> 20,
              threads,
              tcp);
          nextSample = System.nanoTime() + Duration.ofSeconds(30).toNanos();
        }
      }
      System.out.println("errors: " + errorSamples);
      assertThat(errors.get()).as("errors %s", errorSamples).isZero();
      assertThat(transfers.get()).isPositive();
      if (minutes >= 5) {
        assertThat(handshakes.size())
            .as("rekeys observed")
            .isGreaterThanOrEqualTo((int) (minutes / 2) - 1);
      }
      // Compare the last quarter of samples with the second quarter (the first is warm-up).
      int n = samples.size();
      if (n >= 8) {
        double early = average(samples.subList(n / 4, n / 2), 0);
        double late = average(samples.subList(3 * n / 4, n), 0);
        assertThat(late)
            .as("heap after GC (MiB) %.0f -> %.0f", early / 1048576, late / 1048576)
            .isLessThan(early * 1.5 + 32 * 1048576);
        assertThat(average(samples.subList(3 * n / 4, n), 1))
            .as("threads")
            .isLessThanOrEqualTo(average(samples.subList(n / 4, n / 2), 1) + 5);
        // Connections in TIME_WAIT settle at (connection rate x linger time); they must not grow.
        assertThat(average(samples.subList(3 * n / 4, n), 2))
            .as("TCP connections")
            .isLessThanOrEqualTo(average(samples.subList(n / 4, n / 2), 2) * 1.5 + 50);
      }
    }
  }

  private static double average(List<long[]> rows, int column) {
    return rows.stream().mapToLong(r -> r[column]).average().orElse(0);
  }
}
