// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.netstack;

import static com.skanavi.javaguard.netstack.TestNode.LONG;
import static com.skanavi.javaguard.netstack.TestNode.awaitThreadsGone;
import static com.skanavi.javaguard.netstack.TestNode.liveThreads;
import static com.skanavi.javaguard.netstack.TestNode.runAll;
import static com.skanavi.javaguard.netstack.TestNode.sha256;
import static org.assertj.core.api.Assertions.assertThat;

import java.lang.management.ManagementFactory;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * Many tunnels at once, and tunnels churning for a long time. Measurements rather than quick
 * checks, so these run with {@code ./gradlew :javaguard-netstack:soakTest --tests
 * '*TunnelScaleTest*' -PsoakMinutes=N}.
 */
@Tag("soak")
class TunnelScaleTest extends TunnelTestBase {
  private static final int TUNNELS = 100;
  private static final int PORT = 9000;

  @Test
  void reportsTheCostOfEachTunnel() throws Exception {
    TestNode server = node("server", "10.60.0.1/16");
    server.serveDigest(PORT);
    server.start();
    System.gc();
    long heapBefore = usedHeap();
    int threadsBefore = liveThreads(Set.of()).size();

    List<TestNode> clients = new ArrayList<>();
    for (int i = 0; i < TUNNELS; i++) {
      String ip = "10.60." + (1 + i / 250) + "." + (1 + i % 250);
      TestNode client = node(ip, ip + "/16");
      client.connect(server, "10.60.0.1/32");
      server.addPeer(client, null, ip + "/32");
      client.start();
      clients.add(client);
    }

    byte[] data = new byte[64 << 10];
    long start = System.nanoTime();
    runAll(
        clients,
        c ->
            () -> {
              assertThat(c.exchange("10.60.0.1", PORT, data)).isEqualTo(sha256(data));
              return null;
            });
    Duration elapsed = Duration.ofNanos(System.nanoTime() - start);

    System.gc();
    long threads = liveThreads(Set.of()).size() - threadsBefore;
    long heap = usedHeap() - heapBefore;
    System.out.printf(
        "tunnels=%d firstTransfers=%dms threads=%d (%.1f each) heap=%dMiB (%dKiB each)%n",
        TUNNELS,
        elapsed.toMillis(),
        threads,
        (double) threads / TUNNELS,
        heap >> 20,
        (heap >> 10) / TUNNELS);
    assertThat(server.device.peers()).hasSize(TUNNELS);
  }

  @Test
  void churningTunnelsForALongTimeDoesNotLeak() throws Exception {
    long minutes = Long.getLong("javaguard.soak.minutes", 10);
    Set<Thread> baseline = cycle(liveThreads(Set.of()));
    System.gc();
    long early = usedHeap();

    long cycles = 0;
    long end = System.nanoTime() + Duration.ofMinutes(minutes).toNanos();
    while (System.nanoTime() < end) {
      cycle(baseline);
      cycles++;
    }

    awaitThreadsGone(baseline);
    System.gc();
    long late = usedHeap();
    System.out.printf("cycles=%d heap=%dMiB -> %dMiB%n", cycles, early >> 20, late >> 20);
    assertThat(cycles).isPositive();
    assertThat(late).as("heap after GC").isLessThan(early + early / 2 + (32L << 20));
  }

  /** Brings a tunnel up, uses it, closes it, and returns the threads that remain. */
  private Set<Thread> cycle(Set<Thread> known) throws Exception {
    try (TestNode client =
            new TestNode("client", Netstack.builder().address("10.61.0.1/24").build());
        TestNode server =
            new TestNode("server", Netstack.builder().address("10.61.0.2/24").build())) {
      link(client, "10.61.0.1", server, "10.61.0.2");
      server.serveDigest(PORT);
      byte[] data = new byte[64 << 10];
      assertThat(client.exchange("10.61.0.2", PORT, data)).isEqualTo(sha256(data));
      assertThat(client.canPing("10.61.0.2", LONG)).isTrue();
    }
    return liveThreads(Set.of());
  }

  private static long usedHeap() {
    return ManagementFactory.getMemoryMXBean().getHeapMemoryUsage().getUsed();
  }
}
