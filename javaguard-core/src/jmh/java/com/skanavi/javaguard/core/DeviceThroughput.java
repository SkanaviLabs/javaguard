// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core;

import com.skanavi.javaguard.crypto.PrivateKey;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;

/**
 * End-to-end throughput of two devices over loopback UDP: raw 1420-byte IPv4 packets go into one
 * device's {@link PacketPipe} and are counted coming out of the other's. Run with {@code ./gradlew
 * :javaguard-core:throughput [-Pseconds=10]}.
 */
public final class DeviceThroughput {
  private DeviceThroughput() {}

  public static void main(String[] args) throws Exception {
    int seconds = args.length > 0 ? Integer.parseInt(args[0]) : 10;
    InetAddress lo = InetAddress.getLoopbackAddress();
    PrivateKey ka = PrivateKey.generate();
    PrivateKey kb = PrivateKey.generate();
    PacketPipe pa = new PacketPipe(1420, 8192);
    PacketPipe pb = new PacketPipe(1420, 8192);
    try (Device a =
            Device.builder()
                .privateKey(ka)
                .bind(UdpBind.open(new InetSocketAddress(lo, 0)))
                .tun(pa)
                .build();
        Device b =
            Device.builder()
                .privateKey(kb)
                .bind(UdpBind.open(new InetSocketAddress(lo, 0)))
                .tun(pb)
                .build()) {
      a.addPeer(
          PeerConfig.builder(kb.publicKey())
              .endpoint(new InetSocketAddress(lo, b.listenPort()))
              .allowedIp("10.0.0.2/32")
              .build());
      b.addPeer(
          PeerConfig.builder(ka.publicKey())
              .endpoint(new InetSocketAddress(lo, a.listenPort()))
              .allowedIp("10.0.0.1/32")
              .build());
      a.start();
      b.start();
      byte[] packet = new byte[1420];
      packet[0] = 0x45;
      packet[2] = (byte) (1420 >>> 8);
      packet[3] = (byte) 1420;
      packet[9] = (byte) 253;
      byte[] src = {10, 0, 0, 1};
      byte[] dst = {10, 0, 0, 2};
      System.arraycopy(src, 0, packet, 12, 4);
      System.arraycopy(dst, 0, packet, 16, 4);

      AtomicLong received = new AtomicLong();
      Thread sink =
          Thread.ofPlatform()
              .daemon()
              .start(
                  () -> {
                    try {
                      while (true) {
                        if (pb.receive(Duration.ofSeconds(1)) != null) {
                          received.incrementAndGet();
                        }
                      }
                    } catch (InterruptedException e) {
                      // done
                    }
                  });
      // Warm up and complete the handshake.
      long warmEnd = System.nanoTime() + 3_000_000_000L;
      while (System.nanoTime() < warmEnd) {
        pa.send(packet);
      }
      long sent = 0;
      long startReceived = received.get();
      long start = System.nanoTime();
      long end = start + seconds * 1_000_000_000L;
      while (System.nanoTime() < end) {
        if (pa.send(packet)) {
          sent++;
        } else {
          Thread.onSpinWait();
        }
      }
      double elapsed = (System.nanoTime() - start) / 1e9;
      long got = received.get() - startReceived;
      System.out.printf(
          "offered %.0f Mbit/s, delivered %.0f Mbit/s (%d of %d packets, %.1f%% loss)%n",
          sent * 1420 * 8 / elapsed / 1e6,
          got * 1420 * 8 / elapsed / 1e6,
          got,
          sent,
          100.0 * (sent - got) / Math.max(1, sent));
      sink.interrupt();
    }
  }
}
