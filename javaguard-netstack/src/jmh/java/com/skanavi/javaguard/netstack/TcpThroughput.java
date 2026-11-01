// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.netstack;

import com.skanavi.javaguard.core.Device;
import com.skanavi.javaguard.core.PeerConfig;
import com.skanavi.javaguard.core.UdpBind;
import com.skanavi.javaguard.crypto.PrivateKey;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Duration;

/**
 * One TCP stream between two netstacks through two devices over loopback UDP. Run with {@code
 * ./gradlew :javaguard-netstack:throughput [-Pseconds=10]}.
 */
public final class TcpThroughput {
  private TcpThroughput() {}

  public static void main(String[] args) throws Exception {
    int seconds = args.length > 0 ? Integer.parseInt(args[0]) : 10;
    InetAddress lo = InetAddress.getLoopbackAddress();
    PrivateKey ka = PrivateKey.generate();
    PrivateKey kb = PrivateKey.generate();
    Netstack sa = Netstack.builder().address("10.0.0.1/24").build();
    Netstack sb = Netstack.builder().address("10.0.0.2/24").build();
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
      TcpListener l = sb.listenTcp(5001);
      long[] total = new long[1];
      Thread sink =
          Thread.ofPlatform()
              .daemon()
              .start(
                  () -> {
                    try (TcpSocket s = l.accept();
                        InputStream in = s.inputStream()) {
                      byte[] buf = new byte[256 * 1024];
                      int n;
                      while ((n = in.read(buf)) >= 0) {
                        synchronized (total) {
                          total[0] += n;
                        }
                      }
                    } catch (Exception e) {
                      // done
                    }
                  });
      try (TcpSocket s =
          sa.connectTcp(
              new InetSocketAddress(InetAddress.ofLiteral("10.0.0.2"), 5001),
              Duration.ofSeconds(10))) {
        OutputStream out = s.outputStream();
        byte[] chunk = new byte[64 * 1024];
        long warmEnd = System.nanoTime() + 3_000_000_000L;
        while (System.nanoTime() < warmEnd) {
          out.write(chunk);
        }
        long before;
        synchronized (total) {
          before = total[0];
        }
        long start = System.nanoTime();
        long end = start + seconds * 1_000_000_000L;
        while (System.nanoTime() < end) {
          out.write(chunk);
        }
        long after;
        synchronized (total) {
          after = total[0];
        }
        double elapsed = (System.nanoTime() - start) / 1e9;
        System.out.printf("TCP goodput %.0f Mbit/s%n", (after - before) * 8 / elapsed / 1e6);
        s.abort();
      }
      sink.join(1000);
    }
  }
}
