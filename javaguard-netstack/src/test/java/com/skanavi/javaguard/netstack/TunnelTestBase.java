// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.netstack;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterEach;

/** Creates {@link TestNode}s and closes whatever a test left open. */
abstract class TunnelTestBase {
  private final List<AutoCloseable> resources = new ArrayList<>();

  @AfterEach
  void closeEverything() throws Exception {
    for (AutoCloseable c : resources.reversed()) {
      c.close();
    }
  }

  <T extends AutoCloseable> T track(T resource) {
    resources.add(resource);
    return resource;
  }

  /** A node with {@code addresses}, in CIDR form. */
  TestNode node(String name, String... addresses) throws IOException {
    Netstack.Builder stack = Netstack.builder();
    for (String address : addresses) {
      stack.address(address);
    }
    return track(new TestNode(name, stack.build()));
  }

  /** Joins {@code a} and {@code b}, each routing its peer's {@code /32} or {@code /128}. */
  static void link(TestNode a, String aIp, TestNode b, String bIp) {
    a.connect(b, host(bIp));
    b.connect(a, host(aIp));
    a.start();
    b.start();
  }

  private static String host(String ip) {
    return ip + (ip.contains(":") ? "/128" : "/32");
  }
}
