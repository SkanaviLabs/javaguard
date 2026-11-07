// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.netstack;

import static com.skanavi.javaguard.netstack.TestNode.LONG;
import static com.skanavi.javaguard.netstack.TestNode.address;
import static com.skanavi.javaguard.netstack.TestNode.await;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.time.Duration;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

@SuppressWarnings("try") // sockets held open for the length of a block
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class TcpInboundLimitTest extends TunnelTestBase {
  private static final int PORT = 9000;
  private static final Duration BRIEF = Duration.ofSeconds(1);

  private TestNode limited(Netstack.Builder limits) throws IOException {
    return track(new TestNode("server", limits.address("10.40.0.1/24").build()));
  }

  @Test
  void theLimitPerRemoteAppliesUntilAConnectionCloses() throws Exception {
    TestNode server = limited(Netstack.builder().tcpMaxInboundPerRemote(2));
    TestNode client = node("client", "10.40.0.2/24");
    link(server, "10.40.0.1", client, "10.40.0.2");
    TcpListener listener = server.stack.listenTcp(PORT);

    TcpSocket first = client.stack.connectTcp(address("10.40.0.1", PORT), LONG);
    TcpSocket second = client.stack.connectTcp(address("10.40.0.1", PORT), LONG);
    assertThatThrownBy(() -> client.stack.connectTcp(address("10.40.0.1", PORT), BRIEF))
        .isInstanceOf(SocketTimeoutException.class);
    assertThat(server.stack.refusedTcpConnections()).isPositive();

    first.abort();
    listener.accept().abort();
    await("the slot to come back", () -> server.stack.tcpConnectionCount() == 1);
    client.stack.connectTcp(address("10.40.0.1", PORT), LONG).close();
    second.close();
  }

  @Test
  void theTotalLimitCoversAllRemotes() throws Exception {
    TestNode server = limited(Netstack.builder().tcpMaxInbound(1));
    TestNode a = node("a", "10.40.0.2/24");
    TestNode b = node("b", "10.40.0.3/24");
    server.connect(a, "10.40.0.2/32");
    server.connect(b, "10.40.0.3/32");
    a.connect(server, "10.40.0.1/32");
    b.connect(server, "10.40.0.1/32");
    server.start();
    a.start();
    b.start();
    try (TcpListener listener = server.stack.listenTcp(PORT);
        TcpSocket held = a.stack.connectTcp(address("10.40.0.1", PORT), LONG)) {
      assertThatThrownBy(() -> b.stack.connectTcp(address("10.40.0.1", PORT), BRIEF))
          .isInstanceOf(SocketTimeoutException.class);
    }
  }

  /** A server that closes first leaves TIME_WAIT behind for each request; that must not count. */
  @Test
  void connectionsInTimeWaitDoNotCount() throws Exception {
    TestNode server = limited(Netstack.builder().tcpMaxInboundPerRemote(2));
    TestNode client = node("client", "10.40.0.2/24");
    link(server, "10.40.0.1", client, "10.40.0.2");
    TcpListener listener = server.stack.listenTcp(PORT);

    for (int i = 0; i < 20; i++) {
      try (TcpSocket s = client.stack.connectTcp(address("10.40.0.1", PORT), LONG)) {
        TcpSocket accepted = listener.accept();
        accepted.outputStream().write(i);
        accepted.close();
        assertThat(s.inputStream().readAllBytes()).containsExactly((byte) i);
      }
      await(
          "TIME_WAIT",
          () ->
              server.stack.tcpDiagnostics().stream()
                  .noneMatch(d -> d.contains("ESTABLISHED") || d.contains("FIN_WAIT")));
    }
    assertThat(server.stack.refusedTcpConnections()).isZero();
    assertThat(server.stack.tcpConnectionCount()).isEqualTo(20);
  }
}
