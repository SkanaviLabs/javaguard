// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.netstack;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** A listener whose connection sits in TIME_WAIT, driven with scripted segments. */
@Timeout(value = 30, unit = TimeUnit.SECONDS)
class TcpTimeWaitTest {
  private static final byte[] CLIENT = {10, 0, 0, 1};
  private static final byte[] SERVER = {10, 0, 0, 2};
  private static final int CLIENT_PORT = 50000;
  private static final int SERVER_PORT = 7;
  private static final int CLOSED_PORT = 9;
  private static final int FIRST_ISN = 1_000_000;
  private static final int WINDOW = 65535;

  private Netstack server;
  private TcpListener listener;

  @BeforeEach
  void timeWaitOnTheListener() throws Exception {
    server = Netstack.builder().address("10.0.0.2/24").tcpTimeWait(Duration.ofMinutes(1)).build();
    listener = server.listenTcp(SERVER_PORT);

    send(TcpSegment.SYN, FIRST_ISN, 0);
    TcpSegment synAck = receive();
    send(TcpSegment.ACK, FIRST_ISN + 1, synAck.seq() + 1);
    listener.accept(Duration.ofSeconds(5)).close();

    TcpSegment fin = receive();
    assertThat(fin.has(TcpSegment.FIN)).isTrue();
    send(TcpSegment.FIN | TcpSegment.ACK, FIRST_ISN + 1, fin.seq() + 1);
    drain(); // now in TIME_WAIT
  }

  @AfterEach
  void tearDown() {
    listener.close();
    server.close();
  }

  @ParameterizedTest(name = "isn offset {0}")
  @ValueSource(ints = {1000, -1000})
  void newConnectionReplacesTimeWait(int offset) throws Exception {
    int isn = FIRST_ISN + offset;
    send(TcpSegment.SYN, isn, 0);
    TcpSegment synAck = receive();
    assertThat(synAck.has(TcpSegment.SYN)).isTrue();
    assertThat(synAck.ack()).isEqualTo(isn + 1);

    send(TcpSegment.ACK, isn + 1, synAck.seq() + 1);
    assertThat(listener.accept(Duration.ofSeconds(5))).isNotNull();
  }

  @Test
  void oldDuplicateSynDoesNotOpenAConnection() throws Exception {
    send(TcpSegment.SYN, FIRST_ISN, 0);
    TcpSegment answer = receive();
    assertThat(answer.has(TcpSegment.SYN)).isFalse();
    assertThat(answer.has(TcpSegment.ACK)).isTrue();
    assertThat(listener.accept(Duration.ofMillis(100))).isNull();
  }

  /** Discards queued output: a SYN to a closed port draws a RST behind whatever is pending. */
  private void drain() {
    send(CLOSED_PORT, TcpSegment.SYN, 1, 0);
    while (!receive().has(TcpSegment.RST)) {
      // keep reading
    }
  }

  private void send(int flags, int seq, int ack) {
    send(SERVER_PORT, flags, seq, ack);
  }

  private void send(int port, int flags, int seq, int ack) {
    byte[] packet =
        TcpSegment.build(
            CLIENT, SERVER, CLIENT_PORT, port, seq, ack, flags, WINDOW, 1460, -1, null, 0, 0, 1);
    server.write(packet, 0, packet.length);
  }

  private TcpSegment receive() {
    byte[] buffer = new byte[2048];
    int n = server.read(buffer, 0, buffer.length);
    return TcpSegment.parse(IpPacket.parse(buffer, n));
  }
}
