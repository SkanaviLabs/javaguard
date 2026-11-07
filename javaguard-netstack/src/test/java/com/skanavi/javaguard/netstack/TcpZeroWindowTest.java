// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.netstack;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * ACKs across a closed window, driven with scripted segments.
 *
 * <p>Two ends that each fill the other's window used to deadlock: one end's receive buffer was full
 * and it accepted a pure ACK only at exactly {@code rcvNxt}, while the other stamped its ACKs with
 * {@code sndMax}, a segment beyond. Neither end's ACK got through, so both retransmitted until they
 * gave up.
 */
@Timeout(value = 30, unit = TimeUnit.SECONDS)
class TcpZeroWindowTest {
  private static final byte[] CLIENT = {10, 0, 0, 1};
  private static final byte[] SERVER = {10, 0, 0, 2};
  private static final int CLIENT_PORT = 50000;
  private static final int SERVER_PORT = 7;
  private static final int CLOSED_PORT = 9;
  private static final int ISN = 1_000_000;
  private static final int MSS = 1460;
  private static final int SENT = 3000;

  private Netstack server;
  private TcpListener listener;
  private TcpSocket socket;
  private int serverIsn;

  @BeforeEach
  void connected() throws Exception {
    server = Netstack.builder().address("10.0.0.2/24").build();
    listener = server.listenTcp(SERVER_PORT);
    send(TcpSegment.SYN, ISN, 0, 65535, null);
    TcpSegment synAck = receive();
    serverIsn = synAck.seq();
    send(TcpSegment.ACK, ISN + 1, serverIsn + 1, 65535, null);
    socket = listener.accept(Duration.ofSeconds(5));
    assertThat(socket).isNotNull();

    // The server sends data that the client will not acknowledge yet.
    socket.outputStream().write(new byte[SENT]);
    int got = 0;
    while (got < SENT) {
      got += receive().dataLength();
    }
  }

  @AfterEach
  void tearDown() {
    socket.abort();
    listener.close();
    server.close();
  }

  @Test
  void pureAckStaysInsideAClosedWindow() {
    // The client closes its window with all of the server's data unacknowledged, then sends data.
    send(TcpSegment.ACK, ISN + 1, serverIsn + 1, 0, null);
    send(TcpSegment.ACK | TcpSegment.PSH, ISN + 1, serverIsn + 1, 0, new byte[100]);

    TcpSegment ack = nextPureAck();
    assertThat(ack.ack()).isEqualTo(ISN + 101);
    // A receiver whose window is closed takes an ACK only at exactly its rcvNxt, which here is the
    // server's sndUna. sndMax, 3000 bytes further, would be discarded with its ACK field.
    assertThat(ack.seq()).isEqualTo(serverIsn + 1);
  }

  @ParameterizedTest(name = "{0} bytes left free")
  @ValueSource(ints = {0, 4000})
  void ackBeyondTheWindowIsTaken(int free) throws Exception {
    // Fill the server's receive buffer to `free` bytes short; its application never reads.
    int seq = ISN + 1;
    for (int left = TcpConnection.BUFFER_SIZE - free; left > 0; left -= MSS) {
      int n = Math.min(MSS, left);
      send(TcpSegment.ACK, seq, serverIsn + 1, 65535, new byte[n]);
      seq += n;
    }
    drain();

    // The client sent past the room that was left, so its next sequence number lies beyond the
    // server's window. This ACK acknowledges all of the server's data.
    send(TcpSegment.ACK, seq + free + MSS, serverIsn + 1 + SENT, 65535, null);

    // Had the ACK been discarded, the server would retransmit from serverIsn + 1 when its
    // retransmission timer (initially one second) fired.
    var segments = new LinkedBlockingQueue<TcpSegment>();
    Thread.ofVirtual()
        .start(
            () -> {
              while (true) {
                segments.add(receive());
              }
            });
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
    long left;
    while ((left = deadline - System.nanoTime()) > 0) {
      TcpSegment s = segments.poll(left, TimeUnit.NANOSECONDS);
      if (s != null) {
        assertThat(s.dataLength() > 0 && s.seq() == serverIsn + 1)
            .as("retransmission of acknowledged data")
            .isFalse();
      }
    }
  }

  @Test
  void pureAckCarriesSndMaxWhileTheWindowIsOpen() {
    // The client acknowledges nothing but keeps its window open, then sends data.
    send(TcpSegment.ACK | TcpSegment.PSH, ISN + 1, serverIsn + 1, 65535, new byte[100]);

    TcpSegment ack = nextPureAck();
    assertThat(ack.ack()).isEqualTo(ISN + 101);
    // Anything below sndMax could lie behind what the client already received and be discarded.
    assertThat(ack.seq()).isEqualTo(serverIsn + 1 + SENT);
  }

  private TcpSegment nextPureAck() {
    while (true) {
      TcpSegment s = receive();
      if (s.dataLength() == 0 && s.has(TcpSegment.ACK) && !s.has(TcpSegment.SYN)) {
        return s;
      }
    }
  }

  /** Discards queued output: a SYN to a closed port draws a RST behind whatever is pending. */
  private void drain() {
    send(CLOSED_PORT, TcpSegment.SYN, 1, 0, 65535, null);
    while (!receive().has(TcpSegment.RST)) {
      // keep reading
    }
  }

  private void send(int flags, int seq, int ack, int window, byte[] data) {
    send(SERVER_PORT, flags, seq, ack, window, data);
  }

  private void send(int port, int flags, int seq, int ack, int window, byte[] data) {
    int length = data == null ? 0 : data.length;
    byte[] packet =
        TcpSegment.build(
            CLIENT,
            SERVER,
            CLIENT_PORT,
            port,
            seq,
            ack,
            flags,
            window,
            (flags & TcpSegment.SYN) != 0 ? MSS : -1,
            -1,
            data,
            0,
            length,
            1);
    server.write(packet, 0, packet.length);
  }

  private TcpSegment receive() {
    byte[] buffer = new byte[2048];
    int n = server.read(buffer, 0, buffer.length);
    return TcpSegment.parse(IpPacket.parse(buffer, n));
  }
}
