// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import com.skanavi.javaguard.core.noise.Protocol;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.time.Duration;
import org.junit.jupiter.api.Tag;

/**
 * Feeds arbitrary datagrams to a device with an established session. Inputs are steered toward deep
 * paths: transport messages carry the live receiver index, so they reach decryption, and
 * handshake-shaped messages have the right lengths. Any exception is a finding.
 */
@Tag("fuzz")
class DeviceFuzzTest {
  private static final Simulation SIM = new Simulation();
  private static final Simulation.Node A = SIM.node("192.0.2.1", "10.0.0.1");
  private static final Simulation.Node B = SIM.node("192.0.2.2", "10.0.0.2");
  private static final InetSocketAddress FROM =
      new InetSocketAddress(InetAddress.ofLiteral("198.51.100.9"), 4444);

  static {
    SIM.link(A, B);
    A.send(B, "establish");
    SIM.run(Duration.ofMillis(1));
  }

  @FuzzTest(maxDuration = "60s")
  void datagramsNeverThrow(FuzzedDataProvider in) {
    int shape = in.consumeInt(0, 3);
    byte[] packet;
    switch (shape) {
      case 0 -> { // transport message for the live session
        var keypair = B.peer(A).currentKeypair();
        byte[] body = in.consumeBytes(in.consumeInt(0, 1500));
        packet = new byte[16 + body.length];
        ByteBuffer.wrap(packet)
            .order(ByteOrder.LITTLE_ENDIAN)
            .putInt(Protocol.TYPE_TRANSPORT)
            .putInt(keypair == null ? in.consumeInt() : keypair.localIndex())
            .putLong(in.consumeLong());
        System.arraycopy(body, 0, packet, 16, body.length);
      }
      case 1 -> packet = typed(Protocol.TYPE_INITIATION, 148, in);
      case 2 -> packet = typed(Protocol.TYPE_RESPONSE, 92, in);
      default -> packet = in.consumeRemainingAsBytes();
    }
    B.device.processDatagram(packet, 0, packet.length, FROM);
    SIM.network.deliverAll();
  }

  private static byte[] typed(int type, int length, FuzzedDataProvider in) {
    byte[] p = new byte[length];
    byte[] rest = in.consumeBytes(length - 4);
    System.arraycopy(rest, 0, p, 4, rest.length);
    p[0] = (byte) type;
    return p;
  }
}
