// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core.interop;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.skanavi.javaguard.core.interop.WireGuardContainer.Implementation;
import com.skanavi.javaguard.core.noise.CookieChecker;
import com.skanavi.javaguard.core.noise.Handshake;
import com.skanavi.javaguard.core.noise.HandshakeInitiation;
import com.skanavi.javaguard.core.noise.HandshakeResponse;
import com.skanavi.javaguard.core.noise.IndexTable;
import com.skanavi.javaguard.core.noise.Keypair;
import com.skanavi.javaguard.core.noise.Messages;
import com.skanavi.javaguard.core.noise.Noise;
import com.skanavi.javaguard.core.noise.Protocol;
import com.skanavi.javaguard.core.noise.StaticIdentity;
import com.skanavi.javaguard.core.noise.TimeSource;
import com.skanavi.javaguard.crypto.PresharedKey;
import com.skanavi.javaguard.crypto.PrivateKey;
import com.skanavi.javaguard.crypto.PublicKey;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketTimeoutException;
import java.security.SecureRandom;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * Handshakes against real WireGuard implementations (the Linux kernel module and wireguard-go) in a
 * Docker container, in both roles, and proves the derived keys by exchanging ICMP echo packets with
 * the container's IP stack.
 */
@Tag("interop")
class HandshakeInteropTest {
  private static final byte[] JAVA_IP = {10, 9, 0, 1};
  private static final byte[] KERNEL_IP = {10, 9, 0, 2};

  private final StaticIdentity identity = new StaticIdentity(PrivateKey.generate());
  private final Noise noise =
      new Noise(identity, new IndexTable(), TimeSource.system(), new SecureRandom());
  private final CookieChecker checker =
      new CookieChecker(identity, TimeSource.system(), new SecureRandom());
  private WireGuardContainer container;

  @BeforeAll
  static void requireDocker() throws IOException {
    assumeTrue(Docker.available(), "Docker is not available");
    Docker.buildImage();
  }

  @AfterEach
  void removeContainer() throws IOException {
    if (container != null) {
      container.close();
    }
  }

  @ParameterizedTest
  @EnumSource(Implementation.class)
  void javaguardInitiatesPeerResponds(Implementation impl) throws Exception {
    Handshake hs = noise.newHandshake(startPeer(impl, null), PresharedKey.NONE);
    InetSocketAddress kernel = container.endpoint();

    try (DatagramSocket socket =
        new DatagramSocket(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0))) {
      socket.setSoTimeout(3000);
      Keypair keypair = null;
      for (int attempt = 0; attempt < 5 && keypair == null; attempt++) {
        HandshakeInitiation init = noise.createInitiation(hs);
        hs.cookieGenerator().addMacs(init);
        send(socket, init.bytes(), kernel);
        DatagramPacket p = receive(socket);
        if (p == null) {
          continue;
        }
        HandshakeResponse response = HandshakeResponse.parse(p.getData(), 0, p.getLength());
        assertThat(response).as("kernel reply is a handshake response").isNotNull();
        assertThat(checker.checkMac1(response)).as("kernel mac1").isTrue();
        assertThat(noise.consumeResponse(response)).as("consume kernel response").isSameAs(hs);
        keypair = noise.beginSession(hs);
      }
      assertThat(keypair).as("handshake completed").isNotNull();
      System.out.println("Handshake with kernel complete: " + keypair);

      byte[] payload = "javaguard interop".getBytes();
      byte[] ping = Packets.icmpEcho(JAVA_IP, KERNEL_IP, 8, 0x4a47, 1, payload);
      send(socket, Packets.seal(keypair, 0, ping), kernel);

      byte[] reply = null;
      for (int i = 0; i < 10 && reply == null; i++) {
        DatagramPacket p = receive(socket);
        if (p != null && Messages.type(p.getData(), 0, p.getLength()) == Protocol.TYPE_TRANSPORT) {
          byte[] ip = Packets.open(keypair, p.getData(), p.getLength());
          if (Packets.isIcmp(ip, 0, KERNEL_IP)) {
            reply = ip;
          }
        }
      }
      assertThat(reply).as("ICMP echo reply from the kernel").isNotNull();
      System.out.println("Kernel answered our encrypted ping");
    }
    assertThat(container.exec("wg show wg0 latest-handshakes")).doesNotEndWith("\t0");
  }

  @ParameterizedTest
  @EnumSource(Implementation.class)
  void peerInitiatesJavaguardRespondsWithCookieChallenge(Implementation impl) throws Exception {
    try (DatagramSocket socket = new DatagramSocket(new InetSocketAddress(0))) {
      socket.setSoTimeout(1000);
      Handshake hs =
          noise.newHandshake(
              startPeer(impl, "host.docker.internal:" + socket.getLocalPort()), PresharedKey.NONE);
      CompletableFuture<Docker.Result> ping =
          CompletableFuture.supplyAsync(
              () -> {
                try {
                  return container.tryExec("ping -c 1 -W 25 10.9.0.1");
                } catch (IOException e) {
                  throw new RuntimeException(e);
                }
              });

      boolean challenged = false;
      Keypair keypair = null;
      boolean answered = false;
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30);
      while (!answered && System.nanoTime() < deadline) {
        DatagramPacket p = receive(socket);
        if (p == null) {
          continue;
        }
        SocketAddress from = p.getSocketAddress();
        switch (Messages.type(p.getData(), 0, p.getLength())) {
          case Protocol.TYPE_INITIATION -> {
            if (keypair != null) {
              continue;
            }
            HandshakeInitiation init = HandshakeInitiation.parse(p.getData(), 0, p.getLength());
            assertThat(checker.checkMac1(init)).as("kernel mac1").isTrue();
            byte[] source = CookieChecker.sourceBytes((InetSocketAddress) from);
            if (!challenged) {
              // Pretend to be under load: answer with a cookie instead of a handshake.
              assertThat(checker.checkMac2(init, source)).isFalse();
              send(socket, checker.createReply(init, source).bytes(), from);
              challenged = true;
              System.out.println("Sent cookie reply; waiting for retransmission with mac2");
              continue;
            }
            assertThat(checker.checkMac2(init, source)).as("kernel mac2 uses our cookie").isTrue();
            assertThat(noise.consumeInitiation(init, k -> k.equals(hs.remoteStatic()) ? hs : null))
                .isSameAs(hs);
            HandshakeResponse response = noise.createResponse(hs);
            hs.cookieGenerator().addMacs(response);
            send(socket, response.bytes(), from);
            keypair = noise.beginSession(hs);
            System.out.println("Responded to kernel initiation: " + keypair);
          }
          case Protocol.TYPE_TRANSPORT -> {
            assertThat(keypair).as("transport only after handshake").isNotNull();
            byte[] ip = Packets.open(keypair, p.getData(), p.getLength());
            if (Packets.isIcmp(ip, 8, KERNEL_IP)) {
              send(socket, Packets.seal(keypair, 0, Packets.echoReply(ip)), from);
              answered = true;
            }
          }
          default -> {}
        }
      }
      assertThat(challenged).as("kernel retried after cookie reply").isTrue();
      assertThat(answered).as("received kernel's encrypted ping").isTrue();
      Docker.Result result = ping.get(30, TimeUnit.SECONDS);
      assertThat(result.exitCode()).as("kernel ping succeeded: %s", result.output()).isZero();
      System.out.println("Kernel received our encrypted ping reply");
    }
  }

  private PublicKey startPeer(Implementation impl, String endpoint) throws IOException {
    container = new WireGuardContainer(impl, identity.publicKey(), endpoint);
    return container.publicKey();
  }

  private static void send(DatagramSocket socket, byte[] data, SocketAddress to)
      throws IOException {
    socket.send(new DatagramPacket(data, data.length, to));
  }

  private static DatagramPacket receive(DatagramSocket socket) throws IOException {
    DatagramPacket p = new DatagramPacket(new byte[2048], 2048);
    try {
      socket.receive(p);
      return p;
    } catch (SocketTimeoutException e) {
      return null;
    }
  }
}
