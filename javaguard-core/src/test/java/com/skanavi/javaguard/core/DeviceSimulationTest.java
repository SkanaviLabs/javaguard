// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core;

import static java.time.Duration.ofMillis;
import static java.time.Duration.ofSeconds;
import static org.assertj.core.api.Assertions.assertThat;

import com.skanavi.javaguard.core.noise.Keypair;
import com.skanavi.javaguard.core.noise.Protocol;
import com.skanavi.javaguard.crypto.PrivateKey;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Protocol behaviour of two devices on virtual time (whitepaper sections 5 and 6). */
class DeviceSimulationTest {
  private Simulation sim;
  private Simulation.Node a;
  private Simulation.Node b;

  @BeforeEach
  void setUp() {
    sim = new Simulation();
    a = sim.node("192.0.2.1", "10.0.0.1");
    b = sim.node("192.0.2.2", "10.0.0.2");
    sim.link(a, b);
  }

  @Test
  void firstPacketTriggersHandshakeAndDataFlowsBothWays() {
    a.send(b, "hello");
    sim.run(ofMillis(1));
    assertThat(b.received()).containsExactly("hello");
    b.send(a, "world");
    sim.run(ofMillis(1));
    assertThat(a.received()).containsExactly("world");

    assertThat(a.peer(b).lastHandshake()).isPresent();
    assertThat(b.peer(a).lastHandshake()).isPresent();
    assertThat(a.peer(b).txBytes()).isPositive();
    assertThat(b.peer(a).rxBytes()).isEqualTo(a.peer(b).txBytes());
    assertThat(sim.count(Protocol.TYPE_INITIATION, a.bind)).isEqualTo(1);
  }

  @Test
  void packetsQueuedDuringHandshakeArriveInOrder() {
    sim.network.drop(p -> true);
    for (int i = 0; i < 5; i++) {
      a.send(b, "p" + i);
    }
    sim.network.heal();
    sim.run(ofSeconds(6)); // first initiation was lost; the retransmission succeeds
    assertThat(b.received()).containsExactly("p0", "p1", "p2", "p3", "p4");
  }

  @Test
  void initiatorRekeysAfterRekeyAfterTimeWithoutLosingTraffic() {
    Set<Integer> sessions = new HashSet<>();
    int sent = 0;
    for (int t = 0; t < 300; t++) {
      a.send(b, "m" + t);
      sent++;
      sim.run(ofSeconds(1));
      sessions.add(a.peer(b).currentKeypair().localIndex());
    }
    assertThat(b.received()).hasSize(sent);
    assertThat(sessions).hasSizeGreaterThanOrEqualTo(2);
  }

  @Test
  void oneWayTrafficFromTheResponderSurvivesRekeying() {
    a.send(b, "start");
    sim.run(ofMillis(1));
    int sent = 0;
    for (int t = 0; t < 300; t++) {
      b.send(a, "m" + t);
      sent++;
      sim.run(ofSeconds(1));
    }
    assertThat(a.received()).hasSize(sent);
    // The initiator re-handshakes shortly before the session it started would be rejected.
    assertThat(sim.count(Protocol.TYPE_INITIATION, a.bind)).isGreaterThanOrEqualTo(2);
  }

  @Test
  void passiveKeepaliveAfterReceivingData() {
    a.send(b, "ping");
    sim.run(ofMillis(1));
    long before = a.peer(b).rxBytes();
    sim.run(ofSeconds(9));
    assertThat(a.peer(b).rxBytes()).isEqualTo(before);
    sim.run(ofSeconds(2));
    assertThat(a.peer(b).rxBytes()).isEqualTo(before + Transport.MIN_LENGTH);
    sim.run(ofSeconds(60));
    assertThat(a.peer(b).rxBytes()).isEqualTo(before + Transport.MIN_LENGTH);
  }

  @Test
  void persistentKeepaliveHandshakesOnStartAndRepeats() {
    a.peer(b).persistentKeepalive(ofSeconds(25));
    a.device.start();
    sim.run(ofMillis(1));
    assertThat(b.peer(a).lastHandshake()).isPresent();
    long keepalivesBefore = transportCount(a);
    sim.run(ofSeconds(101));
    assertThat(transportCount(a) - keepalivesBefore).isEqualTo(4);
  }

  @Test
  void lostHandshakesAreRetriedThenAbandoned() {
    sim.network.drop(p -> p.target().equals(b.bind.address()));
    a.send(b, "lost");
    sim.run(ofSeconds(130));
    long attempts = sim.network.delivered.stream().count();
    assertThat(attempts).isZero(); // all dropped; count initiations via the dropped filter instead
    sim.network.heal();
    sim.run(ofSeconds(1));
    assertThat(b.received()).isEmpty(); // staged packet was flushed after giving up
  }

  @Test
  void retryCountMatchesRekeyAttemptTime() {
    List<Long> initiationTimes = new ArrayList<>();
    sim.network.drop(
        p -> {
          if (p.type() == Protocol.TYPE_INITIATION) {
            initiationTimes.add(sim.clock.nanoTime());
          }
          return true;
        });
    a.send(b, "lost");
    sim.run(ofSeconds(200));
    // One initial attempt plus retries until REKEY_ATTEMPT_TIME / REKEY_TIMEOUT is exceeded.
    assertThat(initiationTimes).hasSize(20);
    for (int i = 1; i < initiationTimes.size(); i++) {
      long gap = initiationTimes.get(i) - initiationTimes.get(i - 1);
      assertThat(gap).isBetween(ofSeconds(5).toNanos(), ofMillis(5333).toNanos());
    }
  }

  @Test
  void sessionsAreRejectedAfterRejectAfterTime() {
    a.send(b, "first");
    sim.run(ofMillis(1));
    sim.network.drop(
        p -> p.type() == Protocol.TYPE_INITIATION || p.type() == Protocol.TYPE_RESPONSE);
    List<String> expectDelivered = new ArrayList<>();
    expectDelivered.add("first");
    for (int t = 1; t <= 200; t++) {
      sim.run(ofSeconds(1));
      a.send(b, "t" + t);
      if (t < 179) {
        expectDelivered.add("t" + t);
      }
    }
    sim.run(ofMillis(1));
    List<String> got = b.received();
    assertThat(got).containsSequence(expectDelivered);
    assertThat(got).doesNotContain("t181", "t190", "t200");
  }

  @Test
  void peerRoamingUpdatesTheEndpoint() {
    a.send(b, "hi");
    sim.run(ofMillis(1));
    InetSocketAddress moved = new InetSocketAddress(InetAddress.ofLiteral("198.51.100.7"), 4000);
    b.bind.moveTo(moved);
    b.send(a, "from new address");
    sim.run(ofMillis(1));
    assertThat(a.received()).containsExactly("from new address");
    assertThat(a.peer(b).endpoint()).contains(moved);
    a.send(b, "reply");
    sim.run(ofMillis(1));
    assertThat(b.received()).containsExactly("hi", "reply");
  }

  @Test
  void responderUnderLoadDemandsCookie() {
    b.device.forceUnderLoad = true;
    a.send(b, "behind cookie");
    sim.run(ofSeconds(1));
    assertThat(b.received()).isEmpty();
    assertThat(sim.count(Protocol.TYPE_COOKIE_REPLY, b.bind)).isEqualTo(1);
    sim.run(ofSeconds(5));
    assertThat(b.received()).containsExactly("behind cookie");
  }

  @Test
  void dropsPacketsFromSourcesOutsideAllowedIps() {
    a.send(b, "hi");
    sim.run(ofMillis(1));
    b.sendFrom(InetAddress.ofLiteral("10.0.0.99").getAddress(), a, "spoofed");
    b.send(a, "legit");
    sim.run(ofMillis(1));
    assertThat(a.received()).containsExactly("legit");
  }

  @Test
  void dropsReplayedTransportMessages() {
    a.send(b, "once");
    sim.run(ofMillis(1));
    SimNetwork.Packet data =
        sim.network.delivered.stream()
            .filter(p -> p.type() == Protocol.TYPE_TRANSPORT && p.data().length > 32)
            .findFirst()
            .orElseThrow();
    sim.network.inject(data);
    sim.network.inject(data);
    sim.run(ofMillis(1));
    assertThat(b.received()).containsExactly("once");
  }

  @Test
  void rekeysWhenCounterPassesRekeyAfterMessages() {
    a.send(b, "one");
    sim.run(ofMillis(1));
    sim.run(ofSeconds(6)); // past REKEY_TIMEOUT, so a new initiation is allowed
    Keypair first = a.peer(b).currentKeypair();
    a.peer(b).setSendCounter(Protocol.REKEY_AFTER_MESSAGES + 1);
    a.send(b, "two");
    sim.run(ofMillis(1));
    assertThat(b.received()).containsExactly("one", "two");
    assertThat(a.peer(b).currentKeypair()).isNotSameAs(first);
  }

  @Test
  void neverSendsBeyondRejectAfterMessages() {
    a.send(b, "one");
    sim.run(ofMillis(1));
    sim.run(ofSeconds(6)); // past REKEY_TIMEOUT, so a new initiation is allowed
    Keypair first = a.peer(b).currentKeypair();
    a.peer(b).setSendCounter(Protocol.REJECT_AFTER_MESSAGES);
    a.send(b, "two");
    sim.run(ofMillis(1));
    assertThat(a.peer(b).currentKeypair()).isNotSameAs(first);
    assertThat(b.received()).containsExactly("one", "two"); // sent under the new session
  }

  @Test
  void keyMaterialIsErasedAfterThreeRejectAfterTimes() {
    a.send(b, "hi");
    sim.run(ofMillis(1));
    sim.run(ofSeconds(539));
    assertThat(a.peer(b).currentKeypair()).isNotNull();
    sim.run(ofSeconds(2));
    assertThat(a.peer(b).currentKeypair()).isNull();
    assertThat(a.device.indices.size()).isZero();
    a.send(b, "again");
    sim.run(ofMillis(1));
    assertThat(b.received()).containsExactly("hi", "again");
  }

  @Test
  void simultaneousInitiationsConverge() {
    a.send(b, "from a");
    b.send(a, "from b");
    sim.run(ofSeconds(30));
    assertThat(b.received()).contains("from a");
    assertThat(a.received()).contains("from b");
    a.send(b, "after");
    b.send(a, "after");
    sim.run(ofMillis(1));
    assertThat(b.received()).containsExactly("after");
    assertThat(a.received()).containsExactly("after");
  }

  @Test
  void responderWithoutEndpointLearnsItFromTheInitiator() {
    Simulation s = new Simulation();
    Simulation.Node client = s.node("192.0.2.10", "10.0.0.10");
    Simulation.Node server = s.node("192.0.2.20", "10.0.0.20");
    client.connect(server, true);
    server.connect(client, false);
    server.send(client, "nowhere to go");
    s.run(ofSeconds(1));
    assertThat(client.received()).isEmpty();
    client.send(server, "hello server");
    s.run(ofMillis(1));
    server.send(client, "hello client");
    s.run(ofMillis(1));
    assertThat(server.received()).containsExactly("hello server");
    assertThat(client.received()).containsExactly("nowhere to go", "hello client");
  }

  @Test
  void removingAPeerErasesItsSessions() {
    a.send(b, "hi");
    sim.run(ofMillis(1));
    assertThat(a.device.indices.size()).isEqualTo(1);
    assertThat(a.device.removePeer(b.device.publicKey())).isTrue();
    assertThat(a.device.indices.size()).isZero();
    b.send(a, "orphan");
    sim.run(ofMillis(1));
    assertThat(a.received()).isEmpty();
  }

  @Test
  void changingThePrivateKeyRequiresANewHandshake() {
    a.send(b, "old key");
    sim.run(ofMillis(1));
    PrivateKey fresh = PrivateKey.generate();
    a.device.privateKey(fresh);
    b.device.removePeer(b.device.peers().iterator().next().publicKey());
    b.connect(a, true);
    a.send(b, "new key");
    sim.run(ofMillis(1));
    assertThat(b.received()).containsExactly("old key", "new key");
  }

  private long transportCount(Simulation.Node from) {
    return sim.count(Protocol.TYPE_TRANSPORT, from.bind);
  }
}
