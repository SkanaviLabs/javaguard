// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.config;

import static org.assertj.core.api.Assertions.assertThat;

import com.skanavi.javaguard.core.Device;
import com.skanavi.javaguard.core.IpPrefix;
import com.skanavi.javaguard.core.PacketPipe;
import com.skanavi.javaguard.core.Peer;
import com.skanavi.javaguard.core.UdpBind;
import com.skanavi.javaguard.crypto.PresharedKey;
import com.skanavi.javaguard.crypto.PrivateKey;
import com.skanavi.javaguard.crypto.PublicKey;
import java.io.BufferedReader;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class UapiTest {
  private final PrivateKey key = PrivateKey.generate();
  private final PublicKey peerKey = PrivateKey.generate().publicKey();
  private Device device;
  private Uapi uapi;

  @BeforeEach
  void setUp() throws Exception {
    device =
        Device.builder()
            .privateKey(key)
            .bind(UdpBind.open(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0)))
            .tun(new PacketPipe(1420))
            .build();
    uapi =
        new Uapi(
            device,
            port -> UdpBind.open(new InetSocketAddress(InetAddress.getLoopbackAddress(), port)));
  }

  @AfterEach
  void tearDown() throws Exception {
    device.close();
  }

  @Test
  void getReportsTheDevice() {
    assertThat(uapi.get())
        .isEqualTo(
            "private_key="
                + key.toHex()
                + "\nlisten_port="
                + device.listenPort()
                + "\nerrno=0\n\n");
  }

  @Test
  void setCreatesAndConfiguresAPeer() {
    PresharedKey psk = PresharedKey.generate();
    int errno =
        uapi.set(
            List.of(
                "public_key=" + peerKey.toHex(),
                "preshared_key=" + psk.toHex(),
                "endpoint=[2001:db8::1]:51820",
                "persistent_keepalive_interval=25",
                "allowed_ip=10.0.0.0/24",
                "allowed_ip=fd00::/64"));
    assertThat(errno).isZero();
    Peer p = device.peer(peerKey);
    assertThat(p.presharedKey()).isEqualTo(psk);
    assertThat(p.endpoint())
        .contains(new InetSocketAddress(InetAddress.ofLiteral("2001:db8::1"), 51820));
    assertThat(p.persistentKeepalive()).isEqualTo(Duration.ofSeconds(25));
    assertThat(p.allowedIps())
        .containsExactly(IpPrefix.parse("10.0.0.0/24"), IpPrefix.parse("fd00::/64"));

    assertThat(uapi.get())
        .contains("public_key=" + peerKey.toHex() + "\n")
        .contains("preshared_key=" + psk.toHex() + "\n")
        .contains("protocol_version=1\n")
        .contains("endpoint=[2001:db8::1]:51820\n")
        .contains("last_handshake_time_sec=0\nlast_handshake_time_nsec=0\n")
        .contains("tx_bytes=0\nrx_bytes=0\n")
        .contains("persistent_keepalive_interval=25\n")
        .contains("allowed_ip=10.0.0.0/24\nallowed_ip=fd00::/64\n")
        .endsWith("errno=0\n\n");
  }

  @Test
  void allowedIpsCanBeReplacedRemovedAndMoved() {
    PublicKey other = PrivateKey.generate().publicKey();
    uapi.set(
        List.of(
            "public_key=" + peerKey.toHex(), "allowed_ip=10.0.0.0/24", "allowed_ip=10.1.0.0/24"));
    uapi.set(List.of("public_key=" + peerKey.toHex(), "allowed_ip=-10.0.0.0/24"));
    assertThat(device.peer(peerKey).allowedIps()).containsExactly(IpPrefix.parse("10.1.0.0/24"));
    uapi.set(List.of("public_key=" + other.toHex(), "allowed_ip=10.1.0.0/24"));
    assertThat(device.peer(peerKey).allowedIps()).isEmpty(); // moved to the other peer
    uapi.set(
        List.of(
            "public_key=" + other.toHex(), "replace_allowed_ips=true", "allowed_ip=10.2.0.0/16"));
    assertThat(device.peer(other).allowedIps()).containsExactly(IpPrefix.parse("10.2.0.0/16"));
  }

  @Test
  void updateOnlyRemoveAndReplacePeers() {
    assertThat(
            uapi.set(
                List.of(
                    "public_key=" + peerKey.toHex(), "update_only=true", "allowed_ip=10.0.0.0/8")))
        .isZero();
    assertThat(device.peer(peerKey)).isNull();
    uapi.set(List.of("public_key=" + peerKey.toHex()));
    assertThat(device.peer(peerKey)).isNotNull();
    uapi.set(List.of("public_key=" + peerKey.toHex(), "remove=true"));
    assertThat(device.peer(peerKey)).isNull();

    PublicKey a = PrivateKey.generate().publicKey();
    PublicKey b = PrivateKey.generate().publicKey();
    uapi.set(List.of("public_key=" + a.toHex(), "public_key=" + peerKey.toHex()));
    uapi.set(List.of("replace_peers=true", "public_key=" + b.toHex()));
    assertThat(device.peers()).extracting(Peer::publicKey).containsExactly(b);
  }

  @Test
  void changesKeyAndPort() throws Exception {
    PrivateKey next = PrivateKey.generate();
    int port;
    try (var probe = new java.net.DatagramSocket(0, InetAddress.getLoopbackAddress())) {
      port = probe.getLocalPort();
    }
    assertThat(uapi.set(List.of("private_key=" + next.toHex(), "listen_port=" + port, "fwmark=0")))
        .isZero();
    assertThat(device.privateKey()).isEqualTo(next);
    assertThat(device.listenPort()).isEqualTo(port);
  }

  @Test
  void rejectsInvalidRequests() {
    assertThat(uapi.set(List.of("bogus=1"))).isEqualTo(Uapi.EINVAL);
    assertThat(uapi.set(List.of("no equals sign"))).isEqualTo(Uapi.EPROTO);
    assertThat(uapi.set(List.of("fwmark=7"))).isEqualTo(Uapi.EINVAL);
    assertThat(uapi.set(List.of("private_key=" + "00".repeat(32)))).isEqualTo(Uapi.EINVAL);
    assertThat(uapi.set(List.of("public_key=zz"))).isEqualTo(Uapi.EINVAL);
    assertThat(uapi.set(List.of("public_key=" + peerKey.toHex(), "endpoint=vpn.example.com:1")))
        .isEqualTo(Uapi.EINVAL);
    assertThat(uapi.set(List.of("public_key=" + peerKey.toHex(), "public_key=" + peerKey.toHex())))
        .isEqualTo(Uapi.EINVAL);
    assertThat(uapi.set(List.of("public_key=" + key.publicKey().toHex()))).isEqualTo(Uapi.EINVAL);
    assertThat(uapi.set(List.of("public_key=" + peerKey.toHex(), "protocol_version=2")))
        .isEqualTo(Uapi.EINVAL);
    // An invalid line inside a peer block rejects the whole block before it is applied.
    assertThat(device.peer(peerKey)).isNull();
  }

  @Test
  void rejectsOverlongLines() {
    String request = "set=1\n" + "x".repeat(70_000) + "\n\n";
    org.assertj.core.api.Assertions.assertThatThrownBy(
            () -> uapi.serve(new BufferedReader(new StringReader(request)), new StringWriter()))
        .isInstanceOf(java.io.IOException.class)
        .hasMessageContaining("longer than");
  }

  @Test
  void servesSeveralOperationsPerConnection() throws Exception {
    String request =
        "set=1\npublic_key="
            + peerKey.toHex()
            + "\nallowed_ip=10.9.0.0/24\n\nget=1\n\nnope=1\n\nget=1\n\n";
    StringWriter out = new StringWriter();
    uapi.serve(new BufferedReader(new StringReader(request)), out);
    String response = out.toString();
    assertThat(response).startsWith("errno=0\n\nprivate_key=");
    assertThat(response).contains("allowed_ip=10.9.0.0/24\n");
    assertThat(response).endsWith("errno=0\n\nerrno=22\n\n"); // unknown op ends the exchange
  }
}
