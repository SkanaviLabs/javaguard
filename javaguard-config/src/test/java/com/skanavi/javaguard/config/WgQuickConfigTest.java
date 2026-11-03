// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.skanavi.javaguard.core.HostAddress;
import com.skanavi.javaguard.core.IpPrefix;
import com.skanavi.javaguard.crypto.PresharedKey;
import com.skanavi.javaguard.crypto.PrivateKey;
import com.skanavi.javaguard.crypto.PublicKey;
import java.net.InetAddress;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class WgQuickConfigTest {
  private static final PrivateKey KEY = PrivateKey.generate();
  private static final PublicKey PEER1 = PrivateKey.generate().publicKey();
  private static final PublicKey PEER2 = PrivateKey.generate().publicKey();
  private static final PresharedKey PSK = PresharedKey.generate();

  private static final String SAMPLE =
      """
      # A typical client configuration
      [Interface]
      PrivateKey = %s
      Address = 10.0.0.2/24, fd00::2/64
      DNS = 10.0.0.1, corp.example
      MTU = 1380
      listenport=51821   # keys are case-insensitive

      [Peer]
      PublicKey = %s
      PresharedKey = %s
      AllowedIPs = 10.0.0.0/24
      AllowedIPs = fd00::/64
      Endpoint = [2001:db8::1]:51820
      PersistentKeepalive = 25

      [peer]
      PublicKey=%s
      Endpoint = vpn.example.com:443
      PersistentKeepalive = off
      """
          .formatted(KEY.toBase64(), PEER1.toBase64(), PSK.toBase64(), PEER2.toBase64());

  @Test
  void parsesATypicalConfiguration() throws Exception {
    WgQuickConfig c = WgQuickConfig.parse(SAMPLE);
    assertThat(c.iface().privateKey()).isEqualTo(KEY);
    assertThat(c.iface().listenPort()).isEqualTo(51821);
    assertThat(c.iface().addresses()) // host bits are kept, unlike allowed IPs
        .containsExactly(HostAddress.parse("10.0.0.2/24"), HostAddress.parse("fd00::2/64"));
    assertThat(c.iface().addresses().get(0)).hasToString("10.0.0.2/24");
    assertThat(c.iface().dns()).containsExactly(InetAddress.ofLiteral("10.0.0.1"));
    assertThat(c.iface().dnsSearch()).containsExactly("corp.example");
    assertThat(c.iface().mtu()).isEqualTo(1380);

    assertThat(c.peers()).hasSize(2);
    WgQuickConfig.PeerSection p1 = c.peers().get(0);
    assertThat(p1.publicKey()).isEqualTo(PEER1);
    assertThat(p1.presharedKey()).isEqualTo(PSK);
    assertThat(p1.allowedIps())
        .containsExactly(IpPrefix.parse("10.0.0.0/24"), IpPrefix.parse("fd00::/64"));
    assertThat(p1.endpoint()).isEqualTo(new WgQuickConfig.Endpoint("2001:db8::1", 51820));
    assertThat(p1.persistentKeepalive()).isEqualTo(Duration.ofSeconds(25));

    WgQuickConfig.PeerSection p2 = c.peers().get(1);
    assertThat(p2.presharedKey()).isEqualTo(PresharedKey.NONE);
    assertThat(p2.endpoint()).isEqualTo(new WgQuickConfig.Endpoint("vpn.example.com", 443));
    assertThat(p2.persistentKeepalive()).isZero();
    assertThat(p2.allowedIps()).isEmpty();
  }

  @Test
  void formatRoundTrips() throws Exception {
    WgQuickConfig c = WgQuickConfig.parse(SAMPLE);
    assertThat(WgQuickConfig.parse(c.format())).isEqualTo(c);
    assertThat(c.format()).contains("Endpoint = [2001:db8::1]:51820");
  }

  @Test
  void resolvesLiteralEndpointsWithoutDns() throws Exception {
    var peer = WgQuickConfig.parse(SAMPLE).peers().get(0).resolve();
    assertThat(peer.endpoint().getAddress()).isEqualTo(InetAddress.ofLiteral("2001:db8::1"));
    assertThat(peer.allowedIps()).hasSize(2);
  }

  @Test
  void reportsErrorsWithLineNumbers() {
    assertError("[Interface]\nPrivateKey = " + KEY.toBase64() + "\nBogus = 1\n", 3, "unknown key");
    assertError("PrivateKey = " + KEY.toBase64() + "\n", 1, "outside of a section");
    assertError("[Interface]\nPrivateKey = nope\n", 2, "base64");
    assertError(
        "[Interface]\nPrivateKey = " + KEY.toBase64() + "\n[Peer]\nEndpoint = 1.2.3.4:5\n",
        3,
        "no PublicKey");
    assertError("[Interface]\n[Interface]\n", 2, "duplicate");
    assertError(
        "[Interface]\nPrivateKey = " + KEY.toBase64() + "\nListenPort = 70000\n", 3, "ListenPort");
    assertError(
        "[Interface]\nPrivateKey = "
            + KEY.toBase64()
            + "\n[Peer]\nPublicKey = "
            + PEER1.toBase64()
            + "\nAllowedIPs = 10.0.0.0/40\n",
        5,
        "prefix length");
    assertError("[Wat]\n", 1, "unknown section");
    assertError("[Peer]\nPublicKey = " + PEER1.toBase64() + "\n", 0, "missing [Interface]");
    assertError("[Interface]\nListenPort = 1\n", 0, "no PrivateKey");
  }

  @Test
  void rejectsOsLevelKeysUnlessLenient() throws Exception {
    String text =
        "[Interface]\nPrivateKey = " + KEY.toBase64() + "\nPostUp = iptables -A ...\nTable = off\n";
    assertError(text, 3, "not supported");
    List<String> warnings = new ArrayList<>();
    WgQuickConfig c = WgQuickConfig.parseLenient(text, warnings);
    assertThat(c.iface().privateKey()).isEqualTo(KEY);
    assertThat(warnings).hasSize(2).allMatch(w -> w.contains("ignored"));
  }

  private static void assertError(String text, int line, String message) {
    assertThatThrownBy(() -> WgQuickConfig.parse(text))
        .isInstanceOf(ConfigException.class)
        .hasMessageContaining(message)
        .satisfies(e -> assertThat(((ConfigException) e).line()).isEqualTo(line));
  }

  @Test
  void keepsOsLevelKeysWhenParsedForHost() throws Exception {
    String text =
        """
        [Interface]
        PrivateKey = %s
        Table = 1234
        FwMark = 0xca6c
        PreUp = echo pre %%i
        PostUp = echo up1
        PostUp = echo up2
        PreDown = echo predown
        PostDown = echo down
        SaveConfig = true
        """
            .formatted(KEY.toBase64());
    WgQuickConfig c = WgQuickConfig.parseForHost(text);
    WgQuickConfig.HostSettings h = c.host();
    assertThat(h.table()).isEqualTo("1234");
    assertThat(h.fwMark()).isEqualTo(0xca6c);
    assertThat(h.preUp()).containsExactly("echo pre %i");
    assertThat(h.postUp()).containsExactly("echo up1", "echo up2");
    assertThat(h.preDown()).containsExactly("echo predown");
    assertThat(h.postDown()).containsExactly("echo down");
    assertThat(h.saveConfig()).isTrue();
    assertThat(h.hasHooks()).isTrue();
    assertThat(WgQuickConfig.parseForHost(c.format())).isEqualTo(c);

    assertThat(WgQuickConfig.parseForHost(SAMPLE).host())
        .isEqualTo(WgQuickConfig.HostSettings.NONE);
    assertThat(WgQuickConfig.parseLenient(text, new ArrayList<>()).host())
        .isEqualTo(WgQuickConfig.HostSettings.NONE);
    assertThatThrownBy(
            () -> WgQuickConfig.parseForHost(text.replace("Table = 1234", "Table = 1; rm")))
        .hasMessageContaining("invalid Table");
    assertThatThrownBy(() -> WgQuickConfig.parseForHost(text.replace("0xca6c", "0x1ffffffff")))
        .hasMessageContaining("FwMark");
  }
}
