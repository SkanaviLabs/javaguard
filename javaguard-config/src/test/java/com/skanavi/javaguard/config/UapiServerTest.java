// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.skanavi.javaguard.core.Device;
import com.skanavi.javaguard.core.PacketPipe;
import com.skanavi.javaguard.core.UdpBind;
import com.skanavi.javaguard.crypto.PrivateKey;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.Writer;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.Channels;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class UapiServerTest {
  @TempDir Path dir;
  private Device device;

  @BeforeEach
  void setUp() throws Exception {
    device =
        Device.builder()
            .privateKey(PrivateKey.generate())
            .bind(UdpBind.open(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0)))
            .tun(new PacketPipe(1420))
            .build();
  }

  @AfterEach
  void tearDown() throws Exception {
    device.close();
  }

  @Test
  void servesGetOverTheSocketWithOwnerOnlyPermissions() throws Exception {
    Path sock = dir.resolve("wg0.sock");
    try (UapiServer server = UapiServer.start(device, UdpBind::open, sock)) {
      assertThat(server.path()).isEqualTo(sock);
      assertThat(Files.getPosixFilePermissions(sock))
          .isEqualTo(PosixFilePermissions.fromString("rw-------"));
      assertThat(exchange(sock, "get=1\n\n"))
          .startsWith("private_key=" + device.privateKey().toHex());
      assertThat(exchange(sock, "get=1\n\n")).endsWith("errno=0\n\n"); // new connection works too
    }
    assertThat(sock).doesNotExist();
  }

  @Test
  void replacesStaleSocketsButNotLiveOnes() throws Exception {
    Path sock = dir.resolve("wg1.sock");
    Files.createFile(sock); // stale leftover
    try (UapiServer server = UapiServer.start(device, UdpBind::open, sock)) {
      assertThatThrownBy(() -> UapiServer.start(device, UdpBind::open, sock))
          .isInstanceOf(IOException.class)
          .hasMessageContaining("another process");
      assertThat(server.socketExists()).isTrue();
      Files.delete(sock);
      assertThat(server.socketExists()).isFalse();
    }
  }

  @Test
  void createsTheParentDirectory() throws Exception {
    Path sock = dir.resolve("run/wireguard/wg2.sock");
    try (UapiServer server = UapiServer.start(device, UdpBind::open, sock)) {
      assertThat(server.path().getParent()).isDirectory();
    }
  }

  private static String exchange(Path sock, String request) throws IOException {
    try (SocketChannel ch = SocketChannel.open(StandardProtocolFamily.UNIX)) {
      ch.connect(UnixDomainSocketAddress.of(sock));
      Writer w = Channels.newWriter(ch, StandardCharsets.UTF_8);
      w.write(request);
      w.flush();
      ch.shutdownOutput();
      BufferedReader r = new BufferedReader(Channels.newReader(ch, StandardCharsets.UTF_8));
      StringBuilder sb = new StringBuilder();
      String line;
      while ((line = r.readLine()) != null) {
        sb.append(line).append('\n');
      }
      return sb.toString();
    }
  }
}
