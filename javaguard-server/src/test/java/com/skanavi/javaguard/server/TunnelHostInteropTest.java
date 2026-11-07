// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.server;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.skanavi.javaguard.config.WgQuickConfig;
import com.skanavi.javaguard.core.PeerConfig;
import com.skanavi.javaguard.core.interop.Docker;
import com.skanavi.javaguard.core.interop.WireGuardContainer;
import com.skanavi.javaguard.core.interop.WireGuardContainer.Implementation;
import com.skanavi.javaguard.crypto.PrivateKey;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import org.eclipse.jetty.server.Server;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/** A Linux client, with no knowledge of javaguard, using a web server only the tunnel can reach. */
@Tag("interop")
class TunnelHostInteropTest {
  @BeforeAll
  static void requireDocker() throws IOException {
    assumeTrue(Docker.available(), "Docker is not available");
    Docker.buildImage();
  }

  @ParameterizedTest
  @EnumSource(Implementation.class)
  void aLinuxPeerReachesJettyAndNothingElse(Implementation impl) throws Exception {
    PrivateKey key = PrivateKey.generate();
    int port = TunnelClient.freeUdpPort();
    String config =
        "[Interface]\nPrivateKey = "
            + key.toBase64()
            + "\nListenPort = "
            + port
            + "\nAddress = 10.9.0.1/24\n";
    Path dir = Files.createTempDirectory(Path.of("/tmp"), "jg");
    Path socket = dir.resolve("s");
    Server jetty = WebServer.start(socket);
    try (TunnelHost host = TunnelHost.builder().start(WgQuickConfig.parse(config));
        WireGuardContainer peer =
            new WireGuardContainer(impl, key.publicKey(), "host.docker.internal:" + port)) {
      host.addPeer(PeerConfig.builder(peer.publicKey()).allowedIp("10.9.0.2/32").build());
      host.expose(8080, Target.unixSocket(socket), ProxyHeader.V2);

      Docker.Result ping = peer.tryExec("ping -c 1 -W 5 10.9.0.1");
      assertThat(ping.exitCode()).as(ping.output()).isZero();

      Docker.Result page = peer.tryExec("wget -q -O - http://10.9.0.1:8080/");
      assertThat(page.exitCode()).as(page.output()).isZero();
      assertThat(page.output().strip())
          .isEqualTo("10.9.0.2 " + HexFormat.of().formatHex(peer.publicKey().toBytes()));

      Docker.Result closed = peer.tryExec("wget -q -T 3 -O - http://10.9.0.1:8081/");
      assertThat(closed.exitCode()).as("a port that was not exposed").isNotZero();
    } finally {
      jetty.stop();
      Files.deleteIfExists(socket);
      Files.delete(dir);
    }
  }
}
