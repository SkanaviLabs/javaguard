// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.cli;

import static org.assertj.core.api.Assertions.assertThat;

import com.skanavi.javaguard.crypto.PrivateKey;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class MainTest {
  private final ByteArrayOutputStream out = new ByteArrayOutputStream();
  private final ByteArrayOutputStream err = new ByteArrayOutputStream();

  private int run(String stdin, String... args) {
    return Main.run(
        args,
        new ByteArrayInputStream(stdin.getBytes(StandardCharsets.US_ASCII)),
        new PrintStream(out, true, StandardCharsets.UTF_8),
        new PrintStream(err, true, StandardCharsets.UTF_8));
  }

  @Test
  void keyCommands() {
    assertThat(run("", "genkey")).isZero();
    String key = out.toString().strip();
    assertThat(PrivateKey.fromBase64(key)).isNotNull();
    out.reset();
    assertThat(run(key + "\n", "pubkey")).isZero();
    assertThat(out.toString().strip()).isEqualTo(PrivateKey.fromBase64(key).publicKey().toBase64());
    out.reset();
    assertThat(run("", "genpsk")).isZero();
    assertThat(out.toString().strip()).hasSize(44);
  }

  @Test
  void reportsUsageAndErrors(@TempDir Path dir) throws Exception {
    assertThat(run("")).isEqualTo(2);
    assertThat(run("", "frobnicate")).isEqualTo(2);
    assertThat(run("garbage", "pubkey")).isEqualTo(1);
    assertThat(run("", "up")).isEqualTo(1);
    Path bad = Files.writeString(dir.resolve("wg0.conf"), "[Interface]\nPostUp = rm -rf /\n");
    assertThat(run("", "up", bad.toString())).isEqualTo(1);
    assertThat(err.toString()).contains("configuration error").contains("line 2");
    assertThat(run("", "up", bad.toString(), "--name", "way-too-long-interface-name")).isEqualTo(1);
  }
}
