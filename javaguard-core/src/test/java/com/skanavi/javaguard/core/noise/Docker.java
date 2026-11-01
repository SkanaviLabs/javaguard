// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core.noise;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.TimeUnit;

/** Minimal Docker CLI wrapper for interop tests. */
final class Docker {
  static final String IMAGE = "javaguard-interop-wg:2";
  private static final String DOCKERFILE =
      "FROM alpine:3.22\nRUN apk add --no-cache wireguard-tools-wg wireguard-go\n";

  private Docker() {}

  static boolean available() {
    try {
      return exec(null, "docker", "info").exitCode == 0;
    } catch (IOException e) {
      return false;
    }
  }

  static void buildImage() throws IOException {
    check(exec(DOCKERFILE, "docker", "build", "-q", "-t", IMAGE, "-"), "docker build");
  }

  /** Runs a command, failing the test on a non-zero exit; returns trimmed stdout. */
  static String run(String... command) throws IOException {
    return check(exec(null, command), String.join(" ", command));
  }

  static String runWithInput(String input, String... command) throws IOException {
    return check(exec(input, command), String.join(" ", command));
  }

  record Result(int exitCode, String output) {}

  static Result exec(String input, String... command) throws IOException {
    Process p = new ProcessBuilder(List.of(command)).redirectErrorStream(true).start();
    if (input != null) {
      p.getOutputStream().write(input.getBytes(StandardCharsets.UTF_8));
    }
    p.getOutputStream().close();
    try {
      String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
      if (!p.waitFor(180, TimeUnit.SECONDS)) {
        p.destroyForcibly();
        throw new IOException("timed out: " + String.join(" ", command));
      }
      return new Result(p.exitValue(), out.strip());
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IOException(e);
    }
  }

  private static String check(Result r, String what) {
    if (r.exitCode != 0) {
      throw new AssertionError(what + " failed (" + r.exitCode + "): " + r.output);
    }
    return r.output;
  }
}
