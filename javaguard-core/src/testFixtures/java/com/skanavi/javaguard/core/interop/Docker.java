// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core.interop;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.TimeUnit;

/** Minimal Docker CLI wrapper for interop tests (shared as a test fixture). */
public final class Docker {
  public static final String IMAGE = "javaguard-interop-wg:5";
  private static final String DOCKERFILE =
      "FROM alpine:3.22\nRUN apk add --no-cache wireguard-tools-wg wireguard-go socat dnsmasq busybox-extras openssl\n";

  private Docker() {}

  public static boolean available() {
    try {
      return exec(null, "docker", "info").exitCode == 0;
    } catch (IOException e) {
      return false;
    }
  }

  public static void buildImage() throws IOException {
    buildImage(IMAGE, DOCKERFILE);
  }

  /** Builds {@code dockerfile} (no build context) as {@code tag}. */
  public static void buildImage(String tag, String dockerfile) throws IOException {
    check(exec(dockerfile, "docker", "build", "-q", "-t", tag, "-"), "docker build " + tag);
  }

  /** Runs a command, failing the test on a non-zero exit; returns trimmed stdout. */
  public static String run(String... command) throws IOException {
    return check(exec(null, command), String.join(" ", command));
  }

  public static String runWithInput(String input, String... command) throws IOException {
    return check(exec(input, command), String.join(" ", command));
  }

  public record Result(int exitCode, String output) {}

  public static Result exec(String input, String... command) throws IOException {
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
