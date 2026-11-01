// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.config;

/** A configuration file could not be parsed. */
public final class ConfigException extends Exception {
  private static final long serialVersionUID = 1L;

  /** The 1-based line number of the problem, or 0. */
  private final int line;

  /** Creates an exception for a problem on 1-based {@code line} (0 if not line-specific). */
  public ConfigException(int line, String message) {
    super(line > 0 ? "line " + line + ": " + message : message);
    this.line = line;
  }

  /** The 1-based line number, or 0. */
  public int line() {
    return line;
  }
}
