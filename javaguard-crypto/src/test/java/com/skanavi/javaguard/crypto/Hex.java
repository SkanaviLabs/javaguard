// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.crypto;

import java.util.HexFormat;

final class Hex {
  private Hex() {}

  static byte[] bytes(String hex) {
    return HexFormat.of().parseHex(hex.replaceAll("\\s", ""));
  }

  static String hex(byte[] b) {
    return HexFormat.of().formatHex(b);
  }
}
