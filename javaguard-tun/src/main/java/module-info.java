// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

/**
 * Operating-system TUN interfaces for javaguard. This is the only javaguard module that calls
 * native code (through {@code java.lang.foreign}); run with {@code
 * --enable-native-access=com.skanavi.javaguard.tun}.
 */
module com.skanavi.javaguard.tun {
  requires transitive com.skanavi.javaguard.core;

  exports com.skanavi.javaguard.tun;
}
