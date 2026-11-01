// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

/** A local SOCKS5/HTTP proxy that lets unmodified applications use a javaguard tunnel. */
module com.skanavi.javaguard.proxy {
  requires transitive com.skanavi.javaguard.netstack;
  requires transitive java.net.http;

  exports com.skanavi.javaguard.proxy;
}
