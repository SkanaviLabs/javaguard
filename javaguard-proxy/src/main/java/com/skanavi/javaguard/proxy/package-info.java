// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

/**
 * {@link com.skanavi.javaguard.proxy.LocalProxy} accepts SOCKS5 and HTTP proxy connections on a
 * host socket and carries them through a {@link com.skanavi.javaguard.netstack.Netstack}, so
 * browsers, {@code curl} and {@link java.net.http.HttpClient} can use the tunnel without root.
 */
package com.skanavi.javaguard.proxy;
