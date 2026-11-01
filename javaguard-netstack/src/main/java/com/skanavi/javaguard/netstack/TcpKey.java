// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.netstack;

import java.net.InetAddress;

/** Identifies a TCP connection by its four-tuple. */
record TcpKey(InetAddress localAddress, int localPort, InetAddress remoteAddress, int remotePort) {}
