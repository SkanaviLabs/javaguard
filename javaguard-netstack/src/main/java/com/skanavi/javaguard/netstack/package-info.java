// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

/**
 * A userspace network stack for javaguard: {@link com.skanavi.javaguard.netstack.Netstack} is a
 * {@link com.skanavi.javaguard.core.Tun} that gives the application its own IP addresses inside the
 * tunnel, with ICMP echo, UDP sockets and a DNS resolver. TCP follows in a later release.
 */
package com.skanavi.javaguard.netstack;
