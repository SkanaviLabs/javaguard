// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.server;

import com.skanavi.javaguard.crypto.PublicKey;
import com.skanavi.javaguard.netstack.TcpSocket;

/**
 * A TCP connection from a peer.
 *
 * @param peer the peer's public key, fixed when the connection is accepted; the connection is reset
 *     if its address stops belonging to this peer
 * @param socket the connection
 */
public record TunnelConnection(PublicKey peer, TcpSocket socket) {}
