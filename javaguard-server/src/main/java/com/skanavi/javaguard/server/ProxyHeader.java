// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.server;

/** What a local service is told about the peer behind each connection. */
public enum ProxyHeader {
  /** Nothing: the service sees every peer as a local client. */
  NONE,
  /**
   * A PROXY protocol v2 header before the first byte, with the peer's tunnel address and port and
   * its public key in a {@link #PEER_KEY_TLV} field. The service must expect the header, and must
   * accept it only from this host: anyone who can reach the listener can forge it.
   */
  V2;

  /** The TLV type carrying the peer's 32-byte public key, from the protocol's custom range. */
  public static final int PEER_KEY_TLV = 0xE0;
}
