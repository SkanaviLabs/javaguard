// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core;

import com.skanavi.javaguard.crypto.PresharedKey;
import com.skanavi.javaguard.crypto.PublicKey;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Configuration for one peer, as in a {@code [Peer]} section.
 *
 * @param publicKey the peer's public key
 * @param presharedKey the pre-shared key, {@link PresharedKey#NONE} if unused
 * @param endpoint where to send to the peer until it roams, or {@code null} to wait for it
 * @param allowedIps the inner addresses routed to and accepted from this peer
 * @param persistentKeepalive interval for unsolicited keepalives, {@link Duration#ZERO} for off
 */
public record PeerConfig(
    PublicKey publicKey,
    PresharedKey presharedKey,
    InetSocketAddress endpoint,
    List<IpPrefix> allowedIps,
    Duration persistentKeepalive) {

  /** Validates fields and copies the list. */
  public PeerConfig {
    Objects.requireNonNull(publicKey, "publicKey");
    Objects.requireNonNull(presharedKey, "presharedKey");
    allowedIps = List.copyOf(allowedIps);
    if (persistentKeepalive.isNegative() || persistentKeepalive.toSeconds() > 65535) {
      throw new IllegalArgumentException("persistent keepalive must be 0..65535 seconds");
    }
    if (endpoint != null && endpoint.isUnresolved()) {
      throw new IllegalArgumentException("endpoint must be resolved: " + endpoint);
    }
  }

  /** Starts a builder for the peer with {@code publicKey}. */
  public static Builder builder(PublicKey publicKey) {
    return new Builder(publicKey);
  }

  /** Builder for {@link PeerConfig}. */
  public static final class Builder {
    private final PublicKey publicKey;
    private PresharedKey presharedKey = PresharedKey.NONE;
    private InetSocketAddress endpoint;
    private final List<IpPrefix> allowedIps = new ArrayList<>();
    private Duration persistentKeepalive = Duration.ZERO;

    private Builder(PublicKey publicKey) {
      this.publicKey = publicKey;
    }

    /** Sets the pre-shared key. */
    public Builder presharedKey(PresharedKey key) {
      this.presharedKey = key;
      return this;
    }

    /** Sets the initial endpoint. */
    public Builder endpoint(InetSocketAddress endpoint) {
      this.endpoint = endpoint;
      return this;
    }

    /** Adds an allowed IP prefix. */
    public Builder allowedIp(IpPrefix prefix) {
      allowedIps.add(prefix);
      return this;
    }

    /** Adds an allowed IP prefix in {@code address/length} form. */
    public Builder allowedIp(String prefix) {
      return allowedIp(IpPrefix.parse(prefix));
    }

    /** Sets the persistent keepalive interval. */
    public Builder persistentKeepalive(Duration interval) {
      this.persistentKeepalive = interval;
      return this;
    }

    /** Builds the configuration. */
    public PeerConfig build() {
      return new PeerConfig(publicKey, presharedKey, endpoint, allowedIps, persistentKeepalive);
    }
  }
}
