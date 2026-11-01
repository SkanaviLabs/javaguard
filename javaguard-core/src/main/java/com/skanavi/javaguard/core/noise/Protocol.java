// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core.noise;

import static java.nio.charset.StandardCharsets.US_ASCII;

import com.skanavi.javaguard.crypto.Blake2s;
import java.time.Duration;

/** Protocol constants from the WireGuard whitepaper. */
public final class Protocol {
  private Protocol() {}

  /** Message type of a handshake initiation. */
  public static final int TYPE_INITIATION = 1;

  /** Message type of a handshake response. */
  public static final int TYPE_RESPONSE = 2;

  /** Message type of a cookie reply. */
  public static final int TYPE_COOKIE_REPLY = 3;

  /** Message type of a transport data message. */
  public static final int TYPE_TRANSPORT = 4;

  /** Send a new handshake after this many messages under one keypair. */
  public static final long REKEY_AFTER_MESSAGES = 1L << 60;

  /** Never use a keypair for more than this many messages (as unsigned: 2^64 - 2^13 - 1). */
  public static final long REJECT_AFTER_MESSAGES = -(1L << 13) - 1;

  /** Initiate a new handshake when the current keypair is this old. */
  public static final Duration REKEY_AFTER_TIME = Duration.ofSeconds(120);

  /** Never use a keypair older than this. */
  public static final Duration REJECT_AFTER_TIME = Duration.ofSeconds(180);

  /** Give up retrying a handshake after this long. */
  public static final Duration REKEY_ATTEMPT_TIME = Duration.ofSeconds(90);

  /** Retransmit a handshake initiation after this long (plus jitter). */
  public static final Duration REKEY_TIMEOUT = Duration.ofSeconds(5);

  /** Send a keepalive when data was received but nothing sent for this long. */
  public static final Duration KEEPALIVE_TIMEOUT = Duration.ofSeconds(10);

  /** Lifetime of a cookie, and rotation period of the cookie secret. */
  public static final Duration COOKIE_REFRESH_TIME = Duration.ofSeconds(120);

  /** Minimum interval between accepted initiations from one peer (at most 50 per second). */
  public static final Duration HANDSHAKE_INITIATION_RATE = Duration.ofMillis(20);

  static final byte[] CONSTRUCTION = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".getBytes(US_ASCII);
  static final byte[] IDENTIFIER = "WireGuard v1 zx2c4 Jason@zx2c4.com".getBytes(US_ASCII);
  static final byte[] LABEL_MAC1 = "mac1----".getBytes(US_ASCII);
  static final byte[] LABEL_COOKIE = "cookie--".getBytes(US_ASCII);

  /** {@code HASH(CONSTRUCTION)}: the initial chaining key. */
  static final byte[] INITIAL_CHAIN_KEY = Blake2s.hash(CONSTRUCTION);

  /** {@code HASH(INITIAL_CHAIN_KEY || IDENTIFIER)}: the initial handshake hash. */
  static final byte[] INITIAL_HASH = Blake2s.hash(INITIAL_CHAIN_KEY, IDENTIFIER);
}
