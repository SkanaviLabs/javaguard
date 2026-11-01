// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

/**
 * The WireGuard handshake layer: wire message codecs, the {@code Noise_IKpsk2} handshake ({@link
 * com.skanavi.javaguard.core.noise.Noise}), session keypairs, receiver index allocation, and the
 * cookie (mac1/mac2) DoS-mitigation mechanism.
 *
 * <p>This is a low-level API. It performs no I/O and no timer handling; the device layer drives it.
 * Malformed or unauthenticated input never throws: parse and consume methods return {@code null}.
 */
package com.skanavi.javaguard.core.noise;
