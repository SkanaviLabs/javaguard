// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

/**
 * Cryptographic primitives for WireGuard ({@code Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s}).
 *
 * <p>X25519 and ChaCha20-Poly1305 delegate to the JDK's JCA providers, which use HotSpot intrinsics
 * where available. BLAKE2s, HMAC-BLAKE2s, the WireGuard KDF, HChaCha20/XChaCha20 and TAI64N are
 * implemented here. Stateful classes ({@link Blake2s}, {@link HmacBlake2s}, {@link
 * ChaCha20Poly1305}, {@link XChaCha20Poly1305}) are not thread-safe; use one instance per thread.
 */
package com.skanavi.javaguard.crypto;
