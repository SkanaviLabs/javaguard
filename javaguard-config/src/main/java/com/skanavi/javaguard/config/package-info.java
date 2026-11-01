// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

/**
 * Configuration front ends for {@link com.skanavi.javaguard.core.Device}: {@link
 * com.skanavi.javaguard.config.WgQuickConfig} reads and writes wg-quick style files, and {@link
 * com.skanavi.javaguard.config.UapiServer} serves the cross-platform userspace API so the stock
 * {@code wg} tool can inspect and change a running device.
 */
package com.skanavi.javaguard.config;
