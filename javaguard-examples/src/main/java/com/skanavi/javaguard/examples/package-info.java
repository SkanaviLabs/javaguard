// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

/**
 * Small programs showing how to embed javaguard. Each takes a wg-quick style configuration whose
 * {@code [Interface]} has an {@code Address} (and usually {@code DNS}); {@link
 * com.skanavi.javaguard.examples.Tunnel} turns it into a running device with a userspace network
 * stack.
 */
package com.skanavi.javaguard.examples;
