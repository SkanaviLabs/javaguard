// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core.noise;

import java.security.SecureRandom;
import java.util.concurrent.ConcurrentHashMap;
import java.util.random.RandomGenerator;

/**
 * Maps the random 32-bit receiver indices that peers put in their messages to the local handshake
 * or keypair they refer to. Thread-safe.
 */
public final class IndexTable {
  /** Something an index can refer to. */
  public sealed interface Entry permits Handshake, Keypair {}

  private final ConcurrentHashMap<Integer, Entry> entries = new ConcurrentHashMap<>();
  private final RandomGenerator random;

  /** Creates a table that draws indices from a {@link SecureRandom}. */
  public IndexTable() {
    this(new SecureRandom());
  }

  /** Creates a table that draws indices from {@code random}. */
  public IndexTable(RandomGenerator random) {
    this.random = random;
  }

  /** Assigns a fresh unused non-zero index to {@code entry}. */
  int allocate(Entry entry) {
    while (true) {
      int index = random.nextInt();
      if (index != 0 && entries.putIfAbsent(index, entry) == null) {
        return index;
      }
    }
  }

  /**
   * Re-points {@code index} from {@code expected} to {@code replacement}, if it still maps there.
   */
  boolean replace(int index, Entry expected, Entry replacement) {
    return entries.replace(index, expected, replacement);
  }

  /** Returns the entry for {@code index}, or {@code null}. */
  public Entry get(int index) {
    return entries.get(index);
  }

  /** Releases {@code index} if it maps to {@code entry}. */
  public boolean remove(int index, Entry entry) {
    return entries.remove(index, entry);
  }

  /** Number of allocated indices. */
  public int size() {
    return entries.size();
  }
}
