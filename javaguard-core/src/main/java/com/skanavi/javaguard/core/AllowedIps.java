// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core;

// Portions derived from wireguard-go (https://git.zx2c4.com/wireguard-go/),
// Copyright (C) 2017-2025 WireGuard LLC. MIT.

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Cryptokey routing table: maps IP prefixes to owners (peers) with longest-prefix-match lookup. One
 * binary trie per address family. Thread-safe; lookups take a read lock only.
 *
 * @param <T> the owner type
 */
final class AllowedIps<T> {
  private static final class Node<T> {
    Node<T> zero;
    Node<T> one;
    T owner;
    IpPrefix prefix;
  }

  private final Node<T> v4 = new Node<>();
  private final Node<T> v6 = new Node<>();
  private final ReadWriteLock lock = new ReentrantReadWriteLock();

  /** Routes {@code prefix} to {@code owner}, taking it over from any previous owner. */
  void insert(IpPrefix prefix, T owner) {
    byte[] addr = prefix.address().getAddress();
    lock.writeLock().lock();
    try {
      Node<T> node = root(addr.length);
      for (int i = 0; i < prefix.length(); i++) {
        if (bit(addr, 0, i) == 0) {
          node = node.zero == null ? (node.zero = new Node<>()) : node.zero;
        } else {
          node = node.one == null ? (node.one = new Node<>()) : node.one;
        }
      }
      node.owner = owner;
      node.prefix = prefix;
    } finally {
      lock.writeLock().unlock();
    }
  }

  /**
   * Returns the owner of the longest prefix containing the address at {@code addr[off..off+len)},
   * where {@code len} is 4 or 16; {@code null} if none.
   */
  T lookup(byte[] addr, int off, int len) {
    lock.readLock().lock();
    try {
      Node<T> node = root(len);
      T best = node.owner;
      for (int i = 0; i < len * 8 && node != null; i++) {
        node = bit(addr, off, i) == 0 ? node.zero : node.one;
        if (node != null && node.owner != null) {
          best = node.owner;
        }
      }
      return best;
    } finally {
      lock.readLock().unlock();
    }
  }

  /** Removes {@code prefix} if {@code owner} owns it; returns whether it did. */
  boolean remove(IpPrefix prefix, T owner) {
    byte[] addr = prefix.address().getAddress();
    lock.writeLock().lock();
    try {
      Node<T> node = root(addr.length);
      for (int i = 0; i < prefix.length() && node != null; i++) {
        node = bit(addr, 0, i) == 0 ? node.zero : node.one;
      }
      if (node == null || node.owner != owner || !prefix.equals(node.prefix)) {
        return false;
      }
      node.owner = null;
      node.prefix = null;
      return true;
    } finally {
      lock.writeLock().unlock();
    }
  }

  /** Removes every prefix owned by {@code owner}. */
  void removeAll(T owner) {
    lock.writeLock().lock();
    try {
      prune(v4, owner);
      prune(v6, owner);
    } finally {
      lock.writeLock().unlock();
    }
  }

  /** Lists the prefixes owned by {@code owner}, IPv4 first. */
  List<IpPrefix> prefixes(T owner) {
    List<IpPrefix> out = new ArrayList<>();
    lock.readLock().lock();
    try {
      collect(v4, owner, out);
      collect(v6, owner, out);
    } finally {
      lock.readLock().unlock();
    }
    return out;
  }

  private Node<T> root(int addressLength) {
    if (addressLength == 4) {
      return v4;
    }
    if (addressLength == 16) {
      return v6;
    }
    throw new IllegalArgumentException("address length must be 4 or 16");
  }

  private static int bit(byte[] addr, int off, int i) {
    return (addr[off + (i >>> 3)] >>> (7 - (i & 7))) & 1;
  }

  /** Clears {@code owner} below {@code node}; returns whether {@code node} became empty. */
  private static <T> boolean prune(Node<T> node, T owner) {
    if (node.zero != null && prune(node.zero, owner)) {
      node.zero = null;
    }
    if (node.one != null && prune(node.one, owner)) {
      node.one = null;
    }
    if (node.owner == owner) {
      node.owner = null;
      node.prefix = null;
    }
    return node.owner == null && node.zero == null && node.one == null;
  }

  private static <T> void collect(Node<T> node, T owner, List<IpPrefix> out) {
    if (node == null) {
      return;
    }
    if (node.owner == owner) {
      out.add(node.prefix);
    }
    collect(node.zero, owner, out);
    collect(node.one, owner, out);
  }
}
