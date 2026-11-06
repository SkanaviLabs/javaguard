// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.netstack;

/** A fixed-capacity FIFO byte buffer with random-access reads from the head. Not thread-safe. */
final class ByteRing {
  private byte[] buf;
  private int head;
  private int size;

  ByteRing(int capacity) {
    this.buf = new byte[capacity];
  }

  int capacity() {
    return buf.length;
  }

  /** Gives up the storage of an empty ring that will hold no more data. */
  void release() {
    if (size != 0) {
      throw new IllegalStateException("ring is not empty");
    }
    buf = new byte[1]; // not empty: the index arithmetic divides by the length
    head = 0;
  }

  int size() {
    return size;
  }

  int free() {
    return buf.length - size;
  }

  /** Appends up to {@code len} bytes; returns how many fit. */
  int write(byte[] src, int off, int len) {
    int n = Math.min(len, free());
    int tail = (head + size) % buf.length;
    int first = Math.min(n, buf.length - tail);
    System.arraycopy(src, off, buf, tail, first);
    System.arraycopy(src, off + first, buf, 0, n - first);
    size += n;
    return n;
  }

  /** Copies {@code len} bytes starting {@code from} bytes after the head, without consuming. */
  void peek(int from, byte[] dst, int off, int len) {
    if (from < 0 || len < 0 || from + len > size) {
      throw new IndexOutOfBoundsException();
    }
    int start = (head + from) % buf.length;
    int first = Math.min(len, buf.length - start);
    System.arraycopy(buf, start, dst, off, first);
    System.arraycopy(buf, 0, dst, off + first, len - first);
  }

  /** Discards {@code n} bytes from the head. */
  void skip(int n) {
    if (n < 0 || n > size) {
      throw new IndexOutOfBoundsException();
    }
    head = (head + n) % buf.length;
    size -= n;
  }

  /** Reads and consumes up to {@code len} bytes. */
  int read(byte[] dst, int off, int len) {
    int n = Math.min(len, size);
    peek(0, dst, off, n);
    skip(n);
    return n;
  }
}
