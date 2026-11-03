// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.tun;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;
import static java.lang.foreign.ValueLayout.JAVA_SHORT;

import com.skanavi.javaguard.core.Tun;
import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.Locale;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * A Linux kernel TUN interface ({@code /dev/net/tun}, {@code IFF_TUN | IFF_NO_PI}) as a javaguard
 * {@link Tun}: packets the host routes to the interface come out of {@link #read}, and packets
 * passed to {@link #write} are delivered to the host's network stack.
 *
 * <p>Opening needs {@code CAP_NET_ADMIN}. The interface exists while this object is open and is
 * removed by the kernel, together with its addresses and routes, when it is closed or the process
 * exits. Configure it (addresses, MTU, routes) with {@link HostNetwork} or the {@code ip} tool.
 *
 * <p>Uses {@code java.lang.foreign}; run with {@code
 * --enable-native-access=com.skanavi.javaguard.tun} (or {@code ALL-UNNAMED} on the class path) to
 * avoid the JDK's warning. Supported on Linux x86_64 and aarch64. {@link #read} is meant for one
 * thread; {@link #write} may be called from several. {@link #close()} wakes a blocked reader.
 */
public final class LinuxTun implements Tun {
  private static final int BUFFER = 65536;

  private final int fd;
  private final int wakeFd;
  private final String name;
  private final int mtu;
  private final ReadWriteLock lifecycle = new ReentrantReadWriteLock();
  private final ThreadLocal<Scratch> scratch = ThreadLocal.withInitial(Scratch::new);
  private volatile boolean closed;

  /** Per-thread native memory: a packet buffer, errno capture and two pollfds. */
  private static final class Scratch {
    final MemorySegment buf;
    final MemorySegment errno;
    final MemorySegment pollfds;

    Scratch() {
      Arena arena = Arena.ofAuto();
      buf = arena.allocate(BUFFER, 16);
      errno = LibC.errnoSegment(arena);
      pollfds = arena.allocate(2 * LibC.POLLFD_SIZE, 8);
    }
  }

  private LinuxTun(int fd, int wakeFd, String name, int mtu) {
    this.fd = fd;
    this.wakeFd = wakeFd;
    this.name = name;
    this.mtu = mtu;
  }

  /** Whether this platform supports {@link LinuxTun} (Linux on x86_64 or aarch64). */
  public static boolean isSupported() {
    String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
    String arch = System.getProperty("os.arch", "").toLowerCase(Locale.ROOT);
    return os.equals("linux")
        && (arch.equals("amd64") || arch.equals("x86_64") || arch.equals("aarch64"));
  }

  /**
   * Creates a TUN interface.
   *
   * @param name the interface name (up to 15 characters, may contain {@code %d}), or {@code null}
   *     or empty to let the kernel choose one; see {@link #name()} for the result
   * @param mtu the MTU this tun reports to the device; set the interface MTU to match
   * @throws UnsupportedOperationException if not {@link #isSupported() supported}
   * @throws IOException if the device cannot be created, for example without {@code CAP_NET_ADMIN}
   *     or if the name is taken by a non-TUN interface
   */
  public static LinuxTun open(String name, int mtu) throws IOException {
    if (!isSupported()) {
      throw new UnsupportedOperationException(
          "TUN interfaces are supported on Linux x86_64 and aarch64 only, not "
              + System.getProperty("os.name")
              + " "
              + System.getProperty("os.arch"));
    }
    if (mtu < 576 || mtu > 65535) {
      throw new IllegalArgumentException("MTU out of range: " + mtu);
    }
    String requested = name == null ? "" : name;
    IfReq.encodeName(requested);
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment errno = LibC.errnoSegment(arena);
      int fd =
          LibC.open(
              errno,
              arena.allocateFrom("/dev/net/tun"),
              LibC.O_RDWR | LibC.O_NONBLOCK | LibC.O_CLOEXEC);
      if (fd < 0) {
        throw LibC.error("open /dev/net/tun", LibC.errno(errno));
      }
      MemorySegment ifr = IfReq.allocate(arena, requested, (short) (LibC.IFF_TUN | LibC.IFF_NO_PI));
      if (LibC.ioctl(errno, fd, LibC.TUNSETIFF, ifr) < 0) {
        int e = LibC.errno(errno);
        LibC.close(errno, fd);
        throw LibC.error("TUNSETIFF " + (requested.isEmpty() ? "(any name)" : requested), e);
      }
      int wake = LibC.eventfd(errno, 0, LibC.EFD_NONBLOCK | LibC.EFD_CLOEXEC);
      if (wake < 0) {
        int e = LibC.errno(errno);
        LibC.close(errno, fd);
        throw LibC.error("eventfd", e);
      }
      return new LinuxTun(fd, wake, IfReq.name(ifr), mtu);
    }
  }

  /** The interface name the kernel assigned. */
  public String name() {
    return name;
  }

  @Override
  public int mtu() {
    return mtu;
  }

  @Override
  public int read(byte[] buf, int off, int len) throws IOException {
    Scratch s = scratch.get();
    lifecycle.readLock().lock();
    try {
      while (!closed) {
        long n = LibC.read(s.errno, fd, s.buf, BUFFER);
        if (n >= 0) {
          int copy = (int) Math.min(n, len);
          MemorySegment.copy(s.buf, JAVA_BYTE, 0, buf, off, copy);
          return copy;
        }
        int e = LibC.errno(s.errno);
        if (e == LibC.EAGAIN) {
          awaitReadable(s);
        } else if (e != LibC.EINTR) {
          if (closed) {
            break;
          }
          throw LibC.error("read " + name, e);
        }
      }
      return -1;
    } finally {
      lifecycle.readLock().unlock();
    }
  }

  /** Waits until the tun has a packet or {@link #close()} signals the eventfd. */
  private void awaitReadable(Scratch s) throws IOException {
    MemorySegment p = s.pollfds;
    p.set(JAVA_INT, 0, fd);
    p.set(JAVA_SHORT, 4, LibC.POLLIN);
    p.set(JAVA_SHORT, 6, (short) 0);
    p.set(JAVA_INT, 8, wakeFd);
    p.set(JAVA_SHORT, 12, LibC.POLLIN);
    p.set(JAVA_SHORT, 14, (short) 0);
    if (LibC.poll(s.errno, p, 2, -1) < 0) {
      int e = LibC.errno(s.errno);
      if (e != LibC.EINTR) {
        throw LibC.error("poll " + name, e);
      }
    }
  }

  @Override
  public void write(byte[] buf, int off, int len) throws IOException {
    if (len > BUFFER) {
      return;
    }
    Scratch s = scratch.get();
    lifecycle.readLock().lock();
    try {
      if (closed) {
        return;
      }
      MemorySegment.copy(buf, off, s.buf, JAVA_BYTE, 0, len);
      while (LibC.write(s.errno, fd, s.buf, len) < 0) {
        int e = LibC.errno(s.errno);
        if (e == LibC.EAGAIN || e == LibC.ENOBUFS) {
          return; // the host is not keeping up: drop, as a NIC would
        }
        if (e != LibC.EINTR) {
          throw LibC.error("write " + name, e);
        }
      }
    } finally {
      lifecycle.readLock().unlock();
    }
  }

  /** Removes the interface. Wakes a blocked {@link #read}, which then returns {@code -1}. */
  @Override
  public void close() throws IOException {
    synchronized (this) {
      if (closed) {
        return;
      }
      closed = true;
    }
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment errno = LibC.errnoSegment(arena);
      MemorySegment one = arena.allocate(JAVA_LONG);
      one.set(JAVA_LONG, 0, 1L);
      LibC.write(errno, wakeFd, one, 8);
      // Wait for readers and writers to leave before the descriptors can be reused.
      lifecycle.writeLock().lock();
      try {
        LibC.close(errno, fd);
        LibC.close(errno, wakeFd);
      } finally {
        lifecycle.writeLock().unlock();
      }
    }
  }

  @Override
  public String toString() {
    return "LinuxTun[" + name + ", mtu " + mtu + "]";
  }
}
