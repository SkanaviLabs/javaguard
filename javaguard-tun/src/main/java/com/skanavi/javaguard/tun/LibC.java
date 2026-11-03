// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.tun;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.StructLayout;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;

/**
 * The handful of Linux libc calls a TUN device needs, as {@code java.lang.foreign} downcalls that
 * capture {@code errno}. Constants are the x86_64 and aarch64 values (they agree on both). Loading
 * this class performs the restricted linker lookups, so only touch it after checking {@link
 * LinuxTun#isSupported()}.
 */
@SuppressWarnings("restricted") // the module's native boundary; see module-info
final class LibC {
  static final int O_RDWR = 0x2;
  static final int O_NONBLOCK = 0x800;
  static final int O_CLOEXEC = 0x80000;
  static final int EFD_NONBLOCK = O_NONBLOCK;
  static final int EFD_CLOEXEC = O_CLOEXEC;
  static final long TUNSETIFF = 0x400454caL; // _IOW('T', 202, int)
  static final short IFF_TUN = 0x0001;
  static final short IFF_NO_PI = 0x1000;
  static final short POLLIN = 0x1;
  static final int EINTR = 4;
  static final int EAGAIN = 11;
  static final int ENOBUFS = 105;

  /** {@code struct pollfd}: int fd at 0, short events at 4, short revents at 6. */
  static final long POLLFD_SIZE = 8;

  private static final Linker LINKER = Linker.nativeLinker();
  private static final StructLayout CAPTURE = Linker.Option.captureStateLayout();
  private static final VarHandle ERRNO =
      CAPTURE.varHandle(MemoryLayout.PathElement.groupElement("errno"));

  private static final MethodHandle OPEN =
      downcall("open", FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_INT), 2);
  private static final MethodHandle IOCTL =
      downcall("ioctl", FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_LONG, ADDRESS), 2);
  private static final MethodHandle READ =
      downcall("read", FunctionDescriptor.of(JAVA_LONG, JAVA_INT, ADDRESS, JAVA_LONG), -1);
  private static final MethodHandle WRITE =
      downcall("write", FunctionDescriptor.of(JAVA_LONG, JAVA_INT, ADDRESS, JAVA_LONG), -1);
  private static final MethodHandle CLOSE =
      downcall("close", FunctionDescriptor.of(JAVA_INT, JAVA_INT), -1);
  private static final MethodHandle POLL =
      downcall("poll", FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_LONG, JAVA_INT), -1);
  private static final MethodHandle EVENTFD =
      downcall("eventfd", FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_INT), -1);
  private static final MethodHandle STRERROR =
      LINKER.downcallHandle(
          LINKER.defaultLookup().findOrThrow("strerror"), FunctionDescriptor.of(ADDRESS, JAVA_INT));

  private LibC() {}

  private static MethodHandle downcall(String name, FunctionDescriptor fd, int firstVariadic) {
    MemorySegment symbol = LINKER.defaultLookup().findOrThrow(name);
    Linker.Option capture = Linker.Option.captureCallState("errno");
    return firstVariadic < 0
        ? LINKER.downcallHandle(symbol, fd, capture)
        : LINKER.downcallHandle(symbol, fd, capture, Linker.Option.firstVariadicArg(firstVariadic));
  }

  /** Allocates a segment to receive {@code errno} from calls made by one thread. */
  static MemorySegment errnoSegment(Arena arena) {
    return arena.allocate(CAPTURE);
  }

  /** The {@code errno} captured by the last call that used {@code state}. */
  static int errno(MemorySegment state) {
    return (int) ERRNO.get(state, 0L);
  }

  static int open(MemorySegment state, MemorySegment path, int flags) {
    try {
      return (int) OPEN.invokeExact(state, path, flags);
    } catch (Throwable t) {
      throw rethrow(t);
    }
  }

  static int ioctl(MemorySegment state, int fd, long request, MemorySegment arg) {
    try {
      return (int) IOCTL.invokeExact(state, fd, request, arg);
    } catch (Throwable t) {
      throw rethrow(t);
    }
  }

  static long read(MemorySegment state, int fd, MemorySegment buf, long len) {
    try {
      return (long) READ.invokeExact(state, fd, buf, len);
    } catch (Throwable t) {
      throw rethrow(t);
    }
  }

  static long write(MemorySegment state, int fd, MemorySegment buf, long len) {
    try {
      return (long) WRITE.invokeExact(state, fd, buf, len);
    } catch (Throwable t) {
      throw rethrow(t);
    }
  }

  static int close(MemorySegment state, int fd) {
    try {
      return (int) CLOSE.invokeExact(state, fd);
    } catch (Throwable t) {
      throw rethrow(t);
    }
  }

  static int poll(MemorySegment state, MemorySegment fds, long nfds, int timeoutMillis) {
    try {
      return (int) POLL.invokeExact(state, fds, nfds, timeoutMillis);
    } catch (Throwable t) {
      throw rethrow(t);
    }
  }

  static int eventfd(MemorySegment state, int initval, int flags) {
    try {
      return (int) EVENTFD.invokeExact(state, initval, flags);
    } catch (Throwable t) {
      throw rethrow(t);
    }
  }

  /** An {@link IOException} describing {@code errno} for {@code what}. */
  static IOException error(String what, int errno) {
    String message;
    try {
      MemorySegment s = (MemorySegment) STRERROR.invokeExact(errno);
      message = s.reinterpret(256).getString(0);
    } catch (Throwable t) {
      message = "errno " + errno;
    }
    return new IOException(what + ": " + message + " (errno " + errno + ")");
  }

  private static RuntimeException rethrow(Throwable t) {
    if (t instanceof RuntimeException r) {
      throw r;
    }
    if (t instanceof Error e) {
      throw e;
    }
    throw new IllegalStateException(t);
  }
}
