// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.core.noise;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;

/** Little-endian field access for wire messages. */
final class Bytes {
  private static final VarHandle LE_INT =
      MethodHandles.byteArrayViewVarHandle(int[].class, ByteOrder.LITTLE_ENDIAN);
  private static final VarHandle LE_LONG =
      MethodHandles.byteArrayViewVarHandle(long[].class, ByteOrder.LITTLE_ENDIAN);

  private Bytes() {}

  static int getInt(byte[] b, int off) {
    return (int) LE_INT.get(b, off);
  }

  static void putInt(byte[] b, int off, int value) {
    LE_INT.set(b, off, value);
  }

  static long getLong(byte[] b, int off) {
    return (long) LE_LONG.get(b, off);
  }

  static void putLong(byte[] b, int off, long value) {
    LE_LONG.set(b, off, value);
  }

  static byte[] slice(byte[] b, int off, int len) {
    byte[] out = new byte[len];
    System.arraycopy(b, off, out, 0, len);
    return out;
  }
}
