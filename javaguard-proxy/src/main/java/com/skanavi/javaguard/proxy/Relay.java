// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.proxy;

import com.skanavi.javaguard.netstack.TcpSocket;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

/** Copies bytes both ways between a host socket and a tunnel socket, propagating half-closes. */
final class Relay {
  private static final int BUFFER = 64 * 1024;

  private Relay() {}

  /** Relays until both directions finish; closes both sockets. Blocks the calling thread. */
  static void run(Socket client, TcpSocket remote) {
    // A platform thread, so only the session's virtual thread ever parks on the client socket. On
    // Windows, a virtual thread waiting to write missed its wakeup while another waited to read
    // from the same socket, which stalled the relay for good under load.
    Thread upstream =
        Thread.ofPlatform()
            .daemon()
            .name("javaguard-proxy-up")
            .start(
                () -> {
                  try {
                    copy(client.getInputStream(), remote.outputStream());
                    remote.shutdownOutput();
                  } catch (IOException e) {
                    remote.abort();
                    closeQuietly(client);
                  }
                });
    try {
      copy(remote.inputStream(), client.getOutputStream());
      client.shutdownOutput();
      upstream.join();
    } catch (IOException e) {
      remote.abort();
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      remote.abort();
    } finally {
      closeQuietly(client);
      remote.close();
    }
  }

  private static void copy(InputStream in, OutputStream out) throws IOException {
    byte[] buf = new byte[BUFFER];
    int n;
    while ((n = in.read(buf)) >= 0) {
      out.write(buf, 0, n);
      out.flush();
    }
  }

  static void closeQuietly(Socket s) {
    try {
      s.close();
    } catch (IOException e) {
      // already broken
    }
  }
}
