// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.config;

import com.skanavi.javaguard.core.Device;
import java.io.BufferedReader;
import java.io.Closeable;
import java.io.IOException;
import java.io.Writer;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.Channels;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.EnumSet;
import java.util.List;

/**
 * Serves {@link Uapi} for a device on a Unix domain socket, by convention {@code
 * /var/run/wireguard/<interface>.sock}, where {@code wg(8)} looks for userspace interfaces.
 *
 * <p>The protocol reveals and changes the private key, so the socket is created owner-only ({@code
 * rw-------}) on POSIX file systems.
 */
public final class UapiServer implements Closeable {
  private static final System.Logger LOG = System.getLogger(UapiServer.class.getName());

  private final Uapi uapi;
  private final Path path;
  private final ServerSocketChannel server;
  private final Thread acceptor;
  private volatile boolean closed;

  private UapiServer(Uapi uapi, Path path, ServerSocketChannel server) {
    this.uapi = uapi;
    this.path = path;
    this.server = server;
    this.acceptor = new Thread(this::acceptLoop, "javaguard-uapi");
    this.acceptor.setDaemon(true);
  }

  /**
   * The conventional socket path for interface {@code name}: {@code /var/run/wireguard/name.sock}.
   */
  public static Path defaultPath(String name) {
    return Path.of("/var/run/wireguard", name + ".sock");
  }

  /**
   * Binds {@code path} and starts serving {@code uapi}. Creates the parent directory if needed and
   * replaces a stale socket file, but refuses if another process is serving the path.
   */
  public static UapiServer start(Uapi uapi, Path path) throws IOException {
    Path parent = path.toAbsolutePath().getParent();
    boolean posix = FileSystems.getDefault().supportedFileAttributeViews().contains("posix");
    if (parent != null && !Files.isDirectory(parent)) {
      if (posix) {
        Files.createDirectories(
            parent,
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwxr-xr-x")));
      } else {
        Files.createDirectories(parent);
      }
    }
    UnixDomainSocketAddress address = UnixDomainSocketAddress.of(path);
    if (Files.exists(path)) {
      if (isServing(address)) {
        throw new IOException("another process is serving " + path);
      }
      Files.delete(path); // stale socket left by a dead process
    }
    ServerSocketChannel server = ServerSocketChannel.open(StandardProtocolFamily.UNIX);
    try {
      server.bind(address);
      if (posix) {
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
      } else {
        restrictToOwner(path);
      }
    } catch (IOException | RuntimeException e) {
      server.close();
      Files.deleteIfExists(path);
      throw e;
    }
    UapiServer s = new UapiServer(uapi, path, server);
    s.acceptor.start();
    return s;
  }

  /** Starts serving {@code device} at {@code path}; see {@link #start(Uapi, Path)}. */
  public static UapiServer start(Device device, Uapi.BindFactory bindFactory, Path path)
      throws IOException {
    return start(new Uapi(device, bindFactory), path);
  }

  /**
   * Replaces the ACL of {@code path} with one entry granting its owner full access (Windows, where
   * there are no POSIX permissions). The socket serves the private key, so it must not inherit a
   * more permissive ACL from its directory.
   */
  static void restrictToOwner(Path path) throws IOException {
    AclFileAttributeView view = Files.getFileAttributeView(path, AclFileAttributeView.class);
    if (view == null) {
      throw new IOException("cannot restrict access to " + path + ": no POSIX or ACL support");
    }
    AclEntry owner =
        AclEntry.newBuilder()
            .setType(AclEntryType.ALLOW)
            .setPrincipal(view.getOwner())
            .setPermissions(EnumSet.allOf(AclEntryPermission.class))
            .build();
    view.setAcl(List.of(owner));
  }

  private static boolean isServing(UnixDomainSocketAddress address) {
    try {
      SocketChannel.open(address).close();
      return true;
    } catch (IOException e) {
      return false;
    }
  }

  /** The socket path. */
  public Path path() {
    return path;
  }

  /** Whether the socket file still exists. By convention, deleting it asks the daemon to exit. */
  public boolean socketExists() {
    return Files.exists(path);
  }

  private void acceptLoop() {
    while (!closed) {
      try {
        SocketChannel client = server.accept();
        Thread.ofVirtual().name("javaguard-uapi-client").start(() -> serve(client));
      } catch (ClosedChannelException e) {
        return;
      } catch (IOException e) {
        if (!closed) {
          LOG.log(System.Logger.Level.WARNING, "UAPI accept failed", e);
        }
      }
    }
  }

  private void serve(SocketChannel client) {
    try (client;
        BufferedReader in = new BufferedReader(Channels.newReader(client, StandardCharsets.UTF_8));
        Writer out = Channels.newWriter(client, StandardCharsets.UTF_8)) {
      uapi.serve(in, out);
    } catch (IOException e) {
      LOG.log(System.Logger.Level.DEBUG, "UAPI client error", e);
    }
  }

  /** Stops serving and deletes the socket file. */
  @Override
  public void close() throws IOException {
    closed = true;
    server.close();
    Files.deleteIfExists(path);
  }
}
