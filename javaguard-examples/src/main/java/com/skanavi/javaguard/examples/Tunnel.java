// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi

package com.skanavi.javaguard.examples;

import com.skanavi.javaguard.config.ConfigException;
import com.skanavi.javaguard.config.WgQuickConfig;
import com.skanavi.javaguard.core.Device;
import com.skanavi.javaguard.core.UdpBind;
import com.skanavi.javaguard.netstack.Netstack;
import java.io.IOException;
import java.nio.file.Path;

/**
 * A running tunnel built from a configuration file: a {@link Device} terminated by a {@link
 * Netstack}. This is the setup every example shares.
 *
 * @param device the WireGuard device
 * @param stack the userspace network stack inside the tunnel
 */
public record Tunnel(Device device, Netstack stack) implements AutoCloseable {
  /** Parses {@code config}, builds the device and netstack, adds the peers and starts it. */
  public static Tunnel start(Path config) throws IOException, ConfigException {
    WgQuickConfig c = WgQuickConfig.parse(config);
    if (c.iface().addresses().isEmpty()) {
      throw new ConfigException(0, "[Interface] needs an Address for the network stack");
    }
    Netstack stack =
        Netstack.builder()
            .addresses(c.iface().addresses())
            .dnsServers(c.iface().dns())
            .searchDomains(c.iface().dnsSearch())
            .mtu(c.iface().mtu() != null ? c.iface().mtu() : 1420)
            .build();
    int port = c.iface().listenPort() != null ? c.iface().listenPort() : 0;
    Device device =
        Device.builder()
            .privateKey(c.iface().privateKey())
            .bind(UdpBind.open(port))
            .tun(stack)
            .build();
    c.addPeersTo(device);
    device.start();
    return new Tunnel(device, stack);
  }

  @Override
  public void close() throws IOException {
    device.close();
  }
}
