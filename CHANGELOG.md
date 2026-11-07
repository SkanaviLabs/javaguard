# Changelog

## Unreleased

### In progress

- A route-capable server: forwarding for peers to the host network or between peers, IPv4/IPv6
  route advertisement, ACL/NAT and DNS design. This is not part of 1.0.0, 1.1.0 or 1.1.1; the
  `TunnelHost` remains a service-level endpoint with no forwarding beyond the host.

## 1.1.1 (2026-11-07)

### Fixed

- Two TCP ends that filled each other's windows could deadlock until both timed out. An end
  accepted a pure ACK only inside its receive window, and only at exactly `rcvNxt` when the
  window was closed. Pure ACKs carried `sndMax`, which lies beyond the window whenever data was
  sent into room that then filled. Neither end's ACK got through, so neither writer woke to read
  and reopen its window. An end now takes the ACK and window of any segment at or beyond `rcvNxt`
  (RFC 9293 3.10.7.4), dropping only its data. Pure ACKs carry `sndUna` while the peer's window is
  closed, so a strict peer such as Linux accepts them too. Found by stress testing full-duplex
  echo over the internet and over loopback.
- A connection whose peer had closed its window and kept answering probes was aborted with
  `connection timed out` after its retransmission limit. Retransmissions now count against the
  limit only once the peer stops acknowledging.

## 1.1.0 (2026-11-07)

### Added

- `javaguard-server`: `TunnelHost`, a WireGuard server inside a JVM. Peers reach only the ports it
  opens, through `serveTcp` handlers that learn the peer's public key, or `expose`, which relays a
  tunnel port to a local TCP port or Unix socket, optionally with a PROXY protocol v2 header. There
  is no forwarding beyond this host, and each peer must have addresses of its own.
- `Device.peerFor` finds the peer an address belongs to, and `Device.onRoutesChanged` reports
  changes to peers and allowed IPs, including those made through UAPI.
- `Netstack.Builder.tcpMaxInbound` and `tcpMaxInboundPerRemote` limit inbound TCP connections, and
  `Netstack.refusedTcpConnections` counts those refused. Both limits are off by default.
- `LocalProxy.Builder.upstreamSocks5` sends TCP from both the SOCKS5 and HTTP sides through a SOCKS5
  proxy reached inside the tunnel, with optional username/password authentication. Target host
  names go to the upstream unresolved, UDP ASSOCIATE is refused, and a failed upstream fails the
  connection rather than dialing the target directly.

### Changed

- A TCP connection entering TIME_WAIT frees its buffers if they are empty.

### Fixed

- A `Netstack` listener accepts a new connection that reuses the address pair of one in TIME_WAIT.
  The SYN used to get a bare ACK, so the connect stalled until it timed out.

## 1.0.0 (2026-11-03)

First release.

### Protocol and device

- WireGuard protocol: the Noise_IKpsk2 handshake, cookies (mac1/mac2), all timers from section 6
  of the whitepaper, rekeying, roaming, replay protection and cryptokey routing.
- Interoperates with peers running the Linux kernel WireGuard module or `wireguard-go`, as
  initiator and as responder.

### Embedding API

- `Device`, `Peer`, `PeerConfig`, `UdpBind`, `PacketPipe`.
- Pluggable `Tun`, `Bind` and `Scheduler` interfaces.

### Netstack

- Userspace IPv4/IPv6, ICMP echo, UDP sockets and a DNS resolver.
- TCP:
  - RFC 9293 state machine, RFC 6298 retransmission timers.
  - NewReno and SACK loss recovery, delayed ACKs, window scaling.
  - Zero-window probes, keepalives, RFC 5961 protections.

### Proxy

- `LocalProxy`: SOCKS5 (CONNECT and UDP ASSOCIATE, optional username/password) and HTTP (CONNECT
  and plain forwarding), with tunnel-only DNS.
- Helpers for `java.net.http.HttpClient`, `ProxySelector` and `SocketFactory`.

### Configuration and CLI

- wg-quick configuration files: parsing and formatting.
- The UAPI protocol, served on a Unix socket, so `wg show`, `wg set`, `wg showconf` and
  `wg setconf` work against a running device.
- `javaguard` CLI: `genkey`, `genpsk`, `pubkey`, `up` (with `--proxy`).

### OS interface (Linux, optional)

- `javaguard-tun`: `LinuxTun`, a kernel TUN interface as the device's tun, and `HostNetwork`,
  which sets addresses, MTU, routes, DNS and hooks the way wg-quick does. The only module that
  uses native code (FFM).
- `WgQuickConfig.parseForHost` keeps `Table`, `FwMark`, hooks and `SaveConfig` in
  `HostSettings`.
- CLI: `javaguard up <file> --tun [--allow-hooks]`.

### Performance (loopback, Apple Silicon)

| Path | Throughput |
|---|---|
| Raw packets | about 1.7 Gbit/s |
| One TCP stream | about 1.4 Gbit/s |

Crypto runs in an order-preserving parallel pipeline.

### Not yet supported

- IP fragmentation.
- TCP DNS fallback for truncated answers.
- CUBIC congestion control.
- An async socket API.
- Named-pipe UAPI on Windows.
- OS interfaces on macOS and Windows.
- Full-tunnel routing and `FwMark` in `--tun` mode.
