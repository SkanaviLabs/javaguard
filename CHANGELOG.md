# Changelog

## 1.0.0 (unreleased)

First release.

### Protocol and device

- WireGuard protocol: the Noise_IKpsk2 handshake, cookies (mac1/mac2), all timers from section 6
  of the whitepaper, rekeying, roaming, replay protection and cryptokey routing.
- Interoperates with the Linux kernel module and `wireguard-go`, as initiator and as responder.

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
- The cross-platform UAPI, served on a Unix socket, so the `wg` tool can show, set, `showconf` and
  `setconf` a running device.
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
- OS interfaces on macOS and Windows; full-tunnel routing and `FwMark` in `--tun` mode.
