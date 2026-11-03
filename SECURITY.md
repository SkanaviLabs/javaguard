# Security

javaguard is a WireGuard implementation with a pure-Java core and an optional native TUN module.
This document covers its threat model, the results of the security review done during development, and known limitations.

## Reporting

Report vulnerabilities privately to Stanislav Yurin, AI Security Engineering LLC dba Skanavi. Do not
open public issues for security problems.

## Threat model

| Attacker | Can reach | Must not be able to |
|---|---|---|
| **Network** (anyone who can send UDP to the listen port) | `Device` receive path, handshake processing, cookie logic | read or forge tunnel traffic; exhaust memory or CPU beyond bounded work per packet |
| **Authenticated peer** (holds a configured key) | everything above, plus the netstack (IP, ICMP, UDP, TCP, DNS replies) | send traffic from IPs outside its allowed IPs; exhaust memory beyond per-connection bounds; affect other peers' sessions |
| **Local host user** (other OS accounts) | the proxy port, if bound beyond loopback, and the UAPI socket path | read the private key (the UAPI socket is owner-only); use the proxy without credentials when it is exposed |
| **Authenticated peer, `--tun` mode** | the host's own network stack through the interface, for its allowed IPs | reach the host from addresses outside its allowed IPs; anything the host's firewall would block on another interface |

Out of scope: side channels below the JVM (cache timing, power), a compromised JVM or host, and
the application's own process memory.

## Review checklist

| Item | Status | Where |
|---|---|---|
| Constant-time comparison of MACs, tags, keys, proxy credentials | Done | `ConstantTime` (`MessageDigest.isEqual`); JCA verifies AEAD tags; `Socks5Session.Credentials` evaluates both fields |
| No secret-dependent branches in custom crypto | Done | BLAKE2s and HChaCha20 are add-rotate-xor with no secret-indexed tables; X25519 and Poly1305 are the JDK's |
| Keys never logged | Done | `PrivateKey` and `PresharedKey` `toString()` are redacted. Only explicit key accessors and `WgQuickConfig.format()` expose the private key; the UAPI `get` returns it by protocol design, over an owner-only socket |
| mac1 checked before any public-key operation | Done | `Device.processHandshake` |
| DoS: cookie replies under load, per-IP and per-peer rate limits | Done | `CookieChecker`, `RateLimiter`, `HANDSHAKE_INITIATION_RATE` |
| Replay: sliding window checked after authentication; counter limit | Done | `ReplayWindow`, `REJECT_AFTER_MESSAGES` |
| Inbound source address must be within the sending peer's allowed IPs | Done | `Peer.receiveTransport` |
| Endpoint roaming only after authenticated packets | Done | transport after replay check; handshakes after `consumeInitiation`/`consumeResponse` |
| Every length validated before use | Done | Network parsers return `null` on malformed input; fuzzed (below) |
| Bounded queues everywhere a remote party can fill them | Done | see table below |
| Secrets wiped where the JVM allows | Partial | Handshake ephemerals and chaining keys are zeroed. `SecretKeySpec` copies cannot be wiped, and the GC may leave copies |
| Proxy exposure | Done | Binds loopback by default. CLI warns when bound elsewhere without credentials. Tunnel DNS only unless `systemDnsFallback` |
| UAPI exposure | Done | Socket owner-only (`rw-------` on POSIX, an owner-only ACL on Windows); requests are capped in lines and line length |

### Bounded resources

| Resource | Bound |
|---|---|
| Handshake work queue | 1024, excess dropped, "under load" at 128 |
| Crypto pipelines | 4096 packets each way (backpressure) |
| Staged packets per peer | 128 (oldest dropped) |
| Index table entries | up to one handshake and three keypairs per configured peer (needs an authenticated handshake) |
| Netstack inbound/outbound queues | 4096 packets |
| UDP socket receive queue | 256 datagrams |
| TCP half-open per listener / accept backlog | 256 / configurable, default 128 |
| TCP per connection | 256 KiB send + 256 KiB receive buffers, out-of-order queue within the window and at most 512 segments |
| Proxy sessions | 1024 concurrent; HTTP request head 64 KiB |
| DNS / UAPI parsing | name compression loops capped; UAPI 100k lines of at most 64 KiB |

## Native code and host changes (`javaguard-tun`)

`javaguard-tun` is the only module that calls native code. It is opt-in; only the CLI depends on
it, and only for `--tun`.

- **Native boundary.** All downcalls are in `LibC`: `open`, `ioctl(TUNSETIFF)`, `read`,
  `write`, `poll`, `eventfd`, `close`, `strerror`. Buffers are FFM segments with bounds checks;
  the structs are `ifreq` (layout unit-tested) and a two-entry `pollfd` array. Constants are the
  x86_64/aarch64 values, and `LinuxTun` refuses other platforms. Grant access with
  `--enable-native-access=com.skanavi.javaguard.tun` on the module path, or `ALL-UNNAMED` on the
  class path; the CLI's start scripts use the module form.
- **Privileges.** Creating the interface and running `ip` need root or `CAP_NET_ADMIN`. The
  process keeps those privileges while it runs; javaguard does not drop them.
- **Host changes.** Addresses, routes and DNS are applied by running `ip`, `resolvectl` or
  `resolvconf` with an argument list, not through a shell. `Table` is restricted to
  `[A-Za-z0-9_.-]`. Routes that would carry everything or a peer's own endpoint are refused
  unless `Table = off`, which adds no routes. Hooks are the exception: they run through
  `/bin/sh -c` (next bullet).
- **Hooks.** `PreUp`/`PostUp`/`PreDown`/`PostDown` are shell commands run as the javaguard
  process (usually root). The CLI runs them only with `--allow-hooks`. Treat a configuration
  with hooks like a root shell script: only use trusted files, owned by root and not writable
  by others.
- **Exposure.** Unlike the netstack, a TUN interface exposes the host's own services to the
  peer's allowed IPs. Firewall the interface as you would any other.

## Fuzzing

Jazzer targets, run with `./gradlew fuzz` (60 s each by default). Each was run for 3 minutes
during Phase 8 with no findings:

- `Blake2sFuzzTest`: differential against Bouncy Castle
- `HandshakeFuzzTest`: initiation, response and cookie-reply consumers
- `DeviceFuzzTest`: datagrams into a device with a live session (transport messages carry the
  live receiver index)
- `NetstackFuzzTest`: arbitrary IP packets into the netstack
- `TcpFuzzTest`: checksum-valid TCP segments with arbitrary fields, plus raw bytes, against a
  listener

## Known limitations

- TCP buffers are allocated up front: about 512 KiB per connection, including half-open ones. An
  authenticated peer can make the netstack hold up to 256 half-open connections per listener
  (about 128 MiB).
- `java.net.http.HttpClient` refuses Basic proxy auth for HTTPS tunnels unless the JDK property
  `jdk.http.auth.tunneling.disabledSchemes` is relaxed.
- No OS-level isolation. javaguard runs in the application's JVM and shares its fate.
- `--tun` mode does not drop privileges after setup, and does not check the ownership or
  permissions of a configuration file before running its hooks.
