# Security

javaguard is a pure-Java WireGuard implementation. This document covers its threat model, the
results of the security review done during development (Phase 8, 2026-11-01), and known
limitations.

## Reporting

Report vulnerabilities privately to Stanislav Yurin, AI Security Engineering LLC dba Skanavi. Do not
open public issues for security problems.

## Threat model

| Attacker | Can reach | Must not be able to |
|---|---|---|
| **Network** (anyone who can send UDP to the listen port) | `Device` receive path, handshake processing, cookie logic | read or forge tunnel traffic; exhaust memory or CPU beyond bounded work per packet; learn whether a public key is configured |
| **Authenticated peer** (holds a configured key) | everything above, plus the netstack (IP, ICMP, UDP, TCP, DNS replies) | send traffic from IPs outside its allowed IPs; exhaust memory beyond per-connection bounds; affect other peers' sessions |
| **Local host user** (other OS accounts) | the proxy port, if bound beyond loopback, and the UAPI socket path | read the private key (UAPI socket is `rw-------`); use the proxy without credentials when it is exposed |

Out of scope: side channels below the JVM (cache timing, power), a compromised JVM, the host's
own process memory.

## Review checklist

| Item | Status | Where |
|---|---|---|
| Constant-time comparison of MACs, tags, keys, proxy credentials | Done | `ConstantTime` (`MessageDigest.isEqual`); JCA verifies AEAD tags; `Socks5Session.Credentials` evaluates both fields |
| No secret-dependent branches in custom crypto | Done | BLAKE2s and HChaCha20 are add-rotate-xor with no tables; X25519 and Poly1305 are the JDK's |
| Keys never logged | Done | `PrivateKey` and `PresharedKey` `toString()` are redacted. Only UAPI `get` returns the private key, by protocol design, over an owner-only socket |
| mac1 checked before any public-key operation | Done | `Device.processHandshake` |
| DoS: cookie replies under load, per-IP and per-peer rate limits | Done | `CookieChecker`, `RateLimiter`, `HANDSHAKE_INITIATION_RATE` |
| Replay: sliding window checked after authentication; counter limit | Done | `ReplayWindow`, `REJECT_AFTER_MESSAGES` |
| Inbound source address must be within the sending peer's allowed IPs | Done | `Peer.receiveTransport` |
| Endpoint roaming only after authenticated packets | Done | transport after replay check; handshakes after `consumeInitiation`/`consumeResponse` |
| Every length validated before use | Done | All parsers return `null` on malformed input; fuzzed (below) |
| Bounded queues everywhere a remote party can fill them | Done | see table below |
| Secrets wiped where the JVM allows | Partial | Handshake ephemerals and chaining keys are zeroed. `SecretKeySpec` copies cannot be wiped, and the GC may leave copies |
| Proxy exposure | Done | Binds loopback by default. CLI warns when bound elsewhere without credentials. Tunnel DNS only unless `systemDnsFallback` |
| UAPI exposure | Done | Socket `rw-------`; requests are capped in lines and line length |

### Bounded resources

| Resource | Bound |
|---|---|
| Handshake work queue | 1024, excess dropped, "under load" at 128 |
| Crypto pipelines | 4096 packets each way (backpressure) |
| Staged packets per peer | 128 (oldest dropped) |
| Index table entries | one handshake + three keypairs per configured peer (needs an authenticated handshake) |
| Netstack inbound/outbound queues | 4096 packets |
| UDP socket receive queue | 256 datagrams |
| TCP half-open per listener / accept backlog | 256 / configurable (128) |
| TCP per connection | 256 KiB send + 256 KiB receive buffers, out-of-order queue within the window and at most 512 segments |
| Proxy sessions | 1024 concurrent; HTTP request head 64 KiB |
| DNS / UAPI parsing | name compression loops capped; UAPI 100k lines of at most 64 KiB |

## Fuzzing

Jazzer targets, run with `./gradlew fuzz` (60 s each by default). Each was run for 3 minutes
during Phase 8 with no findings:

- `Blake2sFuzzTest`: differential against Bouncy Castle
- `HandshakeFuzzTest`: initiation, response and cookie-reply consumers
- `DeviceFuzzTest`: datagrams into a device with a live session (transport messages carry the
  live receiver index)
- `NetstackFuzzTest`: arbitrary IP packets into the netstack
- `TcpFuzzTest`: checksum-valid TCP segments with arbitrary fields against a listener

## Known limitations

- TCP buffers are allocated up front: about 512 KiB per connection, including half-open ones. An
  authenticated peer can make the netstack hold up to 256 half-open connections per listener
  (about 128 MiB).
- `java.net.http.HttpClient` refuses Basic proxy auth for HTTPS tunnels unless the JDK property
  `jdk.http.auth.tunneling.disabledSchemes` is relaxed.
- No OS-level isolation. javaguard runs in the application's JVM and shares its fate.
