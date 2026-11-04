# javaguard

A WireGuard® implementation in pure Java at its core: the protocol, crypto and network stack use
no JNI and no native code, and need no root. It runs inside your JVM. A userspace TCP/IP stack
gives the application its own addresses inside the tunnel, and a local SOCKS5/HTTP proxy lets
unmodified clients such as `curl`, browsers and `java.net.http.HttpClient` use the tunnel.

On Linux (x86_64 and aarch64), the optional `javaguard-tun` module can instead create a real
network interface, so other programs on the host can use the tunnel. The WireGuard protocol, crypto
and packet processing remain the Java implementation; OS interop is limited to creating and
configuring the TUN interface and reading and writing its packets. It is the one module that calls
native code (through `java.lang.foreign`) and needs root or `CAP_NET_ADMIN`; only the CLI depends
on it, and only for `--tun`.

javaguard is protocol-compatible with peers running the Linux kernel WireGuard module or
`wireguard-go`. This is tested in both roles on every change; see [Testing](#testing).

- **Requirements:** Java 25 or later.
- **License:** MIT.
- **Security:** see [SECURITY.md](SECURITY.md).

## Contents

- [Motivation](#motivation)
- [Modules](#modules)
- [Quick start: embedded](#quick-start-embedded)
- [Quick start: CLI](#quick-start-cli)
  - [A real interface (Linux)](#a-real-interface-linux)
- [Design notes](#design-notes)
- [Building](#building)
- [Testing](#testing)
- [How it compares](#how-it-compares)
- [License](#license)

## Motivation

WireGuard is usually deployed at the operating-system or container level, with a kernel module or
`wireguard-go`, a TUN interface, root, and routes that cover every process on the host or require specific rules.  
javaguard brings it to a JVM applications which need a private
network from an environment they cannot reconfigure or where this approach can significantly simplify overall deployment: a shared CI runner, a managed container
platform, a serverless function, desktop tool shipped as a jar or an agent written in Java, Clojure or any other JVM language.

javaguard puts the tunnel inside the process instead. The userspace stack gives the application
its own addresses without touching host interfaces, routes, or DNS. In this mode the host needs no
new privileges and there is no native library to load or crash: the same artifact runs wherever the
JVM runs. Peers, keys and `wg-quick` files are unchanged, so the other end cannot tell the
difference.

`javaguard-tun` is still included for deployments that need a real interface which is generally useful for testing, audit trail compatibility and various experiments, and it pursues
maximum Java nativity: libc is bound with `java.lang.foreign` downcalls only, with no JNI glue, no
C sources and no bundled per-platform binaries, and the host side runs `ip`, `resolvectl` and
`resolvconf` through `ProcessBuilder`. Everything outside those kernel calls is ordinary Java.

The trade-off is deliberate: traffic only uses the tunnel when it is sent through `Netstack`,
`LocalProxy`, or the `HttpClient`/`SocketFactory` helpers. For multi-tenant services and test
suites, that scoping is the point; a process-wide tunnel would be a bug.

## Modules

| Artifact (`com.skanavi.javaguard:…`) | What it is |
|---|---|
| `javaguard-crypto` | BLAKE2s, HMAC/HKDF, XChaCha20-Poly1305, TAI64N, keys; X25519 and ChaCha20-Poly1305 come from the JDK |
| `javaguard-core` | `Device`, `Peer`, the Noise IKpsk2 handshake, cookies, timers, cryptokey routing, `UdpBind`, `PacketPipe` |
| `javaguard-netstack` | `Netstack`: userspace IPv4/IPv6, ICMP, UDP sockets, TCP, DNS resolver |
| `javaguard-proxy` | `LocalProxy`: SOCKS5 and HTTP proxy into the tunnel, plus `ProxySelector`/`SocketFactory`/`HttpClient` helpers |
| `javaguard-config` | wg-quick file parser/formatter; UAPI server so the stock `wg` tool can manage a device |
| `javaguard-tun` | Optional, Linux: `LinuxTun`, a kernel TUN interface as the device's tun, and `HostNetwork` for addresses, routes, DNS and hooks. Uses FFM |
| `javaguard-cli` | `javaguard genkey`, `pubkey`, `genpsk`, `up <file.conf> [--proxy port]` |

Most applications depend on `javaguard-proxy` and `javaguard-config`; together they pull in
`javaguard-netstack`, `javaguard-core` and `javaguard-crypto`.

```kotlin
dependencies {
    implementation("com.skanavi.javaguard:javaguard-proxy:1.0.0")
    implementation("com.skanavi.javaguard:javaguard-config:1.0.0")
}
```

## Quick start: embedded

The configuration uses wg-quick syntax. `Address` gives the stack its tunnel address, and `DNS`
names the resolver it queries through the tunnel:

```ini
[Interface]
PrivateKey = <base64>
Address = 10.0.0.2/24
DNS = 10.0.0.1

[Peer]
PublicKey = <base64>
Endpoint = vpn.example.com:51820
AllowedIPs = 10.0.0.0/24
PersistentKeepalive = 25
```

```java
WgQuickConfig config = WgQuickConfig.parse(Path.of("client.conf"));

Netstack stack = Netstack.builder()
    .addresses(config.iface().addresses())
    .dnsServers(config.iface().dns())
    .build();
Device device = Device.builder()
    .privateKey(config.iface().privateKey())
    .bind(UdpBind.open(0))
    .tun(stack)
    .build();
config.addPeersTo(device);
device.start();

// Option 1: talk TCP through the tunnel directly.
InetAddress db = stack.dns().resolve("db.internal").get(0);
try (TcpSocket s = stack.connectTcp(new InetSocketAddress(db, 5432), Duration.ofSeconds(10))) {
    s.outputStream().write(...);
}

// Option 2: give existing code a proxy.
LocalProxy proxy = LocalProxy.builder(stack).build();          // 127.0.0.1, random port
HttpClient http = proxy.httpClientBuilder().build();           // java.net.http
Socket socket = proxy.socketFactory().createSocket("db.internal", 5432);
```

Without a network stack, pass a `PacketPipe` as the tun and exchange raw IP packets with
`send`/`receive`.

Runnable versions of these are in [`javaguard-examples`](javaguard-examples/src/main/java/com/skanavi/javaguard/examples):

```bash
./gradlew :javaguard-examples:run -Pexample=EmbeddedHttpClient --args="client.conf http://intranet.example/"
```

## Quick start: CLI

```bash
./gradlew :javaguard-cli:installDist
```

```bash
javaguard-cli/build/install/javaguard/bin/javaguard up client.conf --proxy 1080
```

```bash
curl --socks5-hostname 127.0.0.1:1080 http://intranet.example/
```

```bash
sudo wg show client
```

`up` serves the UAPI socket at `/var/run/wireguard/<name>.sock`, so `wg show`, `wg set` and
`wg setconf` work against it. Creating that directory usually needs root; pass `--socket <path>` or
`--no-uapi` to avoid it. The process exits on SIGTERM or when the socket file is deleted.

Keys that would change the operating system (`PostUp`, `Table`, `FwMark`, …) are rejected,
because in this mode javaguard never touches the host's network configuration. `--lenient`
skips them with a warning instead.

### A real interface (Linux)

```bash
sudo javaguard-cli/build/install/javaguard/bin/javaguard up wg0.conf --tun
```

`--tun` creates interface `wg0` and configures it like wg-quick: `Address`, `MTU`, `DNS`
(through `resolvectl` or `resolvconf`), and a route for every `AllowedIPs` prefix, in the main
table or the one `Table` names (`Table = off` adds none). The interface and its routes disappear
when javaguard exits. `PreUp`, `PostUp`, `PreDown` and `PostDown` run only with
`--allow-hooks`. Not supported yet: routing all traffic (`0.0.0.0/0`, `::/0`), `FwMark` and
`SaveConfig`. Embedded use:

```java
// Module path: --enable-native-access=com.skanavi.javaguard.tun
// Class path:  --enable-native-access=ALL-UNNAMED
LinuxTun tun = LinuxTun.open("wg0", 1420);
Device device = Device.builder().privateKey(key).bind(UdpBind.open(0)).tun(tun).build();
```

## Design notes

- **Threads:** each device has a UDP receive thread, a tun thread, a handshake worker, a timer
  thread and a small crypto pool. The crypto pool keeps packets in order.
- **Performance:** two devices over loopback on Apple Silicon reach about 1.7 Gbit/s for raw
  packets (`./gradlew :javaguard-core:throughput`) and about 1.4 Gbit/s for one TCP stream
  (`./gradlew :javaguard-netstack:throughput`).
- **TCP:** RFC 9293 with NewReno and SACK recovery, delayed ACKs, window scaling and keepalives.
  There is no CUBIC yet, so throughput on lossy long-RTT links follows Reno.
- **Not implemented:** IP fragmentation (fragments are dropped), TCP DNS fallback for truncated
  answers, and OS interfaces on macOS and Windows.

## Building

```bash
./gradlew build
```

`build` runs the unit tests (about 200, including deterministic protocol simulations on
virtual time). Gradle downloads a JDK 25 toolchain if needed.

## Testing

| Command | What it runs |
|---|---|
| `./gradlew test` | Unit, property and simulation tests |
| `./gradlew interopTest` | Docker. Kernel WireGuard and `wireguard-go` in both roles; ping, UDP, DNS, TCP (with 1% loss), the `wg` tool against `javaguard up`, and `HttpClient`/`curl` through the proxy. Add `-PlongInterop=true` for a 260 s run across rekeys |
| `./gradlew fuzz` | Jazzer, 60 s per target |
| `./gradlew :javaguard-netstack:soakTest -PsoakMinutes=N` | Long stability run with leak checks |
| `./gradlew :javaguard-proxy:remoteTest -PremoteEndpoint=… -PremotePublicKey=… -PremoteKeyFile=…` | Against a real peer over the Internet; see `scripts/remote-peer/` |
| `./gradlew :javaguard-crypto:jmh` | Microbenchmarks |
| `./gradlew :javaguard-core:throughput` | End-to-end throughput |

## How it compares

These three projects also run WireGuard in userspace, but none of them implements the whole stack in
a JVM. Each uses a TUN interface and needs either root or Android's `VpnService`.

Snapshot: chop0/wireguard-java at `495da11` (October 2023), WireGuard/wireguard-android at
`1.0.20260315`, and wgtunnel/android at 5.8.2 (October 2026).

| | **javaguard** | **[chop0/wireguard-java](https://github.com/chop0/wireguard-java)** | **[WireGuard/wireguard-android](https://github.com/WireGuard/wireguard-android)** | **[wgtunnel/android](https://github.com/wgtunnel/android)** |
|---|---|---|---|---|
| Type | JVM library and CLI | JVM library and CLI | Official Android app plus `tunnel` library | Android app for WireGuard and AmneziaWG plus shared `core` library |
| Protocol engine | Java | Java | Go (`wireguard-go`) or the kernel module | Go (`amneziawg-go`) via JNI |
| Runtime | Java 25+, any OS with a JVM | Java 21 with preview features, Linux and macOS | Android 8.0+ | Android 8.0+; the core also targets desktop |
| Privileges | None; `CAP_NET_ADMIN` only for `--tun` | Root (TUN and interface setup) | None; root optional for the kernel backend | None; root or Shizuku optional |
| Tunnel model | In-process; optional Linux TUN | Host-wide TUN | Android `VpnService` | Android `VpnService` or local proxy |
| TCP/IP stack | Userspace, in Java | Host kernel | Android OS stack | Android OS stack; gVisor in proxy mode |
| Proxy | SOCKS5 and HTTP | — | — | SOCKS5 and HTTP |
| Config | wg-quick, UAPI, stock `wg` | A subset of wg-quick | wg-quick in the app | wg-quick, AmneziaWG, UAPI |
| Native code | None in the core; FFM for Linux TUN | JNI for TUN, ChaCha20 and Poly1305 | `libwg-go.so` via the NDK | Go and C JNI via the NDK |
| Distribution | Maven Central modules | Source and native-image build | Play Store and Maven Central | Play, F-Droid and Maven Central |
| License | MIT | No license file | Apache-2.0 | MIT |
| Status | 1.0.0, November 2026 | No releases; last commit October 2023 | Actively maintained | 5.8.2, October 2026 |

**chop0/wireguard-java.** It implements WireGuard in Java, but relies on a TUN device and the OS
TCP/IP stack. Root is required, and there is no userspace netstack, proxy, UAPI, keygen or published
build. The project has
not been updated since October 2023 and has no license file; cookies are a TODO, sessions expire
after a fixed 120 s, and the transport path has no replay window. Its ~5 Gbit/s claim uses JNI crypto
and the host stack, so it does not compare directly with javaguard's ~1.7 Gbit/s raw and ~1.4 Gbit/s
TCP, which include Java crypto and the userspace stack. Use it for a small root-run client on
Linux or macOS, not as an unprivileged JVM library.

**WireGuard/wireguard-android.** The official Android app. WireGuard runs in `wireguard-go` or the
kernel module; the Java/Kotlin code is UI, config and JNI. Use it for a system-wide Android VPN. Its
`tunnel` library is Android-only and cannot run on a plain JVM, server or CI runner.

**wgtunnel/android.** A third-party Android client for WireGuard and AmneziaWG, built on
[wgtunnel/core](https://github.com/wgtunnel/core). The packet engine is Go via JNI (AmneziaWG, a
`wireguard-go` fork), with gVisor for proxy mode. It has more Android features than javaguard:
auto-tunneling, multihop, kill switch, split tunneling, split DNS, a local SOCKS5/HTTP proxy and
Android TV. It is not pure Java or in-process; its JVM/desktop core still ships native libraries.

**Choose javaguard** for an in-process, unprivileged JVM tunnel. **Choose chop0/wireguard-java** for
a small Java TUN client on a Linux or macOS host where root is available. **Choose
WireGuard/wireguard-android** for the official Android app. **Choose wgtunnel/android** for an Android
client with AmneziaWG and extra features.

## License

MIT. See [LICENSE](LICENSE). Copyright © 2026 Stanislav Yurin, AI Security Engineering LLC dba
Skanavi. Third-party notices, including the MIT notice for code derived from
[wireguard-go](https://git.zx2c4.com/wireguard-go/), are in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

"WireGuard" and the "WireGuard" logo are registered trademarks of Jason A. Donenfeld. javaguard is
an independent implementation and is not affiliated with, endorsed by, or sponsored by the
WireGuard project or its developers. See <https://www.wireguard.com/>.
