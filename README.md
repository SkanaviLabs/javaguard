# javaguard

A WireGuard® implementation in pure Java: no JNI, no native code, no root. It runs inside your
JVM. A userspace TCP/IP stack gives the application its own addresses inside the tunnel, and a
local SOCKS5/HTTP proxy lets unmodified clients such as `curl`, browsers and
`java.net.http.HttpClient` use the tunnel.

javaguard interoperates with the Linux kernel module and `wireguard-go`. That is tested in both
roles on every change; see [Testing](#testing).

- **Requirements:** Java 25 or later.
- **License:** MIT.
- **Security:** see [SECURITY.md](SECURITY.md).

## Modules

| Artifact (`com.skanavi.javaguard:…`) | What it is |
|---|---|
| `javaguard-crypto` | BLAKE2s, HMAC/HKDF, XChaCha20-Poly1305, TAI64N, keys; X25519 and ChaCha20-Poly1305 come from the JDK |
| `javaguard-core` | `Device`, `Peer`, the Noise IKpsk2 handshake, cookies, timers, cryptokey routing, `UdpBind`, `PacketPipe` |
| `javaguard-netstack` | `Netstack`: userspace IPv4/IPv6, ICMP, UDP sockets, TCP, DNS resolver |
| `javaguard-proxy` | `LocalProxy`: SOCKS5 and HTTP proxy into the tunnel, plus `ProxySelector`/`SocketFactory`/`HttpClient` helpers |
| `javaguard-config` | wg-quick file parser/formatter; UAPI server so the stock `wg` tool can manage a device |
| `javaguard-cli` | `javaguard genkey | pubkey | genpsk | up <file.conf> [--proxy port]` |

Most applications depend on `javaguard-proxy` and `javaguard-config`, which bring in the rest.

```kotlin
dependencies {
    implementation("com.skanavi.javaguard:javaguard-proxy:1.0.0")
    implementation("com.skanavi.javaguard:javaguard-config:1.0.0")
}
```

## Quick start: embedded

The configuration is an ordinary wg-quick file. `Address` gives the netstack its tunnel
address and `DNS` names the resolver it uses inside the tunnel:

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

// Option 1: talk TCP/UDP through the tunnel directly.
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

`up` serves the cross-platform UAPI socket at `/var/run/wireguard/<name>.sock`, so `wg show`,
`wg set` and `wg setconf` work against it. Creating that directory usually needs root; pass
`--socket <path>` or `--no-uapi` to avoid it. The process exits on SIGTERM or when the socket
is deleted.

Keys that would change the operating system (`PostUp`, `Table`, `FwMark`, …) are rejected,
because javaguard never touches the host's network configuration. `--lenient` skips them
with a warning instead.

## Design notes

- **Threads:** each device has a UDP receive thread, a tun thread, a handshake worker, a timer
  thread and a small crypto pool. The crypto pool keeps packets in order.
- **Performance:** two devices over loopback on Apple Silicon reach about 1.7 Gbit/s for raw
  packets and about 1.4 Gbit/s for one TCP stream (`./gradlew :javaguard-netstack:throughput`).
- **TCP:** RFC 9293 with NewReno and SACK recovery, delayed ACKs, window scaling and keepalives.
  There is no CUBIC yet, so throughput on lossy long-RTT links follows Reno.
- **Not implemented:** IP fragmentation (fragments are dropped) and TCP DNS fallback for
  truncated answers.

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
| `./gradlew jmh` | Microbenchmarks |
| `./gradlew :javaguard-core:throughput` | End-to-end throughput |

## License

MIT. See [LICENSE](LICENSE). Copyright © 2026 Stanislav Yurin, AI Security Engineering LLC dba
Skanavi.

"WireGuard" is a registered trademark of Jason A. Donenfeld. javaguard is an independent
implementation and is not affiliated with or endorsed by the WireGuard project.
