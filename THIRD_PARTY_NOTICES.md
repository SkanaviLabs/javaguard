# Third-party notices

javaguard is distributed under the MIT License; see [LICENSE](LICENSE).

This file records the third-party software whose code or structure is reflected in javaguard, as
required by those projects' licenses.

## wireguard-go

Parts of the protocol implementation in `javaguard-core` and the UAPI handling in
`javaguard-config` follow the structure of [wireguard-go](https://git.zx2c4.com/wireguard-go/),
the userspace WireGuard implementation.

```
Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
SPDX-License-Identifier: MIT
```

The MIT License applies to that upstream code:

```
Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Scope of the MIT license in this repository

The WireGuard protocol itself is specified by the [WireGuard
whitepaper](https://www.wireguard.com/papers/wireguard.pdf) and the RFCs it cites. Protocol
constants, message layouts and test vectors are functional requirements of that specification, not
third-party source code.

The GPL-2.0 implementations — the Linux kernel WireGuard module and `wireguard-tools` — are used
only as interoperability peers in the test suite (in Docker containers and in
`scripts/remote-peer/`). They are not vendored, linked, or distributed with javaguard. BoringTun
is mentioned only in a test comment for a published protocol constant.

The `-javadoc.jar` artifacts also contain a `legal/` directory that the JDK's `javadoc` tool copies
from the JDK. Those files are the JDK's notices, not part of javaguard's source.

## Trademarks

"WireGuard" and the "WireGuard" logo are registered trademarks of Jason A. Donenfeld. javaguard is
an independent implementation and is not affiliated with, endorsed by, or sponsored by the
WireGuard project or its developers. See <https://www.wireguard.com/>.
