# ax25ircd

[![CI](https://github.com/mashu/ax25ircd/actions/workflows/ci.yml/badge.svg)](https://github.com/mashu/ax25ircd/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/mashu/ax25ircd/graph/badge.svg)](https://codecov.io/gh/mashu/ax25ircd)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![docs (stable)](https://img.shields.io/badge/docs-stable-8dff70)](https://mashu.github.io/ax25ircd/stable/)
[![docs (dev)](https://img.shields.io/badge/docs-dev-c4a35a)](https://mashu.github.io/ax25ircd/dev/)

An IRC server that is also an AX.25 packet-radio gateway.

```
   irssi ──TCP──┐                        ┌── SM0ABC-7
   WeeChat ─────┼──►  ax25ircd  ──KISS──►│
    HexChat ─────┘                        └── SM0XYZ-9
```

## Install

```sh
curl -fsSL -o ax25ircd.run \
  https://github.com/mashu/ax25ircd/releases/latest/download/ax25ircd-x86_64.run
chmod +x ax25ircd.run && ./ax25ircd.run
```

**Docs:** [stable](https://mashu.github.io/ax25ircd/stable/) ·
[dev](https://mashu.github.io/ax25ircd/dev/)
— [quick start](https://mashu.github.io/ax25ircd/dev/quickstart/) ·
[QMX on Debian](https://mashu.github.io/ax25ircd/dev/qmx/)

A `v*` tag builds the binaries and freezes that tree as **stable**.
`main` is **dev**.
