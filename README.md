# ax25ircd

[![CI](https://github.com/mashu/ax25ircd/actions/workflows/ci.yml/badge.svg)](https://github.com/mashu/ax25ircd/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/mashu/ax25ircd/graph/badge.svg)](https://codecov.io/gh/mashu/ax25ircd)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![docs (stable)](https://img.shields.io/badge/docs-stable-8dff70)](https://mashu.github.io/ax25ircd/stable/)
[![docs (dev)](https://img.shields.io/badge/docs-dev-c4a35a)](https://mashu.github.io/ax25ircd/dev/)

An IRC server that is also an AX.25 packet-radio gateway.

```
   irssi ──TCP/TLS──►  ax25ircd  ──KISS──►  SM0ABC-7
                                        └── SM0XYZ-9
```
