# Quick start

Three ways to run this, in order of how much RF you are willing to emit.

Read [regulatory.md](regulatory.md) before any path that enables `radio.enabled`.

Prebuilt binaries: [Install](install.md). QMX on Debian GNU/Linux: [qmx.md](qmx.md).

## 0. Build

```sh
cargo build --release
cp ax25ircd.example.toml ax25ircd.toml
```

Edit `server.name` and, if the radio will transmit, `radio.callsign` (your
callsign). Check the file:

```sh
./target/release/ax25ircd --check -c ax25ircd.toml
```

## 1. IRC only (no radio)

Leave `radio.enabled = false`. Start the server and connect any IRC client to
`127.0.0.1:6667`. Join `#local`.

```sh
./target/release/ax25ircd -c ax25ircd.toml
```

`#rf` exists but nothing is radiated.

On `#rf`, `CALLSIGN` grants `+v` (permission to speak on IRC). Radiating
requires a registered nick that a control operator has `RADIO GRANT`ed, or
`OPER`. See [usage.md](usage.md).

```
/quote CALLSIGN SM0XYZ
/join #rf
/quote RADIO                 # transmitter status (no OPER needed)
/quote REGISTER secret12     # bind this nick; then ask an oper to GRANT it
```

## 2. Whole stack without a licence (virtual channel)

`ax25irc-kisshub` is a fake shared frequency. Point the gateway TNC at it.

In `ax25ircd.toml`:

```toml
[radio]
enabled = true
callsign = "SK0MT-1"

[radio.tnc]
kind = "tcp"
host = "127.0.0.1"
port = 8001
```

```sh
./target/release/ax25irc-kisshub --bind 127.0.0.1:8001
./target/release/ax25ircd -c ax25ircd.toml
./target/release/ax25irc-station --call SM0ABC-7 --gateway SK0MT-1 --channel '#rf'
```

Connect an IRC client to `127.0.0.1:6667`, `/quote CALLSIGN SM0XYZ`, join
`#rf`. The station nick appears as `SM0ABC|7`. Your IRC chat stays on the
internet until a control operator `RADIO GRANT`s your registered nick (or
you `OPER`). The hub prints frames in `axlisten` format.

## 3. Real RF via Direwolf

ax25ircd never talks to a radio. It talks **KISS** to a TNC. Direwolf is the
usual TNC: it takes sound-card audio, modulates AX.25, and offers KISS on TCP
port 8001.

```
radio ── audio/PTT ──► Direwolf (KISSPORT 8001) ──► ax25ircd :6667
```

Minimal `direwolf.conf` for VHF FM 1200 baud (a 2 m FM rig, SignaLink, etc.):

```
ADEVICE  plughw:1,0
MYCALL   SK0MT-1
CHANNEL  0
MODEM    1200
KISSPORT 8001
TXDELAY  30
```

Then the same `[radio]` / `[radio.tnc]` block as in section 2. Start Direwolf
first, then ax25ircd.

Serial hardware TNCs: `cargo build --release --features serial` and
`radio.tnc.kind = "serial"`.

## 4. QRP Labs QMX (or QMX+)

Debian packages, groups, hamlib, 300 baud Direwolf, and first QSO:
**[QMX on Debian](qmx.md)**. Do not use Digi mode.

## IRC client (irssi)

On this machine:

```
/connect 127.0.0.1 6667
```

Over the internet, TLS (required to speak):

```
/connect -tls irc.example.net 6697
```

Then `/nick alice`, `/quote CALLSIGN YOURCALL`, `/quote REGISTER <password>`.
That binds the nick and the callsign so nobody else can use them. Next
session: `/quote IDENTIFY <password>`. Full walkthrough: [usage.md](usage.md).
