# Install

Tagged releases publish GNU/Linux binaries (static musl): AppImage, `.run`
installer, and a tarball. x86_64 gets all three; aarch64 gets `.run` and
`.tar.gz`.

## Setup

However you install it, `--init` asks the handful of things that cannot be
guessed and writes a configuration that is known to come up — it parses and
validates the result before anything reaches the disk:

```sh
ax25ircd --init -c ~/.config/ax25ircd/ax25ircd.toml
```

Six questions: server name, whether you have a radio (and if so your callsign,
how the TNC is reached, the on-air baud rate and the bridged channel), whether
to generate a TLS certificate, and whether to create a control-operator
account. Enter takes the value in brackets. The `.run` and tarball installers
offer to run it for you when there is no configuration yet and you are at a
terminal; a piped or unattended install copies the annotated example instead,
as it always did.

Two things it will not do on your behalf:

* **Guess the baud rate.** It is a closed choice defaulting to 300, because a
  rate set higher than the modem's makes the duty-cycle governor under-count
  key-down time — see [Airtime](airtime.md). Too low costs throughput; too
  high costs a power amplifier.
* **Enable the transmitter.** Answering the last radio question with Enter
  configures the whole radio side and leaves `radio.enabled = false`. Turn it
  on when you have read [Regulatory](regulatory.md); everything else is
  already in place.

It refuses to replace an existing configuration. Move the old one aside if you
want to start over.

### TLS certificates

`--init` can generate a self-signed certificate and key beside the config
(`tls-cert.pem`, `tls-key.pem`, the key mode 0600) and prints its SHA-256
fingerprint. Self-signed means IRC clients will ask you to confirm it — that
is what the fingerprint is for. Compare and accept it once.

If the host has a real name, a certificate from Let's Encrypt is better: point
`listen.tls.cert` and `listen.tls.key` at it and restart. Either way TLS
protects only the hop from the IRC client to the gateway. Everything that
reaches the antenna is in the clear, by law and by design.

## .run installer

Default prefix is `~/.local`. Existing config is never overwritten.

```sh
curl -fsSL -o ax25ircd.run \
  https://github.com/mashu/ax25ircd/releases/latest/download/ax25ircd-x86_64.run
chmod +x ax25ircd.run
./ax25ircd.run
```

It offers the setup questions above when it finds no configuration and you are
at a terminal. To run them later, or after declining:

```sh
ax25ircd --init -c ~/.config/ax25ircd/ax25ircd.toml
```

`sudo ./ax25ircd.run --system` installs to `/usr/local`. `--extract DIR` unpacks
without installing. ARM: `ax25ircd-aarch64.run`.

## AppImage

```sh
curl -fsSL -o ax25ircd.AppImage \
  https://github.com/mashu/ax25ircd/releases/latest/download/ax25ircd-x86_64.AppImage
chmod +x ax25ircd.AppImage
./ax25ircd.AppImage -c ~/.config/ax25ircd/ax25ircd.toml
./ax25ircd.AppImage station --call SM0ABC-7 --gateway SK0MT-1 --channel '#rf'
./ax25ircd.AppImage kisshub --bind 127.0.0.1:8001
```

## Tarball

```sh
curl -fsSL -O https://github.com/mashu/ax25ircd/releases/latest/download/ax25ircd-x86_64-linux.tar.gz
tar xf ax25ircd-x86_64-linux.tar.gz
./ax25ircd-*/install.sh
```

## From source

Needs Rust 1.75+. Serial hardware TNCs: add `--features serial`. The QMX path
uses Direwolf over TCP KISS, so the default build is enough.

```sh
cargo build --release
./target/release/ax25ircd --init -c ax25ircd.toml
./target/release/ax25ircd -c ax25ircd.toml
```

Or by hand — the minimum is `server.name`, plus `radio.callsign` and a channel
with `rf = true` if you will transmit:

```sh
cp ax25ircd.example.toml ax25ircd.toml
./target/release/ax25ircd --check -c ax25ircd.toml
```

Connect on `127.0.0.1:6667` and join `#local`. Leave `radio.enabled = false`
until you have read [Regulatory](regulatory.md).

A push of a `v*` tag is what builds and uploads these artifacts. See
[Packaging](packaging.md).
