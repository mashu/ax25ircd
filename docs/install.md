# Install

Tagged releases publish GNU/Linux binaries (static musl): AppImage, `.run`
installer, and a tarball. x86_64 gets all three; aarch64 gets `.run` and
`.tar.gz`.

## .run installer

Default prefix is `~/.local`. Existing config is never overwritten.

```sh
curl -fsSL -o ax25ircd.run \
  https://github.com/mashu/ax25ircd/releases/latest/download/ax25ircd-x86_64.run
chmod +x ax25ircd.run
./ax25ircd.run
ax25ircd --check -c ~/.config/ax25ircd/ax25ircd.toml
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
cp ax25ircd.example.toml ax25ircd.toml
# at minimum: server.name; radio.callsign if you will transmit
./target/release/ax25ircd --check -c ax25ircd.toml
./target/release/ax25ircd -c ax25ircd.toml
```

Connect on `127.0.0.1:6667` and join `#local`. Leave `radio.enabled = false`
until you have read [Regulatory](regulatory.md).

A push of a `v*` tag is what builds and uploads these artifacts. See
[Packaging](packaging.md).
