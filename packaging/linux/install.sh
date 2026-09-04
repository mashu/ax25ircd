#!/bin/sh
# Install ax25ircd binaries and data files. Invoked by the .run installer
# and usable from an extracted tarball:
#   tar xf ax25ircd-x86_64-linux.tar.gz
#   ./ax25ircd-*/install.sh
#
#   ./install.sh                 # $HOME/.local
#   ./install.sh --prefix DIR
#   sudo ./install.sh --system   # /usr/local

set -eu

PREFIX=""
SYSTEM=0

usage() {
    cat <<'EOF'
Usage: install.sh [--prefix DIR] [--system]

  --prefix DIR   install root (binaries go to DIR/bin)
  --system       prefix /usr/local (implies running as root)

Default prefix is $HOME/.local. Existing configuration is never overwritten.
EOF
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix)
            PREFIX=${2:-}
            shift 2
            ;;
        --system)
            SYSTEM=1
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            usage
            ;;
    esac
done

HERE=$(CDPATH= cd -- "$(dirname "$0")" && pwd)

if [ -z "$PREFIX" ]; then
    if [ "$SYSTEM" -eq 1 ]; then
        PREFIX=/usr/local
    else
        PREFIX=${HOME}/.local
    fi
fi

if [ "$SYSTEM" -eq 1 ] && [ "$(id -u)" -ne 0 ]; then
    echo "install.sh: --system needs root (try sudo)" >&2
    exit 1
fi

BINDIR="$PREFIX/bin"
DATADIR="$PREFIX/share/ax25ircd"
DOCDIR="$PREFIX/share/doc/ax25ircd"
UNITDIR=""
if [ "$SYSTEM" -eq 1 ]; then
    UNITDIR=/etc/systemd/system
    CONFDIR=/etc/ax25ircd
else
    UNITDIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
    CONFDIR="${XDG_CONFIG_HOME:-$HOME/.config}/ax25ircd"
fi

mkdir -p "$BINDIR" "$DATADIR" "$DOCDIR" "$CONFDIR"

for b in ax25ircd ax25irc-station ax25irc-kisshub; do
    install -m 0755 "$HERE/bin/$b" "$BINDIR/$b"
done

install -m 0644 "$HERE/share/ax25ircd.example.toml" "$DATADIR/ax25ircd.example.toml"
install -m 0644 "$HERE/share/ax25ircd.service" "$DATADIR/ax25ircd.service"
if [ -d "$HERE/share/doc" ]; then
    cp -R "$HERE/share/doc/." "$DOCDIR/"
fi

CONFFILE="$CONFDIR/ax25ircd.toml"
if [ ! -f "$CONFFILE" ]; then
    install -m 0644 "$HERE/share/ax25ircd.example.toml" "$CONFFILE"
    echo "wrote starter config: $CONFFILE"
    echo "edit radio.callsign (your callsign) before enabling radio.enabled"
else
    echo "kept existing config: $CONFFILE"
fi

if [ "$SYSTEM" -eq 1 ]; then
    install -m 0644 "$HERE/share/ax25ircd.service" "$UNITDIR/ax25ircd.service"
    echo "systemd unit: $UNITDIR/ax25ircd.service"
    echo "create a system user, put the config at /etc/ax25ircd.toml (or edit"
    echo "ExecStart), then: systemctl daemon-reload && systemctl enable --now ax25ircd"
else
    mkdir -p "$UNITDIR"
    # User unit: run from the user's config path, not /etc.
    sed -e "s|/usr/local/bin/ax25ircd|$BINDIR/ax25ircd|g" \
        -e "s|/etc/ax25ircd.toml|$CONFFILE|g" \
        -e '/^User=/d' \
        -e '/^Group=/d' \
        -e 's/^ProtectHome=.*/ProtectHome=no/' \
        "$HERE/share/ax25ircd.service" > "$UNITDIR/ax25ircd.service"
    echo "user systemd unit: $UNITDIR/ax25ircd.service"
    echo "  systemctl --user daemon-reload"
    echo "  systemctl --user enable --now ax25ircd"
fi

case ":$PATH:" in
    *":$BINDIR:"*) ;;
    *)
        echo
        echo "note: $BINDIR is not on PATH. Add it, or run $BINDIR/ax25ircd"
        ;;
esac

echo
echo "installed:"
echo "  $BINDIR/ax25ircd"
echo "  $BINDIR/ax25irc-station"
echo "  $BINDIR/ax25irc-kisshub"
echo
echo "next:  ax25ircd --check -c $CONFFILE"
echo "guide: https://mashu.github.io/ax25ircd/"
