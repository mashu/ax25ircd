# QMX on Debian

The QMX is the radio, not a TNC. One USB-C cable gives Debian a sound card and
a CAT serial port. Direwolf turns that into AX.25 KISS. ax25ircd is the IRC
server that speaks KISS. **Do not put the QMX in Digi mode.**

![QMX USB into Direwolf, KISS into ax25ircd, TCP to IRC](assets/chain.png)

!!! warning "Before you enable the radio"
    Automatic control and third-party traffic are the two rules that bite
    gateways. Read [Regulatory](regulatory.md) and your own licence. This page
    is an operator's checklist, not legal advice.

## 1. Debian packages

Bookworm, Trixie, or later.

```sh
sudo apt-get update
sudo apt-get install -y direwolf libhamlib-utils alsa-utils irssi curl
```

`libhamlib-utils` provides `rigctl` (PTT). `irssi` is one client; WeeChat
(`weechat`) is fine too.

## 2. Plug the QMX in, join the right groups

```sh
sudo usermod -aG audio,dialout "$USER"
# log out and back in (or reboot) so the groups take effect
arecord -l
ls -l /dev/serial/by-id/
```

You want a card named **QMX** (remember `plughw:N,0`) and a stable serial path
such as `/dev/serial/by-id/usb-QRP_Labs_QMX_Transceiver-if00`. Do not put
`/dev/ttyACM0` in a config you intend to keep — the number moves.

## 3. Set the radio: SSB USB, IQ off, TX from USB

AIRC is AFSK from Direwolf, sent as ordinary SSB audio. Digi mode is
single-tone FSK (FT8-style) and will not work.

| Control | Setting |
|---|---|
| Mode | SSB, upper sideband |
| IQ | Off — Direwolf needs demodulated audio, not I/Q |
| SSB TX source | USB from the PC (CAT `SS0;`) |
| Frequency | An HF packet allocation used *where you are* |

## 4. Direwolf at 300 baud, not 1200

HF packet is 300 baud. VHF FM is 1200; that is a different radio. Copy
[direwolf-qmx.conf](assets/direwolf-qmx.conf), then edit `ADEVICE`, `MYCALL`
(your callsign), and the `PTT` serial path from step 2.

```
ADEVICE  plughw:1,0
ARATE    48000
MYCALL   YOURCALL-1
CHANNEL  0
MODEM    300
PTT      RIG 2057 /dev/serial/by-id/usb-QRP_Labs_QMX_Transceiver-if00
KISSPORT 8001
TXDELAY  40
TXTAIL   30
```

Hamlib model **2057** is QMX. Older hamlib: Kenwood TS-480, model **2028**, same
serial device.

```sh
direwolf -c direwolf-qmx.conf
```

Leave this terminal running. It should listen on KISS TCP port 8001.

## 5. Install ax25ircd

See [Install](install.md). Short version:

```sh
curl -fsSL -o ax25ircd.run \
  https://github.com/mashu/ax25ircd/releases/latest/download/ax25ircd-x86_64.run
chmod +x ax25ircd.run
./ax25ircd.run
```

AppImage subcommands: `./ax25ircd.AppImage station …` and
`./ax25ircd.AppImage kisshub …`. ARM: aarch64 tarball or `.run` from
[Releases](https://github.com/mashu/ax25ircd/releases/latest).

## 6. Edit the gateway config

The installer writes `~/.config/ax25ircd/ax25ircd.toml` if that file did not
exist. Set `server.name`, **your** callsign, and turn the radio on only when
Direwolf is already listening.

```toml
[radio]
enabled = true
callsign = "YOURCALL-1"
paclen = 128
notice_air_relay = true

[radio.tnc]
kind = "tcp"
host = "127.0.0.1"
port = 8001
tx_pacing_ms = 2500
```

```sh
ax25ircd --check -c ~/.config/ax25ircd/ax25ircd.toml
```

The checker refuses a fake callsign, an ID interval over ten minutes, and
`radio.enabled` with no bridged channel. Keep `#rf` as `rf = true`.

## 7. Start the gateway, then the IRC client

```sh
ax25ircd -c ~/.config/ax25ircd/ax25ircd.toml
# another terminal:
irssi
#  /connect 127.0.0.1 6667
#  /quote CALLSIGN YOURCALL
#  /join #rf
#  /quote RADIO
```

`RADIO` should show the transmitter **ON**. `#rf` is `+rm`: without a callsign
you can listen, you cannot speak. Change the example OPER password before you
bind to a public address.

## 8. First message that actually keys the radio

Send a short line in `#rf`. If `notice_air_relay` is on, the server notices
`Relayed to RF (YOURCALL-1)…`. Watch Direwolf for PTT and a 300-baud frame.

| Goal | Command |
|---|---|
| Speak on `#rf` | `/quote CALLSIGN YOURCALL` then `/join #rf` |
| Transmitter status | `/quote RADIO` |
| Keep a nick | `/quote REGISTER <password>` then `IDENTIFY` |
| Control operator | `/oper …` then `RADIO OFF` / `RADIO HEARD` |

## 9. Optional: a second QMX as the operator radio

Same Direwolf setup on that machine, then the station client:

```sh
ax25irc-station --call YOURCALL-7 --gateway GATEWAY-1 \
    --channel '#rf' --tnc tcp://127.0.0.1:8001
```

AppImage: `./ax25ircd.AppImage station --call …`. The nick on IRC is the
callsign with `-` turned into `|` (`YOURCALL|7`).

## 10. If nothing comes back

- Direwolf not running, or not on `127.0.0.1:8001` — ax25ircd reconnects, but nothing radiates.
- Wrong `plughw` index after unplugging — check `arecord -l` again.
- Not in `dialout` — PTT silently fails. `groups` should list it.
- QMX still in Digi or IQ — audio looks like noise to Direwolf.
- Hamlib 2057 unknown — switch PTT to `RIG 2028`.
- No `+v` on `#rf` — you skipped `CALLSIGN`.
- Practice with no RF: `ax25irc-kisshub --bind 127.0.0.1:8001` and the same
  toml, indoors. Still do not enable radio toward a real antenna until you
  mean it.

ax25ircd never talks to the QMX. It talks KISS to Direwolf. That split is
deliberate: audio, PTT and the modem stay in software that already knows
hamlib. See [Protocol](protocol.md) and [Design](design.md).
