# ax25ircd

An IRC server that is also an AX.25 packet radio gateway. People with an
ordinary IRC client and people with a radio and a TNC talk in the same
channels.

```
   irssi ──TCP──┐                        ┌── SM0ABC-7  (HT + Mobilinkd)
   WeeChat ─────┼──►  ax25ircd  ──KISS──►│
   HexChat ─────┘                        └── SM0XYZ-9  (TNC-Pi + 2 m rig)
```

Written in Rust, no unsafe code, no locks in the message path.

Three binaries:

| Binary | Runs on | Job |
|---|---|---|
| `ax25ircd` | the gateway machine | the IRC server and RF gateway |
| `ax25irc-station` | an operator's laptop or Pi | client for people on the radio side |
| `ax25irc-kisshub` | anywhere | a virtual radio channel, for development without a licence |

## Status

Working and tested: 40 unit tests plus 9 end-to-end tests that drive a real
server through a real KISS codec with a fake TNC and a fake IRC client, and a
full manual run of gateway + station + virtual channel. Verified on rustc 1.75
and later.

## Quick start

```sh
cargo build --release
cp ax25ircd.example.toml ax25ircd.toml
$EDITOR ax25ircd.toml            # at minimum: server.name
./target/release/ax25ircd --check -c ax25ircd.toml
./target/release/ax25ircd -c ax25ircd.toml
```

With `radio.enabled = false` this is a plain IRC server. Connect on
`127.0.0.1:6667` and join `#local`.

To exercise the whole radio path without transmitting, set
`radio.enabled = true` and `radio.tnc.kind = "loopback"`.

For real RF, run Direwolf with `KISSPORT 8001` and point `[radio.tnc]` at it:

```toml
[radio]
enabled = true
callsign = "SK0MT-1"          # your callsign; it identifies the station
id_interval_secs = 540        # must be <= 600

[radio.tnc]
kind = "tcp"
host = "127.0.0.1"
port = 8001
```

**Read `docs/REGULATORY.md` before you enable the radio.** Doing so makes your
station transmit automatically, under your licence, carrying other people's
traffic.

Serial TNCs need a feature flag:

```sh
cargo build --release --features serial
```

## Trying the whole thing without a radio

`ax25irc-kisshub` is a virtual channel: every TCP client that connects is a
station on the same frequency, and it prints every frame in `axlisten` monitor
format.

```sh
ax25irc-kisshub --bind 127.0.0.1:8001 &
ax25ircd -c ax25ircd.toml &                 # radio.tnc.port = 8001
ax25irc-station --call SM0ABC-7 --gateway SK0MT-1 --channel '#rf'
```

Then connect an IRC client to `127.0.0.1:6667`, `/quote CALLSIGN SM0XYZ`, join
`#rf`, and the two of you are talking:

```
#rf <alice> hello over the air
*alice* direct to you
-- #rf members: SM0ABC|7,alice
```

while the channel monitor shows what it cost:

```
SK0MT-1>AIRC:A1......#rf.alice.hello over the air
SM0ABC-7>SK0MT-1:A1......#rf.morning all, 5 watts from Kista
```

## The station client

```sh
ax25irc-station --call SM0ABC-7 --gateway SK0MT-1 --channel '#rf' \
                --tnc tcp://127.0.0.1:8001
ax25irc-station --call SM0ABC-7 --gateway SK0MT-1 \
                --tnc serial:/dev/ttyUSB0@9600 --path SK0MT-2
```

Line-oriented, so it works over ssh and on a headless Pi. Commands:
`/join #chan`, `/part`, `/names`, `/msg <nick> <text>`, `/ping`, `/quit`.
Anything else goes to the current channel. Chat is sent unreliably (a
retransmission arriving thirty seconds late is noise); joins, private messages
and requests are ACKed and retried.

## How it works

| Layer | Module | Job |
|---|---|---|
| Link | `ax25::tnc` | KISS over TCP/serial/loopback, reconnect, TX pacing, bounded TX queue |
| Frame | `ax25::frame`, `ax25::address` | AX.25 v2.2 UI frames, callsign addressing, digipeater paths |
| Application | `airc::frame` | AIRC/1: 8-octet header, plain UTF-8 fields |
| Session | `airc::session` | Sequence numbers, ACK/retry, fragmentation, duplicate suppression |
| Gateway | `bridge`, `policy` | RF ⇄ IRC translation, airtime and legality gates |
| Server | `server`, `irc::client` | Users, channels, RFC 1459 over TCP |

Everything meets in a single-task event loop. Full rationale in
`docs/DESIGN.md`; the on-air protocol is specified in `docs/PROTOCOL.md`.

### The bandwidth problem, in one table

At 1200 baud a channel carries roughly 120 bytes per second, shared, half
duplex. One channel message:

| Format | Bytes | Channel time |
|---|---|---|
| `:SM0ABC|7!rf@sk0mt.ax25 PRIVMSG #rf :hello` | 58 | ~0.48 s |
| AIRC/1 `MSG ["#rf", "hello"]` | 18 | ~0.15 s |

So the RF side never sees numerics, MOTDs, WHOIS replies, nick changes or (by
default) join/part notices. Channel traffic is transmitted once as a broadcast
rather than once per station, and a message heard on the air is never repeated
back onto it — every station in range already got it.

## Messages for stations that are out of range

A private message to a callsign that is not currently on frequency is held and
delivered when the station is next heard, carrying its age:

```
-> PRIVMSG SM0ABC|7 :meet on 145.500 at 1900
<- NOTICE: SM0ABC-7 is not on frequency. Held for delivery when the station
   is next heard (1 waiting, dropped after 24h).

   ... later, on the station ...
   *alice* [held 3h] meet on 145.500 at 1900
```

Bounded per station, bounded overall, and expiring — see `mailbox_*` in the
config. A gateway is not a mail server.

## Extra commands

Beyond RFC 1459, two local commands:

```
CALLSIGN <call>     identify with an amateur callsign (required before your
                    traffic will be relayed to RF; recorded as an unverified
                    claim and logged as such)
CALLSIGN            show what you are currently identified as
```

For control operators (after `OPER`):

```
RADIO STATUS            transmitter state, frame and byte counters, stations heard
RADIO OFF               stop transmitting immediately; IRC keeps running
RADIO ON                resume
RADIO ID                identify now
RADIO HEARD             stations, last heard, queue depth, drops
RADIO MAIL              what is held, and for whom
RADIO KICK <callsign>   remove a station's presence
```

Channel mode `+r` marks a channel as bridged to RF. Only a control operator can
set or clear it, and channels created on the fly by `JOIN` are never `+r`.

## Identity

RF stations appear under their callsign: `SM0ABC-7` becomes the nickname
`SM0ABC|7` (IRC nicks cannot contain `-`). Callsign-shaped nicknames are
reserved, so an IP user cannot impersonate a station.

AX.25 has no authentication and this server does not pretend otherwise. A
callsign heard on the air is a claim; `CALLSIGN` from an IP user is a claim.
Both are logged. If you need real authentication, it belongs on the IP side —
TLS and a tunnel — and the RF side should be treated as what it is: a public
party line.

## Configuration

Every option is documented inline in `ax25ircd.example.toml`. The validator
refuses configurations that would put you in an awkward position, including an
identification interval over ten minutes, a gateway "callsign" that is not a
plausible callsign, more than two digipeater hops, and `radio.enabled` with no
bridged channel.

## Testing

```sh
cargo test
```

The session layer is a pure state machine driven by an explicit `now`, so
retries, timeouts and reassembly are tested in microseconds without a radio.
`tests/gateway.rs` asserts on the actual bytes transmitted: that a station's
JOIN reaches IRC, that a message from the air is not re-transmitted, that an
unidentified user's message never reaches the antenna, that apparent ciphertext
is refused, and that an acknowledged private message is not retried.

## Layout

```
src/
  lib.rs             crate root: layering and public modules
  main.rs            ax25ircd — argument parsing, wiring, shutdown
  config.rs          TOML config and validation
  callsign.rs        callsign/SSID type, nickname mapping
  policy.rs          rate limits, sanitation, plain-language screen
  bridge.rs          what happens when a frame arrives from the air
  ax25/              address, frame, kiss, tnc
  airc/              frame (codec), session (reliability)
  irc/               message (parser), numerics, client (TCP task)
  server/            event loop, state, commands, mailbox
  bin/
    ax25irc-station.rs   client for the radio side
    ax25irc-kisshub.rs   virtual channel for development
docs/
  DESIGN.md          why it is built this way
  PROTOCOL.md        AIRC/1 specification
  REGULATORY.md      the rules, and what the software does about them
tests/
  gateway.rs         end-to-end tests over a loopback TNC
packaging/
  ax25ircd.service   systemd unit (SIGINT on stop, so the station signs off)
ax25ircd.example.toml
LICENSE-MIT
LICENSE-APACHE
```

## Not doing

Server linking (IRC's S2S protocol assumes cheap reliable links; two gateways
on one frequency should share a channel over the air instead), DCC and CTCP
file transfer, and encryption of any kind on the RF path.

## Licence

MIT or Apache-2.0, at your option.
