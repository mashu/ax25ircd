# Station client and virtual channel

## ax25irc-station

Line-oriented, so it works over ssh and on a headless Pi.

```sh
ax25irc-station --call SM0ABC-7 --gateway SK0MT-1 --channel '#rf' \
                --tnc tcp://127.0.0.1:8001
ax25irc-station --call SM0ABC-7 --gateway SK0MT-1 \
                --tnc serial:/dev/ttyUSB0@9600 --path SK0MT-2
```

Commands: `/join #chan`, `/part`, `/names`, `/msg <nick> <text>`, `/ping`,
`/quit`. Anything else goes to the current channel. Chat is sent unreliably (a
retransmission arriving thirty seconds late is noise); joins, private messages
and requests are ACKed and retried.

Serial TNCs need a build with `--features serial`.

### Airtime

The station client runs the same airtime governor as the gateway, with the same
50 % duty ceiling and the same refusal to accept a run/cooldown pair that would
exceed it. You are a human typing rather than an automatic service, but it is
the same QRP radio at the same baud rate, and the finals do not know the
difference.

```sh
ax25irc-station --call SM0ABC-7 --gateway SK0MT-1 \
                --baud 300 --txdelay 400 --txtail 300 \
                --duty 25 --max-continuous 30 --cooldown 60
```

Those are the defaults, and they assume HF: 300 baud, a QMX-class radio. For
1200 baud VHF FM with a heatsink, `--baud 1200 --duty 40`. `--txdelay` and
`--txtail` are pushed to the TNC as the KISS parameters as well as being used
to price each frame, so the modem and the model cannot disagree.

See [Airtime](airtime.md) for what the limits mean and why they are shaped the
way they are.

## ax25irc-kisshub

A virtual channel: every TCP client that connects is a station on the same
frequency, and it prints every frame in `axlisten` monitor format. No radio, no
licence.

```sh
ax25irc-kisshub --bind 127.0.0.1:8001 &
ax25ircd -c ax25ircd.toml &                 # radio.tnc.port = 8001
ax25irc-station --call SM0ABC-7 --gateway SK0MT-1 --channel '#rf'
```

Then connect an IRC client to `127.0.0.1:6667`, `/quote CALLSIGN SM0XYZ`, join
`#rf`. That lets you speak on IRC. To key the virtual transmitter from IRC,
register the nick and have a control operator `RADIO GRANT` it — see
[usage.md](usage.md).

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
