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
`#rf`:

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
