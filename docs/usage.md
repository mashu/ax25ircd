# IRC

Connect any RFC 1459 client to `127.0.0.1:6667`. Join `#local` for internet-only
chat. `#rf` is `+rm`: moderated and bridged. Identify with `CALLSIGN` for `+v`
(permission to speak on the channel). Speaking on IRC and radiating are
separate: without RF-TX privilege your messages stay on the internet, even in
`#rf`. RF stations still hear nothing you type until a control operator grants
you.

## Local commands

Beyond RFC 1459:

```
CALLSIGN <call>     identify with an amateur callsign; on +r channels this
                    grants +v (permission to speak). It does not, by itself,
                    put your traffic on the air.
CALLSIGN            show what you are currently identified as
RFKEY <password>    present the shared RF-TX key (if policy.rf_tx_password is set)
REGISTER <password> bind the current nick to an Argon2id hash on disk
IDENTIFY <password> prove you own a registered nick; may grant RF-TX if the
                    nick is listed in policy.rf_tx_nicks
UNREGISTER <password>
RADIO               public transmitter status (ON/OFF, callsign, frames)
KICK <chan> <nick>  channel operator or server operator
KILL <nick>         server operator only
```

`MODE` on yourself reports `+R` when you hold RF-TX. `WHOIS` says so too.

Channel operators are listed in the config (`operators = ["alice"]`) and
receive `+o` after `IDENTIFY`.

## Control operator (after OPER)

```
RADIO STATUS            transmitter state, frame and byte counters, stations heard
RADIO OFF               stop transmitting immediately; IRC keeps running
RADIO ON                resume
RADIO ID                identify now
RADIO HEARD             stations, last heard, queue depth, drops
RADIO MAIL              what is held, and for whom
RADIO KICK <callsign>   remove a station's presence
RADIO GRANT <nick>      grant RF-TX (and persist it if the nick is registered)
RADIO REVOKE <nick>     take RF-TX away
```

Channel mode `+r` marks a channel as bridged to RF. Only a control operator can
set or clear it, and channels created on the fly by `JOIN` are never `+r`.

## Identity

RF stations appear under their callsign: `SM0ABC-7` becomes the nickname
`SM0ABC|7` (IRC nicks cannot contain `-`). Callsign-shaped nicknames are
reserved, including the casemapping lookalike `SM0ABC\7` and the AX.25 form
`SM0ABC-7`, so an IP user cannot impersonate a station.

AX.25 has no authentication and this server does not pretend otherwise. A
callsign heard on the air is a claim; `CALLSIGN` from an IP user is a claim.
Both are logged. Putting an IP user's text on the air is a separate, operator
granted privilege (`policy.ip_rf_tx`). The default is that ordinary IRC
clients chat on the internet only. See [design.md](design.md) §4.

## Held messages

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

## Configuration

Every option is documented inline in `ax25ircd.example.toml`. The validator
refuses configurations that would put you in an awkward position, including an
identification interval over ten minutes, a gateway "callsign" that is not a
plausible callsign, more than two digipeater hops, and `radio.enabled` with no
bridged channel.
