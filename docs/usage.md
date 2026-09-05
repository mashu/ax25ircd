# IRC

Connect any RFC 1459 client to `127.0.0.1:6667`. Two kinds of people share a
bridged channel. They are not the same account.

* **Internet user** — ordinary nick (`alice`). Registers, may be granted RF-TX,
  claims a callsign with `CALLSIGN`. The nick itself is not a callsign.
* **RF station** — `ax25irc-station` or any AIRC client. Already on the air.
  Appears as a reserved nick derived from the AX.25 source (`SM0ABC-7` →
  `SM0ABC|7`). No `REGISTER`, no `RADIO GRANT`. Restrict with
  `policy.allow_callsigns` / `deny_callsigns`.

Callsign-shaped nicks (`SM0ABC|7`, `SM0ABC-7`, `SM0ABC\7`) are reserved for
stations heard on the air. An internet user cannot take them.

Speaking on IRC and radiating are separate. Without RF-TX your messages stay
on the internet even in `#rf`.

## Letting an internet user key the transmitter

Three things. The nick does **not** have to look like a callsign.

1. **Register the nick.** `/quote REGISTER <password>` then, on later
   connects, `/quote IDENTIFY <password>`. Written to `accounts.file`
   (`nicks.json` by default).
2. **A control operator grants RF-TX.** They `OPER`, then
   `/quote RADIO GRANT alice`. Refused if the nick is not registered — there
   would be nothing to persist. The flag is stored on that account and
   applied immediately if they are online.
3. **Claim a callsign.** `/quote CALLSIGN SM0XYZ`. Required every session
   unless the nick is identified, in which case the last claim is restored
   from the nick file. Still a logged claim, not proof of licence.

Then join `#rf`. If an RF station is in the channel and the transmitter is on,
`PRIVMSG #rf` is radiated. You will get a NOTICE when it actually goes out.

A control operator (`OPER`) has RF-TX for that session without a grant. They
still need `CALLSIGN` before their text is radiated. On a public
`listen.bind`, `[[opers]]` passwords must be Argon2id hashes from
`ax25ircd --hash-password`; plaintext is accepted only on loopback.

`UNREGISTER` deletes the account, including the grant and stored callsign.
Changing nick drops `IDENTIFY`; RF-TX comes back only after `IDENTIFY` on a
nick that still has the grant.

## Letting an RF station on the air

The station transmits with its own radio. The gateway does not grant it RF-TX.

```sh
ax25irc-station --call SM0ABC-7 --gateway SK0MT-1 --channel '#rf'
```

If `allow_callsigns` is empty, any plausible amateur callsign may use the RF
side. A non-empty list is a closed system. `deny_callsigns` bans a station
(SSID 0 bans every SSID of that call).

## After a restart

`Accounts::load` reads `nicks.json` at startup. There is no other privilege
store.

| | Survives | Lost |
|---|---|---|
| Registered nicks, password hashes, RF-TX grants, last CALLSIGN | `nicks.json` | |
| Channels, `+r`, channel operator lists, OPER passwords | config file | runtime `MODE` changes |
| Who is connected, mailbox, RF sessions, `OPER` this session | | yes — in memory |

On connect, `IDENTIFY` reloads RF-TX and the stored callsign. `OPER` is entered
again each session. The mailbox is a cache, not a mail server.

## Channel modes

Set in `[[channels]]` in the config. Reloaded on start. Only `OPER` can change
`+r` at runtime, and that change is not written back to the file.

| Mode | Meaning |
|---|---|
| `+r` | Bridged to RF. Config: `rf = true`. JOIN-created channels are never `+r`. |
| `+m` | Moderated. Default on `+r` channels: only `+v` / `+o` may `PRIVMSG`. |
| `+t` | Topic locked (default). |
| `+k` / `+l` | Key / limit, as usual. |
| `+n` | Always on. No external messages. |

A `+r` message is radiated only if the transmitter is on, at least one RF
station is in the channel, the sender has RF-TX, and they have a CALLSIGN.

## User and member flags

| Flag | Where | Meaning |
|---|---|---|
| `+v` | channel | May speak on a `+m` channel. On `+r`, a CALLSIGN (or OPER) grants this. Does **not** mean the text is radiated. |
| `+o` | channel | Channel operator. On `+r`, only a server OPER may grant it. Config `operators = ["alice"]` applies after IDENTIFY. |
| `+o` | user (`MODE` yourself) | Control operator (`OPER` this session). |
| `+R` | user | RF-TX. `WHOIS` says so too. |

## Commands

RFC 1459 `NICK` `USER` `JOIN` `PART` `PRIVMSG` `NOTICE` `TOPIC` `NAMES` `LIST`
`WHO` `WHOIS` `MODE` `MOTD` `LUSERS` `AWAY` `PING` `PONG` `QUIT` `KICK` work as
usual. Local extensions:

```
OPER <name> <pass>   control operator this session ([[opers]] in the config)
CALLSIGN <call>      claim a callsign; +v on +r. Required before radiation.
CALLSIGN             show the current claim
REGISTER <password>  bind this nick to an Argon2id hash on disk
IDENTIFY <password>  prove you own it; reloads RF-TX and last CALLSIGN
UNREGISTER <password>
RADIO                transmitter status (anyone)
KICK <chan> <nick>   channel op or OPER
KILL <nick>          OPER only
```

After `OPER`:

```
RADIO STATUS              transmitter, frames, stations heard, duty cycle
RADIO DUTY                airtime spent, backlog, limits in force, PA cooldown
RADIO QUEUE               everything accepted but not yet transmitted
RADIO LIMIT DUTY <1-50|off>    lower the duty cycle now, no restart
RADIO LIMIT PACING <ms|off>    widen the gap between transmissions
RADIO OFF / ON            kill switch; purges the transmit queue
RADIO ID                  identify now (rate-limited to id_interval)
RADIO HEARD               stations, last heard, queue depth
RADIO MAIL                held private messages (in memory, expires)
RADIO KICK <callsign>     drop an RF station's presence
RADIO GRANT <nick>        persist RF-TX on a registered nick
RADIO REVOKE <nick>       take it away (also persisted)
```

## Held messages

A private message to a callsign that is not on frequency is held and delivered
when the station is next heard, carrying its age. Bounded and expiring; gone
on restart. See `mailbox_*` in the config.

```
-> PRIVMSG SM0ABC|7 :meet on 145.500 at 1900
<- NOTICE: SM0ABC-7 is not on frequency. Held for delivery when the station
   is next heard (1 waiting, dropped after 24h).
```

## Configuration

Every option is documented inline in `ax25ircd.example.toml`. Unknown keys are
refused. The validator also refuses an identification interval over ten
minutes, a gateway "callsign" that is not a plausible callsign, more than two
digipeater hops, and `radio.enabled` with no bridged channel.
