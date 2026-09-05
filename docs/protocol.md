# AIRC/1 — the on-air protocol

Status: draft, version 1. This document is normative for interoperability and
is published so that the protocol cannot be said to obscure the meaning of a
transmission.

## 1. Carriage

AIRC/1 messages travel in the information field of **AX.25 v2.2 UI frames**
with `PID = 0xF0` ("no layer 3 protocol").

* **Source address**: the transmitting station's callsign and SSID.
* **Destination address**: the callsign of the intended station for unicast, or
  the gateway's configured protocol address (default `AIRC`) for broadcast.
  Identification frames use `ID`.
* **Digipeater path**: at most two hops.

The AX.25 source address is the sender's identity. AIRC never repeats it in the
payload.

## 2. Frame format

```
 0      1      2      3      4      5      6      7      8 ...
+------+------+------+------+------+------+------+------+---------------+
| 'A'  | '1'  | kind |flags |    seq (BE) | fidx | ftot | payload       |
+------+------+------+------+------+------+------+------+---------------+
```

| Field | Size | Meaning |
|---|---|---|
| magic | 2 | ASCII `A1`. Distinguishes AIRC from APRS and other traffic on frequency. |
| kind | 1 | Message type, table below. |
| flags | 1 | Bit 0 `ACK_REQ`, bit 1 `RETRY`, bit 2 `TRUNCATED`. Other bits reserved, transmitted as 0, ignored on receipt. |
| seq | 2 | Sequence number, per sender, big endian, wraps, never 0. One space per station, covering both its unicast and its broadcast traffic. |
| fidx | 1 | Fragment index, 0-based. |
| ftot | 1 | Fragment count, ≥ 1. |
| payload | n | Fields separated by `0x1F`, UTF-8. |

Total header: 8 octets. The payload is limited by the AX.25 `paclen` in use
(128 by default, 256 maximum), so 120 payload octets per frame in the default
configuration.

Receivers **must** ignore frames whose magic does not match, whose `kind` they
do not recognise, or where `ftot == 0` or `fidx >= ftot`.

## 3. Message types

Uplink is station → gateway, downlink is gateway → station. The asymmetry is
deliberate: uplink omits the sender (it is in the AX.25 address), downlink adds
it (the receiving station has no other way to know who spoke).

| Kind | Value | Direction | Payload fields |
|---|---|---|---|
| `HELLO` | 0x01 | up | (optional) client name/version |
| `WELCOME` | 0x02 | down | server name, first MOTD line |
| `JOIN` | 0x03 | up | channel |
| `PART` | 0x04 | up | channel, reason? |
| `MSG` | 0x05 | up | target, text |
| | | down | target, from, text |
| `NOTICE` | 0x06 | both | same as `MSG` |
| `NAMES` | 0x07 | up | channel |
| `NAMES_REPLY` | 0x08 | down | channel, comma-separated nicks, topic? |
| `PING` | 0x09 | up | token |
| `PONG` | 0x0A | down | token |
| `ACK` | 0x0B | both | 2 octets: the sequence number being acknowledged |
| `ERROR` | 0x0C | down | numeric-ish code, text |
| `ID` | 0x0D | down | identification text |
| `QUIT` | 0x0E | up | reason? |
| `PRESENCE` | 0x0F | down | channel, nick, `+` or `-` |
| `STORED` | 0x10 | down | target, from, text, age in seconds |

`ACK` is the only message whose payload is binary rather than text fields.

`STORED` is a `MSG` that was held while the station was out of range; the
fourth field is how long it waited, in seconds, so a client can show
`[held 3h]` rather than pretending the message is fresh.

Nicknames are rendered with `|` where an SSID would use `-`: the station
`SM0ABC-7` appears as `SM0ABC|7`. Channel names keep their leading `#`.

## 3.1 Addressing rules for receivers

A station receives every frame on the channel, not only its own. Before
processing a frame it **must** check the AX.25 destination address:

* addressed to its own callsign — process it, and ACK if asked;
* addressed to a protocol address (one that is not a plausible amateur
  callsign, such as `AIRC` or `ID`) — process it as a broadcast, never ACK it;
* addressed to another station's callsign — ignore it completely.

Ignoring the third case matters for more than politeness. Sequence numbers are
per sender, so consuming another station's unicast traffic pollutes the
duplicate-suppression window and causes messages meant for you to be discarded
as duplicates.

The **gateway** applies the rule more strictly still: it acts only on frames
addressed to its own callsign, and never on broadcasts. `MSG` is the same
`kind` in both directions but a different shape — uplink `[target, text]`,
downlink `[target, from, text]` — so a gateway that processed broadcasts would
read another gateway's downlink as uplink traffic from a station, relay it, and
transmit it again. Two gateways sharing a frequency would then key each other
indefinitely, with nobody watching either of them. Stations always unicast to
the gateway, so nothing is lost by the restriction.

## 3.2 What the gateway will and will not transmit

The gateway is an automatically controlled station on a shared, thermally
limited channel, so its side of the protocol is deliberately quieter than the
IRC feature set behind it.

* **`JOIN` is answered with a member count, not a member list.** The reply is
  `NAMESREPLY [channel, "<n> here", topic]`. A station that joins did not ask
  who else is present, and a roll call is seconds of airtime.
* **`NAMES` is the only way to get the list**, and the reply is capped both by
  count (`radio.rf_names_max`) and by length; the truncation is visible as a
  trailing `+<n> more`.
* **`ERROR` is never acknowledged or retried.** A reliable error costs up to
  `max_retries` transmissions — more than the frame that provoked it.
* **`PRESENCE` is off by default.** Join and part notices are the lowest-value
  traffic on the channel.
* Quits, nick changes, channel modes and IRC numerics are never transmitted.

A station implementation should therefore expect `NAMESREPLY` in two shapes and
distinguish them by whether the second field is a count or a list.

## 4. Reliability

Two modes:

* **Unreliable broadcast.** `flags.ACK_REQ` clear, addressed to the protocol
  address. Used for channel messages, presence and ID. One transmission
  reaches every station in range. Receivers deduplicate on (source, seq).
* **Reliable unicast.** `flags.ACK_REQ` set, addressed to a station callsign.
  The receiver replies with `ACK` carrying the sequence number. The sender
  retries up to `max_retries` times with linear backoff (`ack_timeout`,
  2×, 3×, capped at 4×), with `flags.RETRY` set on repeats, then gives up.

One reliable message is in flight per peer at a time; further messages queue
behind it and the queue is bounded (16 by default). A duplicate that has
already been delivered is still ACKed, because the usual reason for a
retransmission is that the previous ACK was lost.

## 5. Fragmentation

If a payload exceeds `paclen - 8`, it is split. All fragments carry the same
`seq` and `kind`, with `fidx` counting from 0 to `ftot - 1`. Fragments are
reassembled by concatenating payloads in index order. Fragmentation happens on
raw octets, so a UTF-8 sequence may be split across fragments; decoding happens
after reassembly. Incomplete reassembly buffers are discarded after a timeout
(60 s by default).

Reliable fragmented messages are acknowledged as a whole: the ACK carries the
shared sequence number and is sent when the last missing fragment arrives.

## 5.1 Held messages

If a station is not in range when someone sends it a private message, the
gateway may hold the message and deliver it as a `STORED` frame on next
contact. Holding is bounded per station, bounded overall, and expires; a
gateway is entitled to refuse. Nothing in the protocol requires a client to do
anything special — `STORED` can be treated exactly like `MSG` if the age is not
interesting.

## 6. Station lifecycle

```
        (nothing)
            │  send HELLO ──────────────► gateway creates presence, sends WELCOME
            ▼
        registered
            │  JOIN #rf ────────────────► gateway replies NAMES_REPLY
            ▼
        in channel
            │  MSG / NOTICE / NAMES / PING
            │  PART, QUIT, or silence for peer_idle_timeout
            ▼
        (nothing)
```

The gateway is forgiving about lost frames: any valid AIRC frame from a
plausible amateur callsign creates the station's presence, and a `MSG` to a
bridged channel auto-joins it. A station that loses its `JOIN` in a collision
should not lose its conversation too.

## 7. Worked example

Station `SM0ABC-7` says "hi all" in `#rf`.

AX.25 UI frame, `SM0ABC-7 > SK0MT-1` (the gateway callsign), `PID 0xF0`, information field:

```
41 31 05 00 00 2A 00 01 23 72 66 1F 68 69 20 61 6C 6C
 A  1  ^  ^  ^^^^^  ^  ^  #  r  f  ␟  h  i     a  l  l
       |  |    |    |  └── ftot = 1
       |  |    |    └───── fidx = 0
       |  |    └────────── seq  = 42
       |  └─────────────── flags: unreliable
       └────────────────── kind: MSG
```

18 octets of information field, 35 octets of AX.25 frame including addresses
and FCS — about 0.25 s of channel time at 1200 baud.

The gateway relays it to IRC as
`:SM0ABC|7!rf@SM0ABC-7.ax25 PRIVMSG #rf :hi all` and does **not** re-transmit
it. When `alice` (identified as `SM0XYZ`) replies, the gateway broadcasts:

```
41 31 05 00 00 07 00 01 "#rf" ␟ "alice" ␟ "hello Anders"
```

## 8. Version negotiation

The magic contains the version digit. A future AIRC/2 uses `A2`; an AIRC/1
implementation ignores it as foreign traffic, which is the correct behaviour on
a shared channel. `HELLO` may carry a client name and version string for
diagnostics; the gateway does not act on it.

## 9. What is deliberately absent

No compression, no encryption, no binary-packed text, no dictionary coding of
nicknames or channels. All of these would save airtime; all of them make it
harder for a third party monitoring the frequency to read the traffic, which is
exactly what amateur regulations require to be possible.
