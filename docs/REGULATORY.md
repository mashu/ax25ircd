# Regulatory notes

**This is not legal advice.** It is a summary of the rules that shaped the
design, written by people who are not your regulator. Amateur radio rules vary
by country and change over time. Before you enable `radio.enabled`, read your
own licence conditions and your national regulations, and satisfy *yourself*
that what this software does is permitted where you are. You, the licensee, are
responsible for everything your station transmits.

## 1. The four rules that matter here

### 1.1 No obscured meaning

Amateur transmissions must not use codes or ciphers intended to hide the
meaning of a message. In the United States this is 47 CFR §97.113(a)(4); most
other administrations have an equivalent, and the ITU Radio Regulations
(Article 25.2A) say the same thing internationally.

What the software does:

* AIRC/1 is plain UTF-8 behind a documented 8-octet header. The specification
  is published in `docs/PROTOCOL.md` precisely so that anyone monitoring the
  frequency can decode it.
* No compression, no encryption, no dictionary coding — even though all three
  would save meaningful airtime.
* `policy.block_apparent_ciphertext` refuses to transmit text that looks like a
  PGP block or a long high-entropy base64 token. It is a conservative
  heuristic, not a guarantee: it catches the obvious cases and leaves judgement
  to you.
* TLS, if you put it in front of the IP side, protects the hop between the user
  and the gateway and stops there. This asymmetry is stated to every user at
  registration.

Note the grey area the software does *not* enter: authentication (as opposed to
concealment) is treated differently in different jurisdictions, and some
administrations explicitly permit it for control links. There is no signing or
challenge-response in AIRC/1. If you want it, understand your local position
first.

### 1.2 Station identification

An automatically controlled station must identify itself at intervals — ten
minutes in most jurisdictions (§97.119(a) in the US; similar elsewhere), and at
the end of a series of transmissions.

What the software does:

* Refuses to start if `radio.id_interval_secs` is 0 or greater than 600.
* Transmits an `ID` frame carrying the gateway callsign whenever the interval
  has elapsed *and* the station has transmitted since the last ID. It does not
  identify an idle station, because that is just QRM.
* Transmits an ID on clean shutdown if anything was transmitted since the last
  one.
* `RADIO ID` identifies on demand.
* Every AX.25 frame also carries the gateway callsign in its source address.

Your callsign, not the network's, goes in `radio.callsign`, and the config
check rejects anything that is not a plausible amateur callsign (it must
contain both a letter and a digit — `GATEWAY` is refused).

### 1.3 Third-party traffic

When an unlicensed person's message is transmitted by your station, that is
third-party traffic. Rules differ sharply: some administrations permit it
broadly, some only with specific countries under a third-party agreement, some
not at all. An IRC gateway is a third-party traffic machine by construction.

What the software does:

* `policy.require_callsign_for_rf` (on by default) means an IP user's messages
  are not transmitted until they have identified with `CALLSIGN <call>`. Users
  who have not are told why, and their message still reaches the IRC side of
  the channel.
* `policy.allow_callsigns` turns the gateway into a closed system: only listed
  stations may use it at all.
* `policy.deny_callsigns` bans specific stations; a listed callsign with SSID 0
  bans every SSID of that station.
* Nothing is transmitted to a `+r` channel unless at least one RF station is
  actually in it.

The `CALLSIGN` command records a *claim*. It is not verification. If your
regulator's position requires you to know that the originator is licensed, you
need an out-of-band process (a closed `allow_callsigns` list, club membership,
whatever) — the software will not do it for you and does not pretend to.

### 1.4 Content and purpose

Amateur radio is not a common carrier. Business communications, broadcasting,
music, obscenity and (in most places) encrypted or commercial traffic are
prohibited. An open IRC channel bridged to RF will eventually carry something
you did not want radiated.

What the software does:

* Strips IRC formatting and control characters before transmission — what goes
  on the air is readable in a terminal.
* Caps message length (`max_rf_text_len`, default 160 characters) and rate
  (token buckets per station and per IP user).
* Logs every frame in `axlisten`-compatible monitor format so you can
  reconstruct what your station transmitted and when.
* Gives the control operator `RADIO OFF` (immediate transmitter kill, IRC keeps
  running), `RADIO KICK <callsign>`, and `MODE #chan -r` to unbridge a channel.

It does not do content filtering beyond that, and you should not expect it to.
The control operator is a person, not a config file.

## 2. Automatic control

Running this gateway means your station transmits without a human at the
controls. Most administrations allow automatic control for specific station
types on specific bands and segments — in the US, §97.109(d) permits it for
stations in the auto-control subbands, and packet is one of the intended uses.
Check that the frequency you plan to use is one where automatic control is
permitted for your licence class.

Practical consequences:

* Keep the control operator reachable. `OPER` plus `RADIO OFF` should be
  possible from your phone.
* Pick a frequency that is used for packet by local convention, and coordinate
  with whoever else is on it. `tx_pacing_ms` exists so you can be a good
  neighbour; do not set it to 0 on a shared channel.
* `radio.path` is capped at two digipeater hops, and empty is best. Long paths
  are the classic way to make yourself unpopular.

## 3. Before you go on the air — checklist

- [ ] Read your licence conditions on automatic control, third-party traffic
      and encryption.
- [ ] `radio.callsign` is *your* callsign (or your club's, with permission).
- [ ] `id_interval_secs` ≤ 600 and `id_text` says something useful about the
      station.
- [ ] The frequency permits automatic control for your licence class, and local
      users know you are there.
- [ ] `require_callsign_for_rf = true` unless you have a specific reason.
- [ ] `allow_callsigns` populated if your rules require a closed system.
- [ ] You can reach `RADIO OFF` within a minute, from wherever you are.
- [ ] Logs are being kept somewhere you can read them later.
- [ ] `tx_pacing_ms` is set so you occupy a sane fraction of the channel.
- [ ] You have listened on the frequency for a while first.

## 4. Regional pointers

These are starting points for your own reading, not authority:

* **United States** — 47 CFR Part 97, especially §97.109 (control),
  §97.113 (prohibited transmissions), §97.115 (third-party), §97.119 (ID),
  §97.221 (automatically controlled digital stations).
* **United Kingdom** — Ofcom Amateur Radio Licence terms, notably the clauses
  on unattended operation and message content.
* **Sweden** — PTS regulations (PTSFS) on amateur radio; SSA publishes
  practical guidance on packet and unattended stations.
* **Germany** — AFuG/AFuV; unattended operation has specific notification
  requirements.
* **Canada** — RBR-4.
* **IARU Region 1** — band plans, for choosing a frequency that will not annoy
  anyone.

## 5. If in doubt

Leave `radio.enabled = false`. The server is a perfectly good IRC daemon
without it, and `radio.tnc.kind = "loopback"` lets you exercise the entire
gateway path — including the on-air protocol — with nothing reaching an
antenna.
