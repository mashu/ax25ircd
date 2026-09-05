# Airtime, duty cycle and the transmit queue

A packet gateway is an automatically controlled station. Nobody is watching it
when the IRC side gets busy at two in the morning, and the two things it can
damage — the transmitter's finals and the shared channel — are both slow
enough that you find out afterwards.

ax25ircd has two separate mechanisms for this, and they are easy to confuse.

| | `[policy]` | `[radio.duty]` |
|---|---|---|
| Counts | messages | seconds of key-down time |
| Scope | per user, per station, per channel | the whole transmitter |
| Protects | fairness between users | the finals and the band |
| Bypassed by | nothing | nothing |

`[policy]` stops one loud user drowning out the others. It does not stop
*fifty* polite users between them keying your radio continuously, and it has
no idea how long a message actually takes to transmit.

`[radio.duty]` is the one that keeps the smoke inside the transistors.

## Why this matters more than it sounds

At 300 baud — HF packet, which is what a QMX runs — a 128-octet AX.25 frame is
about **four seconds of unbroken carrier**, plus TXDELAY and TXTAIL. So:

* A single long IRC line, fragmented into three frames, is ~15 s of transmit.
* Ten messages held in a station's mailbox, flushed the moment that station is
  heard, is over a minute of near-continuous key-down.
* A retry cycle triples it.

A QMX has no heatsink worth the name and no thermal fold-back. Sustained
transmit at that duty is the documented way to kill its finals. Almost any HF
transceiver derates hard above 30-50 % duty; a QRP rig has less margin, not
more.

None of this is malicious traffic. It is one busy evening on `#rf`.

## How the governor works

Every frame is costed before it is keyed:

```text
airtime = txdelay + (octets_on_wire × 8 / baud) + txtail
```

and three independent limits are checked:

1. **Duty cycle.** Airtime in a sliding window (default 25 % of ten minutes).
2. **Continuous run.** After `max_continuous_secs` of unbroken transmitting,
   the transmitter is forced off for `cooldown_secs`. Transmissions less than
   three seconds apart count as one run, because as far as the power amplifier
   is concerned they are.
3. **Rolling-hour budget.** A hard ceiling on airtime per hour, so a
   pathological backlog cannot drip-feed the channel indefinitely.

A frame that cannot go yet is **deferred**, not dropped, and is retried exactly
when enough old airtime falls out of the window. A frame held longer than
`max_hold_secs` **is** dropped and counted: on a 1 kbit/s channel a two-minute-
old chat line costs the same airtime as a fresh one and carries less
information.

Station identification bypasses all of this. It is one short frame, it is a
legal obligation, and it goes out on a separate priority path that neither the
duty limits nor the operator's inhibit can hold back.

## Configuration

```toml
[radio.duty]
enabled = true
baud = 300               # 300 = HF SSB packet, 1200 = VHF FM
txdelay_ms = 400         # match the TNC's TXDELAY
txtail_ms = 300          # match the TNC's TXTAIL
window_secs = 600
max_duty_percent = 25
max_continuous_secs = 30
cooldown_secs = 60
hourly_airtime_secs = 900   # 0 disables
max_hold_secs = 120
```

Two starting points:

=== "QRP HF (QMX, 300 baud)"

    The defaults above. Conservative on purpose: this is the configuration
    most likely to be damaged by getting it wrong.

=== "VHF FM (1200 baud, a radio with a heatsink)"

    ```toml
    [radio.duty]
    baud = 1200
    txdelay_ms = 300
    txtail_ms = 100
    max_duty_percent = 40
    max_continuous_secs = 60
    cooldown_secs = 30
    hourly_airtime_secs = 1800
    ```

`ax25ircd --check` refuses a configuration where a full-length frame is longer
than the whole duty allowance — otherwise nothing would ever be transmitted and
you would be left guessing why.

## Watching it

```
/quote RADIO DUTY
```

```
airtime: 12.4% duty over the last 600s, 74s keyed in the last hour (budget 900s);
total keyed 512s; 3 frames deferred, 0 dropped stale, 0 dropped while inhibited
limits: 25% of 600s, max 30s continuous then 60s cooldown, 900s per rolling hour,
frames dropped after 120s held (baud 300, txdelay 400ms, txtail 300ms)
```

`RADIO STATUS` shows the duty percentage and any active cooldown to everyone;
the full breakdown is control-operator only.

## Stopping it

```
/quote RADIO OFF
```

This is the kill switch, and it is a real one:

1. The station identifies, because it has transmitted and owes the band a
   sign-off.
2. Everything already queued in the TNC task is **discarded**, not drained.
   An operator who says "off" does not mean "off once the backlog clears".
3. Nothing further is queued, and the TNC task refuses to key up even if
   something tries.

`RADIO ON` re-enables it. The airtime already spent is still counted — the
window does not reset because you toggled the switch.

If you need something more forceful than that, stop the process: with
`panic = "abort"` and no PTT of its own, ax25ircd cannot leave the radio keyed.
PTT belongs to Direwolf, and Direwolf drops it when its client goes away.

!!! warning "`enabled = false`"
    Turning the governor off is only reasonable into a dummy load. `RADIO DUTY`
    says so in as many words, because the setting is easy to copy from
    somebody's example config and forget.
