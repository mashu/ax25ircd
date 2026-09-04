//! Configuration. Everything an operator can get legally wrong (station ID
//! interval, gateway callsign, what may cross to RF) lives here and is
//! validated at startup rather than discovered on the air.

use std::path::Path;
use std::time::Duration;

use serde::Deserialize;

use crate::callsign::Callsign;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(default)]
    pub listen: ListenConfig,
    #[serde(default)]
    pub radio: RadioConfig,
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub channels: Vec<ChannelConfig>,
    #[serde(default)]
    pub opers: Vec<OperConfig>,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub accounts: AccountsConfig,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Server name announced to clients, e.g. `ax25irc.sk0mt.example`.
    pub name: String,
    #[serde(default = "default_network")]
    pub network: String,
    #[serde(default)]
    pub motd: Vec<String>,
    #[serde(default = "default_max_nick_len")]
    pub max_nick_len: usize,
    #[serde(default = "default_max_channels")]
    pub max_channels_per_user: usize,
    /// Optional connection password for IP clients (PASS).
    #[serde(default)]
    pub password: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenConfig {
    #[serde(default = "default_bind")]
    pub bind: Vec<String>,
    #[serde(default = "default_ping_interval")]
    pub ping_interval_secs: u64,
    #[serde(default = "default_registration_timeout")]
    pub registration_timeout_secs: u64,
    /// Simultaneous IP connections from one host. 0 disables the cap.
    #[serde(default = "default_max_conns_per_host")]
    pub max_conns_per_host: u32,
}

impl Default for ListenConfig {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            ping_interval_secs: default_ping_interval(),
            registration_timeout_secs: default_registration_timeout(),
            max_conns_per_host: default_max_conns_per_host(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RadioConfig {
    #[serde(default)]
    pub enabled: bool,
    /// The gateway's own station callsign. This is the station that is
    /// transmitting, so this is the callsign that must be identified.
    #[serde(default)]
    pub callsign: String,
    /// AX.25 destination address for AIRC frames. Acts as a protocol marker
    /// so other users of the channel can filter us out.
    #[serde(default = "default_destination")]
    pub destination: String,
    /// Digipeater path, at most two hops by convention.
    #[serde(default)]
    pub path: Vec<String>,
    #[serde(default)]
    pub tnc: TncSection,
    /// Station identification interval. Must be <= 600 s.
    #[serde(default = "default_id_interval")]
    pub id_interval_secs: u64,
    #[serde(default = "default_id_text")]
    pub id_text: String,
    /// AX.25 information field limit.
    #[serde(default = "default_paclen")]
    pub paclen: usize,
    #[serde(default = "default_ack_timeout")]
    pub ack_timeout_secs: u64,
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
    #[serde(default = "default_idle_timeout")]
    pub peer_idle_timeout_secs: u64,
    /// Relay channel join/part notices to RF stations. Cheap on a quiet
    /// channel, expensive on a busy one.
    #[serde(default)]
    pub presence_notices: bool,
    /// Hold private messages for stations that are out of range and deliver
    /// them when the station is next heard.
    #[serde(default = "default_true")]
    pub mailbox_enabled: bool,
    /// Messages held per station.
    #[serde(default = "default_mailbox_per_station")]
    pub mailbox_per_station: usize,
    /// Messages held across all stations. A gateway is not a mail server.
    #[serde(default = "default_mailbox_total")]
    pub mailbox_total: usize,
    /// Held messages older than this are dropped.
    #[serde(default = "default_mailbox_ttl")]
    pub mailbox_ttl_secs: u64,
    /// Re-transmit messages that arrived from RF back onto RF, so that
    /// stations hidden from each other but both audible to the gateway can
    /// hold a conversation. Doubles the airtime of every RF message; leave it
    /// off unless you actually have a hidden-terminal problem.
    #[serde(default)]
    pub repeat_rf_traffic: bool,
    /// NOTICE the sender when a channel message is actually put on the air.
    #[serde(default = "default_true")]
    pub notice_air_relay: bool,
}

impl Default for RadioConfig {
    fn default() -> Self {
        toml::from_str("").expect("RadioConfig defaults are self-consistent")
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TncSection {
    /// "tcp", "serial" or "loopback".
    #[serde(default = "default_tnc_kind")]
    pub kind: String,
    #[serde(default = "default_tnc_host")]
    pub host: String,
    #[serde(default = "default_tnc_port")]
    pub port: u16,
    #[serde(default)]
    pub device: String,
    #[serde(default = "default_baud")]
    pub baud: u32,
    #[serde(default)]
    pub kiss_port: u8,
    #[serde(default = "default_tx_pacing")]
    pub tx_pacing_ms: u64,
    #[serde(default)]
    pub txdelay: Option<u8>,
    #[serde(default)]
    pub persistence: Option<u8>,
    #[serde(default)]
    pub slottime: Option<u8>,
}

impl Default for TncSection {
    fn default() -> Self {
        Self {
            kind: default_tnc_kind(),
            host: default_tnc_host(),
            port: default_tnc_port(),
            device: String::new(),
            baud: default_baud(),
            kiss_port: 0,
            tx_pacing_ms: default_tx_pacing(),
            txdelay: None,
            persistence: None,
            slottime: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    /// Longest message body relayed to RF. Longer messages are truncated and
    /// flagged, because a 400 character rant is 3 s of airtime.
    #[serde(default = "default_max_rf_text")]
    pub max_rf_text_len: usize,
    /// Token bucket per RF station.
    #[serde(default = "default_rf_msgs_per_min")]
    pub rf_msgs_per_min: u32,
    #[serde(default = "default_rf_burst")]
    pub rf_burst: u32,
    /// Same, for IP users sending into an RF-bridged channel.
    #[serde(default = "default_ip_msgs_per_min")]
    pub ip_to_rf_msgs_per_min: u32,
    /// Refuse to transmit text that looks like ciphertext or base64. Amateur
    /// rules in most countries forbid obscuring the meaning of a message.
    #[serde(default = "default_true")]
    pub block_apparent_ciphertext: bool,
    /// Only IP users who have identified with a callsign may have their
    /// traffic relayed to RF. Leave true unless you have thought hard about
    /// third-party traffic rules.
    #[serde(default = "default_true")]
    pub require_callsign_for_rf: bool,
    /// Callsigns that may not use the gateway at all.
    #[serde(default)]
    pub deny_callsigns: Vec<String>,
    /// If non-empty, only these callsigns may use the gateway.
    #[serde(default)]
    pub allow_callsigns: Vec<String>,
    /// IRC-side flood cap on +r channels (messages dropped, not just kept off the air).
    #[serde(default = "default_rf_channel_msgs")]
    pub rf_channel_msgs_per_min: u32,
    #[serde(default = "default_rf_channel_burst")]
    pub rf_channel_burst: u32,
    /// Commands per minute per IP nick (JOIN/PRIVMSG/MODE/...).
    #[serde(default = "default_ip_cmds_per_min")]
    pub ip_cmds_per_min: u32,
    #[serde(default = "default_ip_cmd_burst")]
    pub ip_cmd_burst: u32,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            max_rf_text_len: default_max_rf_text(),
            rf_msgs_per_min: default_rf_msgs_per_min(),
            rf_burst: default_rf_burst(),
            ip_to_rf_msgs_per_min: default_ip_msgs_per_min(),
            block_apparent_ciphertext: true,
            require_callsign_for_rf: true,
            deny_callsigns: Vec::new(),
            allow_callsigns: Vec::new(),
            rf_channel_msgs_per_min: default_rf_channel_msgs(),
            rf_channel_burst: default_rf_channel_burst(),
            ip_cmds_per_min: default_ip_cmds_per_min(),
            ip_cmd_burst: default_ip_cmd_burst(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelConfig {
    pub name: String,
    #[serde(default)]
    pub topic: String,
    /// Relay this channel over the air.
    #[serde(default)]
    pub rf: bool,
    /// Nicks that receive +o on join after IDENTIFY.
    #[serde(default)]
    pub operators: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperConfig {
    pub name: String,
    /// Plain password. This server does not pretend to be a security product;
    /// run it behind TLS or on localhost and treat OPER as a local console.
    pub password: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    /// Extra copy of tracing output (journald/stderr still get it).
    #[serde(default)]
    pub file: Option<String>,
    /// Append-only audit trail: connections, callsigns, kicks, RF TX.
    #[serde(default)]
    pub audit_file: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountsConfig {
    /// JSON file of Argon2id nick hashes. Created on first REGISTER.
    #[serde(default = "default_nicks_file")]
    pub file: String,
    /// How long a user may sit on a registered nick without IDENTIFY.
    #[serde(default = "default_identify_timeout")]
    pub identify_timeout_secs: u64,
    #[serde(default = "default_min_password")]
    pub min_password_len: usize,
}

impl Default for AccountsConfig {
    fn default() -> Self {
        Self {
            file: default_nicks_file(),
            identify_timeout_secs: default_identify_timeout(),
            min_password_len: default_min_password(),
        }
    }
}

impl Config {
    pub fn from_toml(text: &str) -> anyhow::Result<Self> {
        let cfg: Config = toml::from_str(text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path.as_ref())?;
        Self::from_toml(&text)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.server.name.trim().is_empty() {
            anyhow::bail!("server.name must be set");
        }
        for ch in &self.channels {
            if !crate::irc::message::is_channel_name(&ch.name) {
                anyhow::bail!("invalid channel name: {}", ch.name);
            }
        }
        if !self.radio.enabled {
            return Ok(());
        }

        let call: Callsign = self
            .radio
            .callsign
            .parse()
            .map_err(|e| anyhow::anyhow!("radio.callsign: {e}"))?;
        call.require_amateur()
            .map_err(|e| anyhow::anyhow!("radio.callsign: {e}"))?;
        self.radio
            .destination
            .parse::<Callsign>()
            .map_err(|e| anyhow::anyhow!("radio.destination: {e}"))?;
        for d in &self.radio.path {
            d.parse::<Callsign>()
                .map_err(|e| anyhow::anyhow!("radio.path entry {d}: {e}"))?;
        }
        if self.radio.path.len() > 2 {
            anyhow::bail!("radio.path: more than two digipeater hops is antisocial");
        }
        if self.radio.id_interval_secs == 0 || self.radio.id_interval_secs > 600 {
            anyhow::bail!(
                "radio.id_interval_secs must be between 1 and 600; \
                 an automatically transmitting station has to identify at least every 10 minutes"
            );
        }
        if self.radio.paclen < 32 || self.radio.paclen > 256 {
            anyhow::bail!("radio.paclen must be between 32 and 256");
        }
        if self.channels.iter().all(|c| !c.rf) {
            anyhow::bail!("radio.enabled is true but no channel has rf = true");
        }
        for c in self
            .policy
            .deny_callsigns
            .iter()
            .chain(&self.policy.allow_callsigns)
        {
            c.parse::<Callsign>()
                .map_err(|e| anyhow::anyhow!("policy callsign {c}: {e}"))?;
        }
        Ok(())
    }

    pub fn gateway_callsign(&self) -> Option<Callsign> {
        self.radio.callsign.parse().ok()
    }

    pub fn rf_path(&self) -> Vec<Callsign> {
        self.radio.path.iter().filter_map(|d| d.parse().ok()).collect()
    }

    pub fn id_interval(&self) -> Duration {
        Duration::from_secs(self.radio.id_interval_secs)
    }
}

fn default_network() -> String {
    "AX25IRC".into()
}
fn default_max_nick_len() -> usize {
    30
}
fn default_max_channels() -> usize {
    20
}
fn default_bind() -> Vec<String> {
    vec!["127.0.0.1:6667".into()]
}
fn default_ping_interval() -> u64 {
    120
}
fn default_registration_timeout() -> u64 {
    60
}
fn default_destination() -> String {
    "AIRC".into()
}
fn default_id_interval() -> u64 {
    540
}
fn default_id_text() -> String {
    "AX25IRC gateway".into()
}
fn default_paclen() -> usize {
    128
}
fn default_ack_timeout() -> u64 {
    12
}
fn default_max_retries() -> u32 {
    3
}
fn default_idle_timeout() -> u64 {
    1800
}
fn default_tnc_kind() -> String {
    "tcp".into()
}
fn default_tnc_host() -> String {
    "127.0.0.1".into()
}
fn default_tnc_port() -> u16 {
    8001
}
fn default_baud() -> u32 {
    9600
}
fn default_tx_pacing() -> u64 {
    1500
}
fn default_mailbox_per_station() -> usize {
    10
}
fn default_mailbox_total() -> usize {
    200
}
fn default_mailbox_ttl() -> u64 {
    24 * 3600
}
fn default_max_rf_text() -> usize {
    160
}
fn default_rf_msgs_per_min() -> u32 {
    6
}
fn default_rf_burst() -> u32 {
    4
}
fn default_ip_msgs_per_min() -> u32 {
    10
}
fn default_true() -> bool {
    true
}
fn default_max_conns_per_host() -> u32 {
    8
}
fn default_rf_channel_msgs() -> u32 {
    10
}
fn default_rf_channel_burst() -> u32 {
    4
}
fn default_ip_cmds_per_min() -> u32 {
    90
}
fn default_ip_cmd_burst() -> u32 {
    30
}
fn default_nicks_file() -> String {
    "nicks.json".into()
}
fn default_identify_timeout() -> u64 {
    60
}
fn default_min_password() -> usize {
    8
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r##"
[server]
name = "test.example"
"##;

    #[test]
    fn minimal_config_parses() {
        let cfg = Config::from_toml(MINIMAL).unwrap();
        assert_eq!(cfg.listen.bind, vec!["127.0.0.1:6667"]);
        assert!(!cfg.radio.enabled);
    }

    #[test]
    fn rejects_illegal_id_interval() {
        let text = r##"
[server]
name = "test.example"
[radio]
enabled = true
callsign = "SM0ABC-1"
id_interval_secs = 3600
[[channels]]
name = "#rf"
rf = true
"##;
        let err = Config::from_toml(text).unwrap_err().to_string();
        assert!(err.contains("id_interval_secs"), "{err}");
    }

    #[test]
    fn rejects_radio_without_rf_channel() {
        let text = r##"
[server]
name = "test.example"
[radio]
enabled = true
callsign = "SM0ABC-1"
[[channels]]
name = "#ip"
"##;
        assert!(Config::from_toml(text).is_err());
    }

    #[test]
    fn rejects_non_callsign_gateway_identity() {
        let text = r##"
[server]
name = "test.example"
[radio]
enabled = true
callsign = "GATEWAY"
[[channels]]
name = "#rf"
rf = true
"##;
        assert!(Config::from_toml(text).is_err());
    }
}
