//! RFC 1459 / 2812 message parsing, with IRCv3 message tags tolerated on
//! input (we parse and ignore them rather than choking on a modern client).

use std::fmt;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Message {
    pub tags: Vec<(String, Option<String>)>,
    pub prefix: Option<String>,
    pub command: String,
    pub params: Vec<String>,
}

impl Message {
    pub fn new(command: &str, params: Vec<String>) -> Self {
        Self {
            command: command.to_ascii_uppercase(),
            params,
            ..Default::default()
        }
    }

    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = Some(prefix.into());
        self
    }

    pub fn param(&self, i: usize) -> Option<&str> {
        self.params.get(i).map(|s| s.as_str())
    }

    /// Parse one line (without the trailing CRLF). Returns `None` for an empty
    /// or malformed line, which the caller simply ignores per RFC 1459.
    pub fn parse(line: &str) -> Option<Self> {
        let mut rest = line.trim_end_matches(['\r', '\n']).trim_start();
        let mut msg = Message::default();

        if let Some(stripped) = rest.strip_prefix('@') {
            let (tags, remainder) = stripped.split_once(' ')?;
            for tag in tags.split(';').filter(|t| !t.is_empty()) {
                match tag.split_once('=') {
                    Some((k, v)) => msg.tags.push((k.to_string(), Some(v.to_string()))),
                    None => msg.tags.push((tag.to_string(), None)),
                }
            }
            rest = remainder.trim_start();
        }

        if let Some(stripped) = rest.strip_prefix(':') {
            let (prefix, remainder) = stripped.split_once(' ')?;
            msg.prefix = Some(prefix.to_string());
            rest = remainder.trim_start();
        }

        let mut parts = rest.splitn(2, ' ');
        let command = parts.next()?;
        if command.is_empty() {
            return None;
        }
        msg.command = command.to_ascii_uppercase();

        // Parameters are separated by spaces and nothing else. `trim_start`
        // would also eat a tab, silently deleting a parameter that consists
        // of one.
        let mut remainder = parts.next().unwrap_or("").trim_start_matches(' ');
        while !remainder.is_empty() {
            if let Some(trailing) = remainder.strip_prefix(':') {
                msg.params.push(trailing.to_string());
                break;
            }
            match remainder.split_once(' ') {
                Some((p, r)) => {
                    if !p.is_empty() {
                        msg.params.push(p.to_string());
                    }
                    remainder = r.trim_start_matches(' ');
                }
                None => {
                    msg.params.push(remainder.to_string());
                    break;
                }
            }
        }
        Some(msg)
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(prefix) = &self.prefix {
            write!(f, ":{} ", scrub_irc(prefix))?;
        }
        // The command is scrubbed like everything else. Commands we construct
        // are literals, but a parsed one is attacker-controlled: `parse` only
        // strips CR/LF from the *end* of a line, so "FOO\rBAR baz" yields a
        // command with a carriage return in it. Echoing that back unscrubbed
        // would be an injection into every client that saw it.
        write!(f, "{}", scrub_irc(&self.command))?;
        for (i, p) in self.params.iter().enumerate() {
            let last = i + 1 == self.params.len();
            if last {
                // The trailing parameter runs to the end of the line, so it
                // may contain spaces and keeps them exactly: collapsing runs
                // of spaces mangles anything aligned — a table, a code
                // snippet — for no safety benefit. Only the characters that
                // could end the line are removed.
                let p = strip_line_breaks(p);
                // Introduce it with a colon whenever leaving it bare would
                // change it: empty, starting with a colon, or carrying any
                // whitespace at all. Checking only for `' '` missed a tab,
                // which the parser then trimmed away along with the whole
                // parameter.
                if p.is_empty() || p.starts_with(':') || p.chars().any(char::is_whitespace) {
                    write!(f, " :{p}")?;
                } else {
                    write!(f, " {p}")?;
                }
            } else {
                // Middle parameters are space-delimited on the wire, so a
                // space inside one silently turns it into two and every
                // parameter after it shifts. This is reachable from
                // configuration — `server.name` becomes the topic setter, and
                // RPL_TOPICWHOTIME puts the setter in a middle position.
                //
                // An empty one, or one starting with a colon, has the same
                // problem from the other direction. See `middle_param`.
                write!(f, " {}", middle_param(p))?;
            }
        }
        Ok(())
    }
}

/// Make a string safe to use as a *middle* parameter, a prefix or a command:
/// no line breaks, and no interior whitespace that would split the field.
///
/// RF-originated reasons and topics are otherwise a protocol-injection path
/// into every IP client in the channel, and a field with an interior space
/// silently becomes two fields.
pub fn scrub_irc(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '\r' | '\n' | '\0' => ' ',
            other => other,
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        // `split_whitespace` collapsed runs to single spaces; a middle
        // parameter may not contain even one.
        .replace(' ', "_")
}

/// Make a value safe in a *middle* parameter position.
///
/// Two things are unrepresentable there and both shift every parameter that
/// follows: an interior space (the fields are space-delimited) and a leading
/// colon (that is what introduces the trailing parameter). Numerics are
/// positional, so a client reads the next field as this one.
fn middle_param(s: &str) -> String {
    let cleaned = scrub_irc(s);
    if cleaned.is_empty() {
        // Not representable at all. The conventional placeholder keeps the
        // field count right.
        return "*".into();
    }
    if cleaned.starts_with(':') {
        return format!("_{cleaned}");
    }
    cleaned
}

/// Remove only what could end the line early. Used for the trailing
/// parameter, which is allowed to contain spaces and should keep them.
pub fn strip_line_breaks(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(c, '\r' | '\n' | '\0'))
        .collect()
}

/// IRC "RFC 1459" casemapping: `{}|^` are the lowercase forms of `[]\~`.
pub fn lower(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' => c.to_ascii_lowercase(),
            '[' => '{',
            ']' => '}',
            '\\' => '|',
            '~' => '^',
            other => other,
        })
        .collect()
}

pub fn is_channel_name(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some('#') | Some('&') => {}
        _ => return false,
    }
    s.len() >= 2
        && s.len() <= 50
        && !s.contains(' ')
        && !s.contains(',')
        && !s.contains('\x07')
        && !s.contains('\r')
        && !s.contains('\n')
        && !s.contains('\0')
}

/// Nick rules, extended to allow the `|` we use for SSIDs (already legal in
/// RFC 2812's `special` set).
pub fn is_valid_nick(s: &str, max_len: usize) -> bool {
    if s.is_empty() || s.len() > max_len {
        return false;
    }
    let first_ok = s
        .chars()
        .next()
        .map(|c| c.is_ascii_alphabetic() || "[]\\`_^{|}".contains(c))
        .unwrap_or(false);
    first_ok
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "[]\\`_^{|}-".contains(c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_typical_lines() {
        let m = Message::parse("PRIVMSG #ham :hello world").unwrap();
        assert_eq!(m.command, "PRIVMSG");
        assert_eq!(m.params, vec!["#ham", "hello world"]);

        let m = Message::parse(":nick!u@h JOIN #ham\r\n").unwrap();
        assert_eq!(m.prefix.as_deref(), Some("nick!u@h"));
        assert_eq!(m.command, "JOIN");

        let m = Message::parse("@time=now;x :s TOPIC #a :b c").unwrap();
        assert_eq!(m.tags.len(), 2);
        assert_eq!(m.params, vec!["#a", "b c"]);

        assert!(Message::parse("   ").is_none());
    }

    #[test]
    fn a_middle_parameter_never_carries_a_space() {
        let m = Message::new("333", vec!["a".into(), "My Server".into(), "1".into()]);
        let line = m.to_string();
        assert_eq!(line, "333 a My_Server 1");
        assert_eq!(Message::parse(&line).unwrap().params.len(), 3);
    }

    #[test]
    fn an_empty_middle_parameter_does_not_shift_the_ones_after_it() {
        let m = Message::new(
            "333",
            vec!["alice".into(), "#rf".into(), String::new(), "1700".into()],
        );
        let back = Message::parse(&m.to_string()).unwrap();
        assert_eq!(back.params.len(), 4, "{m}");
        assert_eq!(back.params[3], "1700", "the timestamp kept its position");
    }

    #[test]
    fn whitespace_that_is_not_a_space_still_survives() {
        for text in ["\t", "a\tb", " leading", "trailing ", "\u{b}vertical"] {
            let m = Message::new("PRIVMSG", vec!["#a".into(), text.into()]);
            let back = Message::parse(&m.to_string()).unwrap();
            assert_eq!(
                back.params,
                vec!["#a", text],
                "{text:?} did not survive: {m}"
            );
        }
    }

    #[test]
    fn a_middle_parameter_cannot_start_a_trailing_parameter() {
        // A raw IPv6 address is the reachable case: it appears as the host in
        // RPL_WHOREPLY, in a middle position.
        let m = Message::new(
            "352",
            vec![
                "alice".into(),
                "#rf".into(),
                "user".into(),
                "::1".into(),
                "server".into(),
                "bob".into(),
                "H".into(),
                "0 Bob".into(),
            ],
        );
        let back = Message::parse(&m.to_string()).unwrap();
        assert_eq!(back.params.len(), 8, "{m}");
        assert_eq!(back.params[7], "0 Bob", "the realname kept its position");
        assert!(!back.params[3].starts_with(':'));
    }

    #[test]
    fn the_trailing_parameter_keeps_its_spacing_but_not_line_breaks() {
        let m = Message::new("PRIVMSG", vec!["#a".into(), "two    spaces".into()]);
        assert_eq!(m.to_string(), "PRIVMSG #a :two    spaces");
        let m = Message::new("PRIVMSG", vec!["#a".into(), "bye\r\nQUIT".into()]);
        let line = m.to_string();
        assert!(!line.contains('\r') && !line.contains('\n'), "{line}");
        // No space left in it, so the colon is not needed; it still parses
        // back as a single trailing parameter, which is what matters.
        assert_eq!(Message::parse(&line).unwrap().params, vec!["#a", "byeQUIT"]);
    }

    #[test]
    fn serialises_trailing_correctly() {
        let m = Message::new("PRIVMSG", vec!["#ham".into(), "hello world".into()])
            .with_prefix("SM0ABC|7!rf@radio");
        assert_eq!(
            m.to_string(),
            ":SM0ABC|7!rf@radio PRIVMSG #ham :hello world"
        );

        let m = Message::new("PART", vec!["#ham".into()]);
        assert_eq!(m.to_string(), "PART #ham");

        let m = Message::new("QUIT", vec!["".into()]);
        assert_eq!(m.to_string(), "QUIT :");
    }

    #[test]
    fn a_command_with_a_control_character_cannot_split_a_line() {
        // `parse` trims CR and LF only from the end of the line.
        let m = Message::parse("PRIV\rMSG #ham :hi").unwrap();
        assert!(m.command.contains('\r'), "the parser keeps it, by design");
        let line = m.to_string();
        assert!(
            !line.contains('\r') && !line.contains('\n'),
            "serialising must not carry it back out: {line:?}"
        );
    }

    #[test]
    fn casemapping_and_validation() {
        assert_eq!(lower("Nick[]\\"), "nick{}|");
        assert!(is_channel_name("#ham"));
        assert!(!is_channel_name("ham"));
        assert!(!is_channel_name("#ham\r\nPRIVMSG"));
        assert!(!is_channel_name("#ham\n"));
        assert!(is_valid_nick("SM0ABC|7", 30));
        assert!(!is_valid_nick("0ABC", 30));
    }

    #[test]
    fn serialising_strips_crlf_so_rf_cannot_inject_irc_lines() {
        let m = Message::new("QUIT", vec!["bye\r\nNOTICE alice :pwned".into()])
            .with_prefix("SM0ABC|7!rf@radio");
        let line = m.to_string();
        assert!(!line.contains('\r') && !line.contains('\n'), "{line}");
        assert!(
            !line.contains("\r\nNOTICE") && line.starts_with(":SM0ABC|7!rf@radio QUIT :"),
            "must remain a single IRC line: {line}"
        );
    }
}
