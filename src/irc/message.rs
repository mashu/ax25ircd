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

        let mut remainder = parts.next().unwrap_or("").trim_start();
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
                    remainder = r.trim_start();
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
            write!(f, ":{prefix} ")?;
        }
        write!(f, "{}", self.command)?;
        for (i, p) in self.params.iter().enumerate() {
            let last = i + 1 == self.params.len();
            if last && (p.is_empty() || p.contains(' ') || p.starts_with(':')) {
                write!(f, " :{p}")?;
            } else {
                write!(f, " {p}")?;
            }
        }
        Ok(())
    }
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
    fn serialises_trailing_correctly() {
        let m = Message::new("PRIVMSG", vec!["#ham".into(), "hello world".into()])
            .with_prefix("SM0ABC|7!rf@radio");
        assert_eq!(m.to_string(), ":SM0ABC|7!rf@radio PRIVMSG #ham :hello world");

        let m = Message::new("PART", vec!["#ham".into()]);
        assert_eq!(m.to_string(), "PART #ham");

        let m = Message::new("QUIT", vec!["".into()]);
        assert_eq!(m.to_string(), "QUIT :");
    }

    #[test]
    fn casemapping_and_validation() {
        assert_eq!(lower("Nick[]\\"), "nick{}|");
        assert!(is_channel_name("#ham"));
        assert!(!is_channel_name("ham"));
        assert!(is_valid_nick("SM0ABC|7", 30));
        assert!(!is_valid_nick("0ABC", 30));
    }
}
