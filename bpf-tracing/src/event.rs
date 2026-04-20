use std::{fmt::Display, str::FromStr, time::Duration};
use tracing::{self, Level};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Event {
    pub kind: Kind,
    pub content: String,
    pub cpu: usize,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub time_since_boot: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum Kind {
    Message(Level),
    StartSpan(Level),
    EndSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ParseError {
    InvalidCpu,
    InvalidTime,
    InvalidLevel,
    InvalidFormat,
    UnstructuredLog,
}

impl Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::InvalidCpu => write!(f, "invalid cpu"),
            ParseError::InvalidTime => write!(f, "invalid time"),
            ParseError::InvalidLevel => write!(f, "invalid level"),
            ParseError::InvalidFormat => write!(f, "invalid format"),
            ParseError::UnstructuredLog => write!(f, "unstructured log"),
        }
    }
}

impl FromStr for Event {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        fn extract(lhs: char, rhs: char, s: &str) -> Option<(usize, &str)> {
            let Some(l) = s.find(lhs) else { return None };
            let Some(r) = s[l + 1..].find(rhs) else {
                return None;
            };
            let r = l + 1 + r;
            Some((r, &s[l + 1..r]))
        }

        let mut s = s.trim_start();

        let mut nth = |mut idx: usize| {
            while let Some((prefix, rest)) = s.split_once(char::is_whitespace) {
                s = rest;

                if idx == 0 && prefix.len() > 0 {
                    return Some(prefix);
                }

                idx = idx.saturating_sub(1);
            }

            None
        };

        let Some(cpu) = nth(1)
            .and_then(|c| c.strip_prefix('['))
            .and_then(|c| c.strip_suffix(']'))
        else {
            return Err(ParseError::InvalidFormat);
        };

        let Some(time_since_boot) = nth(1).and_then(|c| c.strip_suffix(':')) else {
            return Err(ParseError::InvalidFormat);
        };

        const MARKER: &str = "bpf_trace_printk: ";
        let Some(msg) = s.strip_prefix(MARKER) else {
            return Err(ParseError::InvalidFormat);
        };

        let Some((level_idx, level)) = extract('[', ']', &msg) else {
            return Err(ParseError::UnstructuredLog);
        };

        let (level, file, line) = if let Some((level, loc)) = level.split_once('|') {
            if let Some((file, line)) = loc.rsplit_once(':') {
                if let Some(line) = line.parse::<u32>().ok() {
                    (level, Some(file.to_string()), Some(line))
                } else {
                    return Err(ParseError::InvalidLevel);
                }
            } else {
                return Err(ParseError::InvalidLevel);
            }
        } else {
            (level, None, None)
        };

        let kind = if &level[0..1] == "<" {
            Kind::EndSpan
        } else {
            if &level[0..1] == ">" {
                let Ok(level) = Level::from_str(&level[1..]) else {
                    return Err(ParseError::InvalidLevel);
                };
                Kind::StartSpan(level)
            } else {
                let Ok(level) = Level::from_str(level) else {
                    return Err(ParseError::InvalidLevel);
                };
                Kind::Message(level)
            }
        };

        let content = msg[level_idx + 2..].to_string();
        let cpu = cpu.parse::<usize>().map_err(|_| ParseError::InvalidCpu)?;

        let time_since_boot = time_since_boot
            .parse::<f64>()
            .map_err(|_| ParseError::InvalidTime)?;
        let time_since_boot = Duration::from_secs_f64(time_since_boot);

        Ok(Event {
            kind,
            content,
            cpu,
            file,
            line,
            time_since_boot,
        })
    }
}

pub(crate) type CallsiteKey = (Option<String>, Option<u32>, bool, tracing::metadata::Level);

impl TryFrom<Event> for CallsiteKey {
    type Error = ();
    fn try_from(event: Event) -> Result<Self, Self::Error> {
        match event.kind {
            Kind::StartSpan(level) => Ok((event.file.clone(), event.line, true, level)),
            Kind::EndSpan => Err(()),
            Kind::Message(level) => Ok((event.file.clone(), event.line, false, level)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn format_event(
        cpu: usize,
        span: Option<&str>,
        level: Level,
        file: Option<&str>,
        line: Option<usize>,
        content: &str,
    ) -> String {
        let span = span.map(|s| s.to_string()).unwrap_or_default();
        let file = file.map(|f| format!("|{f}")).unwrap_or_default();
        let line = line.map(|l| format!(":{l}")).unwrap_or_default();
        format!(
            "            <...>-445247   [{cpu:03}] ...11 78517.088267: bpf_trace_printk: [{span}{level}{file}{line}] {content}"
        )
    }

    #[test]
    fn parse_message() {
        let log = format_event(7, None, Level::DEBUG, None, None, "test");
        let event: Event = log.parse().expect("parse");
        assert_eq!(event.kind, Kind::Message(Level::DEBUG));
        assert_eq!(event.content, String::from("test"));
        assert_eq!(event.cpu, 7);
    }

    #[test]
    fn parse_span_start() {
        let msg = "test with whitespace suffix   ";
        let log = format_event(7, Some(">"), Level::ERROR, None, None, msg);
        let event: Event = log.parse().expect("parse");
        assert_eq!(event.kind, Kind::StartSpan(Level::ERROR));
        assert_eq!(event.content, String::from(msg));
        assert_eq!(event.cpu, 7);
    }

    #[test]
    fn parse_span_end() {
        let log = format_event(12, Some("<"), Level::DEBUG, None, None, "test_start");
        let event: Event = log.parse().expect("parse");
        assert_eq!(event.kind, Kind::EndSpan);
        assert_eq!(event.content, String::from("test_start"));
        assert_eq!(event.cpu, 12);
    }

    #[test]
    fn parse_source_loc() {
        let file = "projs/bpf-tracing/example/src/monitor.bpf.c";
        let log = format_event(3, None, Level::INFO, Some(file), Some(34), "sockops");
        let event: Event = log.parse().expect("parse");
        assert_eq!(event.kind, Kind::Message(Level::INFO));
        assert_eq!(
            event.file,
            Some(String::from("projs/bpf-tracing/example/src/monitor.bpf.c"))
        );
        assert_eq!(event.line, Some(34));
        assert_eq!(event.content, String::from("sockops"));
        assert_eq!(event.cpu, 3);
    }

    #[test]
    fn try_parse_plain_log() {
        let log = "asdfqwer-926693 [007] ...11 681876.746781: bpf_trace_printk: Established socket [127.0.0.1:51914->127.0.0.1:12345]";
        assert!(log.parse::<Event>().is_err());
    }
}
