use std::str::FromStr;
use tracing::{self, Level};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Event {
    pub kind: Kind,
    pub content: String,
    pub cpu: usize,
    pub file: Option<String>,
    pub line: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum Kind {
    Message(Level),
    StartSpan(Level),
    EndSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ParseError {
    InvalidLog,
    InvalidLevel,
    InvalidCpu,
    InvalidLine,
}

impl FromStr for Event {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        const MARKER: &str = "bpf_trace_printk:";

        fn extract(lhs: char, rhs: char, s: &str) -> Option<(usize, &str)> {
            let Some(l) = s.find(lhs) else { return None };
            let Some(r) = s[l + 1..].find(rhs) else {
                return None;
            };
            let r = l + 1 + r;
            Some((r, &s[l + 1..r]))
        }

        let Some((cpu_idx, cpu)) = extract('[', ']', s) else {
            return Err(ParseError::InvalidCpu);
        };

        let Some(msg_idx) = s[cpu_idx..].find(MARKER) else {
            return Err(ParseError::InvalidLog);
        };
        let msg_idx = cpu_idx + msg_idx;

        let Some((level_idx, level)) = extract('[', ']', &s[msg_idx..]) else {
            return Err(ParseError::InvalidLevel);
        };
        let level_idx = level_idx + msg_idx;

        let Ok(cpu) = cpu.parse() else {
            return Err(ParseError::InvalidCpu);
        };

        let content = s[level_idx + 2..].to_string();
        let (level, file, line) = if let Some((level, loc)) = level.split_once('|') {
            if let Some((file, line)) = loc.rsplit_once(':') {
                if let Some(line) = line.parse::<u32>().ok() {
                    (level, Some(file.to_string()), Some(line))
                } else {
                    return Err(ParseError::InvalidLine);
                }
            } else {
                return Err(ParseError::InvalidLine);
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

        Ok(Event {
            kind,
            content,
            cpu,
            file,
            line,
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
            "packets-149149 [{cpu:03}] ...11 78517.088267: bpf_trace_printk: [{span}{level}{file}{line}] {content}"
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
}
