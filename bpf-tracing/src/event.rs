use std::str::FromStr;
use tracing::{self, Level};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub kind: Kind,
    pub cpu: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    Message(String, Level),
    StartSpan(String, Level),
    EndSpan(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    InvalidLog,
    InvalidLevel,
    InvalidCpu,
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

        let msg = s[level_idx + 1..].trim().to_string();

        let kind = if &level[0..1] == "<" {
            let name = level[1..].trim().to_string();
            Kind::EndSpan(name)
        } else {
            if &level[0..1] == ">" {
                let Ok(level) = Level::from_str(&level[1..]) else {
                    return Err(ParseError::InvalidLevel);
                };
                Kind::StartSpan(msg, level)
            } else {
                let Ok(level) = Level::from_str(level) else {
                    return Err(ParseError::InvalidLevel);
                };
                Kind::Message(msg, level)
            }
        };

        Ok(Event { kind, cpu })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_message() {
        let log = format!(
            "packets-149149 [{:03}] ...11 78517.088267: bpf_trace_printk: [{}] {}",
            7,
            Level::DEBUG,
            "test"
        );
        let event: Event = log.parse().expect("parse");
        assert_eq!(
            event.kind,
            Kind::Message(String::from("test"), Level::DEBUG)
        );
        assert_eq!(event.cpu, 7);
    }

    #[test]
    fn parse_span_start() {
        let log = format!(
            "packets-149149 [{:03}] ...11 78517.088267: bpf_trace_printk: [>{}] {}",
            7,
            Level::ERROR,
            "test"
        );
        let event: Event = log.parse().expect("parse");
        assert_eq!(
            event.kind,
            Kind::StartSpan(String::from("test"), Level::ERROR)
        );
        assert_eq!(event.cpu, 7);
    }

    #[test]
    fn parse_span_end() {
        let log = format!(
            "packets-149149 [{:03}] ...11 78517.088267: bpf_trace_printk: [<{}]",
            12, "test_start"
        );
        let event: Event = log.parse().expect("parse");
        assert_eq!(event.kind, Kind::EndSpan(String::from("test_start")));
        assert_eq!(event.cpu, 12);
    }
}
