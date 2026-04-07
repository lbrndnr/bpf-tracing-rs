use std::str::FromStr;
use tracing::{self, Level};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Event {
    pub kind: Kind,
    pub content: String,
    pub cpu: usize,
    pub file: Option<String>,
    pub line: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Kind {
    Message(Level),
    StartSpan(Level),
    EndSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
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

        let mut content = s[level_idx + 1..].trim().to_string();
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
            content = level[1..].trim().to_string();
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
        assert_eq!(event.kind, Kind::Message(Level::DEBUG));
        assert_eq!(event.content, String::from("test"));
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
        assert_eq!(event.kind, Kind::StartSpan(Level::ERROR));
        assert_eq!(event.content, String::from("test"));
        assert_eq!(event.cpu, 7);
    }

    #[test]
    fn parse_span_end() {
        let log = format!(
            "packets-149149 [{:03}] ...11 78517.088267: bpf_trace_printk: [<{}]",
            12, "test_start"
        );
        let event: Event = log.parse().expect("parse");
        assert_eq!(event.kind, Kind::EndSpan);
        assert_eq!(event.content, String::from("test_start"));
        assert_eq!(event.cpu, 12);
    }

    #[test]
    fn parse_source_loc() {
        let log = "<...>-386819  [007] ...11 763164.439561: bpf_trace_printk: [INFO|projs/bpf-tracing/example/src/monitor.bpf.c:34] sockops";
        let event: Event = log.parse().expect("parse");
        assert_eq!(event.kind, Kind::Message(Level::INFO));
        assert_eq!(
            event.file,
            Some(String::from("projs/bpf-tracing/example/src/monitor.bpf.c"))
        );
        assert_eq!(event.line, Some(34));
        assert_eq!(event.content, String::from("sockops"));
        assert_eq!(event.cpu, 7);
    }
}
