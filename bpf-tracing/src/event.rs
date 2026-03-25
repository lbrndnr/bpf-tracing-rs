use std::str::FromStr;
use tracing;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub level: tracing::Level,
    pub content: Content,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Content {
    Message(String),
    StartSpan,
    EndSpan,
}

impl FromStr for Event {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        println!("{}", s);
        const MARKER: &str = "bpf_trace_printk:";

        let bytes = s.as_bytes();
        let Some(marker_pos) = s.find(MARKER) else {
            return Err("no marker found".to_string());
        };
        let after_marker = marker_pos + MARKER.len();

        let Some(rel_l) = bytes[after_marker..].iter().position(|&b| b == b'[') else {
            return Err("no '[' found after marker".to_string());
        };
        let l = after_marker + rel_l;

        let Some(rel_r) = bytes[l + 1..].iter().position(|&b| b == b']') else {
            return Err("no ']' found after '['".to_string());
        };
        let r = l + 1 + rel_r;

        // safe: '[' and ']' are ASCII boundaries
        let inner = &s[l + 1..r];
        let msg = s[r + 1..].trim().to_string();

        let level = match inner {
            "TRACE" => tracing::Level::TRACE,
            "DEBUG" => tracing::Level::DEBUG,
            "INFO" => tracing::Level::INFO,
            "WARN" => tracing::Level::WARN,
            "ERROR" => tracing::Level::ERROR,
            _ => return Err("unknown event type".to_string()),
        };
        Ok(Event {
            level,
            content: Content::Message(msg),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_log_events() {
        let event: Event = "bpf_trace_printk: [TRACE] test".parse().expect("parse");
        assert!(matches!(event.content, Content::Message(_)));

        // let event = "packets-149149  [003] ...11 78517.088267: bpf_trace_printk: EOS sockop"
        //     .parse()
        //     .expect("parse");
        // assert_eq!(event, LogEvent::Trace(String::from("sockop")));
    }
}
