use std::{
    fs::File,
    io::{self, BufRead},
    path::Path,
    str::FromStr,
    thread::{self, JoinHandle},
};
use tracing;

const TRACE_PIPE_PATH: &str = "/sys/kernel/debug/tracing/trace_pipe";

#[derive(Debug, Clone, PartialEq, Eq)]
enum LogEvent {
    Trace(String),
    Debug(String),
    Info(String),
    Warn(String),
    Error(String),
}

impl FromStr for LogEvent {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(LogEvent::Trace(s.to_string()))
    }
}

pub fn try_init() -> io::Result<JoinHandle<()>> {
    observe(TRACE_PIPE_PATH, |val| {
        if let Ok(event) = val.parse() {
            emit(event);
        }
    })
}

fn observe<P: AsRef<Path>>(
    path: P,
    callback: impl Fn(String) + Send + Sync + 'static,
) -> io::Result<JoinHandle<()>> {
    let path = path.as_ref().to_path_buf();
    let file = File::open(&path)?;

    let handle = thread::spawn(move || {
        let mut lines = io::BufReader::new(file).lines();
        while let Some(Ok(line)) = lines.next() {
            callback(line);
        }
    });

    Ok(handle)
}

fn emit(event: LogEvent) {
    match event {
        LogEvent::Trace(msg) => tracing::trace!(target: "bpf", "{}", msg),
        LogEvent::Debug(msg) => tracing::debug!(target: "bpf", "{}", msg),
        LogEvent::Info(msg) => tracing::info!(target: "bpf", "{}", msg),
        LogEvent::Warn(msg) => tracing::warn!(target: "bpf", "{}", msg),
        LogEvent::Error(msg) => tracing::error!(target: "bpf", "{}", msg),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Write, sync::mpsc, thread::sleep, time::Duration};

    const TEST_INTERVAL: Duration = Duration::from_millis(100);

    #[test]
    fn observe_nonexistent_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("test.log");

        fn callback(_: String) {}

        assert!(observe(path, callback).is_err());
    }

    #[test]
    fn observe_file_changes() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("test.log");
        let mut file = File::create(&path).unwrap();
        let (tx, rx) = mpsc::channel();

        let callback = move |val: String| {
            tx.send(val).ok();
        };

        observe(path, callback).expect("observe");

        file.write_all(b"hello\n").unwrap();
        file.write_all(b"world\n").unwrap();

        sleep(2 * TEST_INTERVAL);

        assert_eq!(rx.recv().unwrap(), "hello".to_string());
        assert_eq!(rx.recv().unwrap(), "world".to_string());
    }

    #[test]
    fn parse_log_events() {
        assert_eq!(
            LogEvent::Trace(String::from("test")),
            "[TRACE] test".parse().expect("parse")
        );
        assert_eq!(
            LogEvent::Debug(String::from("test")),
            "[debug]test".parse().expect("parse")
        );
        assert_eq!(
            LogEvent::Info(String::from("test")),
            "[InFo]     test".parse().expect("parse")
        );
    }
}
