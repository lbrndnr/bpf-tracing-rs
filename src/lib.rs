use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
    str::FromStr,
    sync::mpsc::{self, Receiver},
    thread::{self, sleep},
    time::Duration,
};
use tracing;

const TRACE_PIPE_PATH: &str = "/sys/kernel/debug/tracing/trace_pipe";

type Result<T> = std::result::Result<T, std::io::Error>;

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

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(LogEvent::Trace(s.to_string()))
    }
}

pub fn try_init() -> Result<()> {
    Ok(())
}

fn observe<P: AsRef<Path>>(path: P, interval: Duration) -> Result<Receiver<Result<String>>> {
    let path = path.as_ref().to_path_buf();
    let (tx, rx) = mpsc::channel::<Result<String>>();
    let mut file = File::open(&path)?;

    thread::spawn(move || {
        let (ntx, nrx) = mpsc::channel();
        let config = Config::default().with_poll_interval(interval);

        let mut watcher: RecommendedWatcher = Watcher::new(ntx, config).unwrap();
        watcher.watch(&path, RecursiveMode::NonRecursive).unwrap();

        let mut offset = 0u64;
        loop {
            match nrx.recv() {
                Ok(_) => {
                    if let Err(e) = file.seek(SeekFrom::Start(offset)) {
                        tx.send(Err(e));
                        break;
                    }

                    let mut buf = Vec::new();
                    if let Err(e) = file.read_to_end(&mut buf) {
                        tx.send(Err(e)).ok();
                        break;
                    }

                    let changes = String::from_utf8_lossy(&buf).to_string();
                    for line in changes.lines() {
                        tx.send(Ok(line.to_string())).ok();
                    }
                    offset += buf.len() as u64;
                }
                Err(e) => {
                    // tx.send(std::io::Error::from(e));
                    break;
                }
            };
        }
    });

    Ok(rx)
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
    use std::io::Write;

    const TEST_INTERVAL: Duration = Duration::from_millis(100);

    #[test]
    fn observe_nonexistent_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("test.log");

        assert!(observe(path, TEST_INTERVAL).is_err());
    }

    #[test]
    fn observe_file_changes() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("test.log");
        let mut file = File::create(&path).unwrap();

        let rx = observe(path, TEST_INTERVAL).unwrap();

        sleep(2 * TEST_INTERVAL);

        file.write_all(b"hello\n").unwrap();
        file.write_all(b"world\n").unwrap();

        sleep(2 * TEST_INTERVAL);

        assert_eq!(rx.recv().unwrap().unwrap(), "hello".to_string());
        assert_eq!(rx.recv().unwrap().unwrap(), "world".to_string());
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
