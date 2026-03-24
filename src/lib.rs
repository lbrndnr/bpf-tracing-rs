use nix::sys::statfs::{FsType, statfs};
use std::{
    fs::File,
    io::{self, BufRead, BufReader},
    path::Path,
    str::FromStr,
    thread::{self, JoinHandle},
};
use tracing;

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

        match inner {
            "TRACE" => Ok(LogEvent::Trace(msg)),
            "DEBUG" => Ok(LogEvent::Debug(msg)),
            "INFO" => Ok(LogEvent::Info(msg)),
            "WARN" => Ok(LogEvent::Warn(msg)),
            "ERROR" => Ok(LogEvent::Error(msg)),
            _ => Err("unknown event type".to_string()),
        }
    }
}

pub fn try_init() -> io::Result<JoinHandle<()>> {
    let pipe = get_trace_pipe()?;
    observe(&pipe, |val| {
        if let Ok(event) = val.parse() {
            emit(event);
        }
    })
}

fn get_trace_pipe() -> io::Result<impl AsRef<Path>> {
    fn validate(path: &Path) -> bool {
        const TRACEFS_MAGIC: FsType = FsType(0x74726163);
        if let Ok(stat) = statfs(path) {
            return stat.filesystem_type() == TRACEFS_MAGIC;
        }

        false
    }
    let known_mounts = [
        Path::new("/sys/kernel/tracing"),
        Path::new("/sys/kernel/debug/tracing"),
    ];
    if let Some(path) = known_mounts.into_iter().find(|p| validate(p)) {
        let path = path.to_path_buf();
        return Ok(path.join("trace_pipe"));
    }

    let file = File::open("/proc/mounts")?;
    let mut lines = BufReader::new(file).lines();
    while let Some(Ok(line)) = lines.next() {
        if line.starts_with("tracefs") {
            let mount = line.split_whitespace().nth(1).map(Path::new);
            if let Some(mount) = mount {
                if validate(mount) {
                    return Ok(mount.join("trace_pipe"));
                }
            }
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "trace_pipe not found",
    ))
}

fn observe<P: AsRef<Path>>(
    path: P,
    callback: impl Fn(String) + Send + Sync + 'static,
) -> io::Result<JoinHandle<()>> {
    let path = path.as_ref().to_path_buf();
    let file = File::open(&path)?;

    let handle = thread::spawn(move || {
        let mut lines = BufReader::new(file).lines();
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

        sleep(TEST_INTERVAL);

        assert_eq!(rx.recv().unwrap(), "hello".to_string());
        assert_eq!(rx.recv().unwrap(), "world".to_string());
    }

    #[test]
    fn parse_log_events() {
        assert_eq!(
            LogEvent::Trace(String::from("test")),
            "bpf_trace_printk: [TRACE] test".parse().expect("parse")
        );
    }
}
