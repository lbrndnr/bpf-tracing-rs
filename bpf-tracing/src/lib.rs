use crate::event::{Content, Event};
use nix::sys::statfs::{FsType, statfs};
use std::{
    fs::File,
    io::{self, BufRead, BufReader},
    path::Path,
    thread::{self, JoinHandle},
};

mod event;

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

fn emit(event: Event) {
    match event.content {
        Content::Message(msg) => match event.level {
            tracing::Level::TRACE => tracing::trace!(target: "bpf", "{}", msg),
            tracing::Level::DEBUG => tracing::debug!(target: "bpf", "{}", msg),
            tracing::Level::INFO => tracing::info!(target: "bpf", "{}", msg),
            tracing::Level::WARN => tracing::warn!(target: "bpf", "{}", msg),
            tracing::Level::ERROR => tracing::error!(target: "bpf", "{}", msg),
        },
        Content::StartSpan => {}
        Content::EndSpan => {}
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
}
