use crate::event::{Event, Kind};
use nix::sys::statfs::{FsType, statfs};
use std::{
    cell::RefCell,
    collections::{HashMap, VecDeque},
    fs::File,
    io::{self, BufRead, BufReader},
    path::Path,
    thread::{self, JoinHandle},
};
use tracing::{self, Level, metadata::Metadata, span::EnteredSpan};

mod event;

const TARGET: &str = "bpf";

type Spans = Vec<VecDeque<EnteredSpan>>;

pub fn try_init() -> io::Result<JoinHandle<()>> {
    let pipe = get_trace_pipe()?;
    let new_cx = || {
        let cpus = thread::available_parallelism().unwrap().get();
        let mut spans: Spans = Vec::new();
        for _ in 0..cpus {
            spans.push(VecDeque::new());
        }
        spans
    };

    observe(&pipe, new_cx, move |val, spans| {
        if let Ok(event) = val.parse() {
            emit(event, spans);
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

fn observe<P: AsRef<Path>, C>(
    path: P,
    new_cx: impl FnOnce() -> C + Send + Sync + 'static,
    mut callback: impl FnMut(String, &mut C) + Send + Sync + 'static,
) -> io::Result<JoinHandle<()>> {
    let path = path.as_ref().to_path_buf();
    let file = File::open(&path)?;

    let handle = thread::spawn(move || {
        let mut cx = new_cx();
        let mut lines = BufReader::new(file).lines();
        while let Some(Ok(line)) = lines.next() {
            callback(line, &mut cx);
        }
    });

    Ok(handle)
}

fn emit(event: Event, spans: &mut Spans) {
    thread_local! {
        static CALLSITES: RefCell<HashMap<String, &'static Metadata<'static>>> = RefCell::new(HashMap::new());
    }

    match event.kind {
        Kind::Message(msg, level) => {
            match level {
                Level::TRACE => tracing::trace!(target: TARGET, "{}", msg),
                Level::DEBUG => tracing::debug!(target: TARGET, "{}", msg),
                Level::INFO => tracing::info!(target: TARGET, "{}", msg),
                Level::WARN => tracing::warn!(target: TARGET, "{}", msg),
                Level::ERROR => tracing::error!(target: TARGET, "{}", msg),
            };
        }
        Kind::StartSpan(name, level) => {
            let mut cs = CALLSITES.take();
            let meta = cs.entry(name.clone()).or_insert_with(|| {
                let name = name.clone();
                let leaked_name: &'static str = Box::leak(name.clone().into_boxed_str());
                let callsite = tracing::callsite!(name: "fake", kind: tracing::metadata::Kind::SPAN, fields: &[]);
                let meta = Box::leak(Box::new(Metadata::new(
                    leaked_name,
                    TARGET,
                    level,
                    Some(file!()),
                    Some(line!()),
                    Some(module_path!()),
                    tracing::field::FieldSet::new(&[], tracing::callsite::Identifier(callsite)),
                    tracing::metadata::Kind::SPAN,
                )));
                meta
            });

            let parent = spans[event.cpu].back().and_then(|p| p.id());
            let values = tracing::valueset!(meta.fields(),);

            let span = tracing::Span::child_of(parent, meta, &values);
            spans[event.cpu].push_back(span.entered());
        }
        Kind::EndSpan(_name) => _ = spans[event.cpu].pop_back(),
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

        fn no_cx() -> Option<()> {
            None
        }
        fn callback(_: String, _: &mut Option<()>) {}

        assert!(observe(path, no_cx, callback).is_err());
    }

    #[test]
    fn observe_file_changes() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("test.log");
        let mut file = File::create(&path).unwrap();
        let (tx, rx) = mpsc::channel();

        fn no_cx() -> Option<()> {
            None
        }
        let callback = move |val: String, _: &mut Option<()>| {
            tx.send(val).ok();
        };

        observe(path, no_cx, callback).expect("observe");

        file.write_all(b"hello\n").unwrap();
        file.write_all(b"world\n").unwrap();

        sleep(TEST_INTERVAL);

        assert_eq!(rx.recv().unwrap(), "hello".to_string());
        assert_eq!(rx.recv().unwrap(), "world".to_string());
    }
}
