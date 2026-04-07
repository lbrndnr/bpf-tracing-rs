use crate::event::{Event, Kind};
use nix::sys::statfs::{FsType, statfs};
use std::{
    cell::RefCell,
    collections::{HashMap, VecDeque},
    fs::File,
    io::{self, BufRead, BufReader},
    path::{Component, Path, PathBuf},
    thread::{self, JoinHandle},
};
use tracing::{self, metadata::Metadata, span::EnteredSpan};

mod event;

const TARGET: &str = "bpf";

type Spans = Vec<VecDeque<(String, EnteredSpan)>>;

thread_local! {
    static CALLSITES: RefCell<HashMap<Event, &'static Metadata<'static>>> = RefCell::new(HashMap::new());
    static SPANS: RefCell<Spans> = {
        let cpus = thread::available_parallelism().unwrap().get();
        let mut spans: Spans = Vec::new();
        for _ in 0..cpus {
            spans.push(VecDeque::new());
        }
        RefCell::new(spans)
    };
}

pub fn try_init() -> io::Result<JoinHandle<()>> {
    let pipe = get_trace_pipe()?;

    observe(&pipe, move |val| {
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

fn strip_matching_prefix_components(full: &Path, base: &Path) -> PathBuf {
    let mut full_it = full.components().peekable();
    let mut base_it = base.components().peekable();

    while let (Some(f), Some(b)) = (full_it.peek(), base_it.peek()) {
        if f == b {
            full_it.next();
            base_it.next();
        } else {
            break;
        }
    }

    let mut out = PathBuf::new();
    for c in full_it {
        match c {
            Component::Normal(s) => out.push(s),
            Component::CurDir => out.push("."),
            Component::ParentDir => out.push(".."),
            Component::RootDir => out.push(Path::new("/")),
            Component::Prefix(p) => out.push(p.as_os_str()),
        }
    }
    out
}

fn get_callsite(event: Event) -> Option<&'static Metadata<'static>> {
    let (level, kind) = match event.kind {
        Kind::Message(level) => (level, tracing::metadata::Kind::EVENT),
        Kind::StartSpan(level) => (level, tracing::metadata::Kind::SPAN),
        Kind::EndSpan => return None,
    };

    CALLSITES.with_borrow_mut(|cs| {
        if let Some(meta) = cs.get(&event) {
            Some(*meta)
        } else {
            let callsite = if kind == tracing::metadata::Kind::EVENT {
                tracing::callsite!(name: "fake", kind: tracing::metadata::Kind::EVENT, fields: &[])
            } else {
                tracing::callsite!(name: "fake", kind: tracing::metadata::Kind::SPAN, fields: &[])
            };

            let file: Option<&'static str> = if let Some(ref file) = event.file {
                let path = Path::new(&file);
                let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
                let rel = strip_matching_prefix_components(path, manifest)
                    .to_string_lossy()
                    .to_string();

                Some(Box::leak(rel.into_boxed_str()) as &'static str)
            } else {
                None
            };

            let meta = Box::leak(Box::new(Metadata::new(
                "",
                TARGET,
                level,
                file,
                event.line,
                None,
                tracing::field::FieldSet::new(
                    &["message"],
                    tracing::callsite::Identifier(callsite),
                ),
                kind,
            )));
            cs.insert(event, meta);

            let meta: &'static Metadata = meta;
            Some(meta)
        }
    })
}

fn emit(event: Event) {
    let cpu = event.cpu;
    SPANS.with_borrow_mut(|spans| match &event.kind {
        Kind::Message(_) => {
            let content = event.content.clone();
            let meta = get_callsite(event).expect("callsite");
            let parent = spans[cpu].back().and_then(|(_, p)| p.id());

            tracing::Event::child_of(
                parent,
                meta,
                &tracing::valueset_all!(meta.fields(), "{}", content),
            );
        }
        Kind::StartSpan(_) => {
            let content = event.content.clone();
            let meta = get_callsite(event).expect("callsite");
            let parent = spans[cpu].back().and_then(|(_, p)| p.id());

            let span = tracing::Span::child_of(
                parent,
                meta,
                &tracing::valueset_all!(meta.fields(), "{}", content),
            );
            spans[cpu].push_back((content, span.entered()));
        }
        Kind::EndSpan => {
            let content = event.content;
            while let Some((n, _)) = spans[cpu].pop_back() {
                if n == content {
                    break;
                }
            }
        }
    });
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
