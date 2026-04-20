use crate::event::{CallsiteKey, Event, Kind};
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
    static CALLSITES: RefCell<HashMap<CallsiteKey, &'static Metadata<'static>>> = RefCell::new(HashMap::new());
    static SPANS: RefCell<Spans> = {
        let cpus = thread::available_parallelism().unwrap().get();
        let mut spans: Spans = Vec::new();
        for _ in 0..cpus {
            spans.push(VecDeque::new());
        }
        RefCell::new(spans)
    };
}

/// Initializes a tracefs reader that continuously observes and
/// emits tracing events.
///
/// # Errors
/// Returns an Error if the `trace_pipe` file cannot be opened
/// or found.
pub fn try_init() -> io::Result<JoinHandle<()>> {
    let pipe = get_trace_pipe()?;
    trace_events(&pipe, emit)
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

fn trace_events<P: AsRef<Path>>(
    path: P,
    callback: impl Fn(Event) + Send + Sync + 'static,
) -> io::Result<JoinHandle<()>> {
    // let start_time = Duration::from(nix::time::clock_gettime(
    //     nix::time::ClockId::CLOCK_MONOTONIC,
    // )?);

    observe(path, move |val| {
        if let Ok(event) = val.parse::<Event>() {
            // if event.time_since_boot > start_time {
            callback(event);
            // }
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

fn get_callsite(key: CallsiteKey) -> &'static Metadata<'static> {
    CALLSITES.with_borrow_mut(|cs| {
        if let Some(meta) = cs.get(&key) {
            *meta
        } else {
            let (file, line, is_span, level) = key;

            let callsite = if is_span {
                tracing::callsite!(name: "fake", kind: tracing::metadata::Kind::EVENT, fields: &[])
            } else {
                tracing::callsite!(name: "fake", kind: tracing::metadata::Kind::SPAN, fields: &[])
            };

            let static_file: Option<&'static str> = if let Some(ref file) = file {
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
                static_file,
                line,
                None,
                tracing::field::FieldSet::new(
                    &["message"],
                    tracing::callsite::Identifier(callsite),
                ),
                if is_span {
                    tracing::metadata::Kind::SPAN
                } else {
                    tracing::metadata::Kind::EVENT
                },
            )));

            let key = (file, line, is_span, level);
            cs.insert(key, meta);

            let meta: &'static Metadata = meta;
            meta
        }
    })
}

fn emit(event: Event) {
    let cpu = event.cpu;
    SPANS.with_borrow_mut(|spans| match &event.kind {
        Kind::Message(lvl) => {
            if *lvl <= tracing::metadata::LevelFilter::current() {
                let content = event.content.clone();
                let meta = get_callsite(event.try_into().unwrap());
                let parent = spans[cpu].back().and_then(|(_, p)| p.id());

                tracing::Event::child_of(
                    parent,
                    meta,
                    &tracing::valueset_all!(meta.fields(), "{}", content),
                );
            }
        }
        Kind::StartSpan(lvl) => {
            if *lvl <= tracing::metadata::LevelFilter::current() {
                let content = event.content.clone();
                let meta = get_callsite(event.try_into().unwrap());
                let parent = spans[cpu].back().and_then(|(_, p)| p.id());

                let span = tracing::Span::child_of(
                    parent,
                    meta,
                    &tracing::valueset_all!(meta.fields(), "{}", content),
                );
                spans[cpu].push_back((content, span.entered()));
            }
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
    use tracing::Level;

    use super::*;
    use std::{io::Write, sync::mpsc, thread::sleep, time::Duration};

    const TEST_INTERVAL: Duration = Duration::from_millis(500);

    #[test]
    fn observe_nonexistent_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("test.log");

        fn callback(_: String) {}

        assert!(observe(path, callback).is_err());
    }

    #[test]
    fn observes_file_changes() {
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

    // #[test]
    // fn drains_tracefs() {
    //     let temp_dir = tempfile::tempdir().unwrap();
    //     let path = temp_dir.path().join("test.log");
    //     let mut file = File::create(&path).unwrap();

    //     let boot_time = Duration::from(
    //         nix::time::clock_gettime(nix::time::ClockId::CLOCK_BOOTTIME).expect("boot_time"),
    //     );

    //     let msg0 = format!(
    //         "example-83756   [004] ...11 {:.6}: bpf_trace_printk: [INFO] msg0\n",
    //         boot_time.as_secs_f64() - 2.0
    //     );
    //     let msg1 = format!(
    //         "example-83756   [004] ...11 {:.6}: bpf_trace_printk: [INFO] msg1\n",
    //         boot_time.as_secs_f64() - 1.0
    //     );

    //     file.write_all(msg0.as_bytes()).unwrap();
    //     file.write_all(msg1.as_bytes()).unwrap();

    //     let (tx, rx) = mpsc::channel();

    //     let callback = move |e: Event| {
    //         tx.send(e).ok();
    //     };

    //     trace_events(&path, callback).expect("trace_events");

    //     let boot_time = Duration::from(
    //         nix::time::clock_gettime(nix::time::ClockId::CLOCK_BOOTTIME).expect("boot_time"),
    //     );
    //     let msg2 = format!(
    //         "example-83756   [004] ..s31 {:.6}: bpf_trace_printk: [INFO] msg2\n",
    //         boot_time.as_secs_f64() + 0.000238
    //     );
    //     file.write_all(msg2.as_bytes()).unwrap();

    //     sleep(TEST_INTERVAL);

    //     assert_eq!(rx.recv().unwrap().content, "msg2".to_string());
    // }

    #[test]
    fn leaks_one_callsite_per_level_and_kind() {
        fn callsite_len() -> usize {
            CALLSITES.with_borrow(|cs| cs.len())
        }

        let event_msg_info1 = Event {
            kind: Kind::Message(Level::INFO),
            content: "event 1".to_string(),
            cpu: 1,
            file: None,
            line: None,
            time_since_boot: Duration::from_secs(1),
        };

        let event_msg_info2 = Event {
            kind: Kind::Message(Level::INFO),
            content: "event 2".to_string(),
            cpu: 9,
            file: None,
            line: None,
            time_since_boot: Duration::from_secs(1),
        };

        let _callsite1 = get_callsite(event_msg_info1.try_into().unwrap());
        let _callsite2 = get_callsite(event_msg_info2.try_into().unwrap());
        assert_eq!(callsite_len(), 1);

        let event_span_info3 = Event {
            kind: Kind::StartSpan(Level::INFO),
            content: "event 3".to_string(),
            cpu: 29,
            file: None,
            line: None,
            time_since_boot: Duration::from_secs(1),
        };
        let _callsite3 = get_callsite(event_span_info3.try_into().unwrap());
        assert_eq!(callsite_len(), 2);

        let event_span_info4 = Event {
            kind: Kind::StartSpan(Level::INFO),
            content: "event 4".to_string(),
            cpu: 29,
            file: Some(String::from("this/is/a/test_file.rs")),
            line: Some(12),
            time_since_boot: Duration::from_secs(1),
        };
        let _callsite4 = get_callsite(event_span_info4.try_into().unwrap());
        assert_eq!(callsite_len(), 3);

        let event_span_info5 = Event {
            kind: Kind::StartSpan(Level::INFO),
            content: "event 5".to_string(),
            cpu: 29,
            file: Some(String::from("this/is/a/test_file.rs")),
            line: Some(12),
            time_since_boot: Duration::from_secs(1),
        };
        let _callsite5 = get_callsite(event_span_info5.try_into().unwrap());
        assert_eq!(callsite_len(), 3);
    }
}
