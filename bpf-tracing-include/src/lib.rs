use std::{env, ffi::OsString, path::Path};
use tracing::{Level, metadata::ParseLevelError};

/// Returns the clang arguments used to compile an eBPF program with bpf-tracing.
/// The vector contains the path to the include directory along with other clang
/// definitions. The log level is determined from the `BPF_LOG` or `RUST_LOG`
/// environment variables. If `source_loc` is `true`, tracing messages will
/// include source location information.
#[inline]
pub fn clang_args_from_env(source_loc: bool) -> Vec<OsString> {
    let level = std::env::var("BPF_LOG")
        .or(std::env::var("RUST_LOG"))
        .map_err(|e| e.to_string())
        .and_then(|v| v.parse().map_err(|e: ParseLevelError| e.to_string()))
        .ok();

    println!("cargo:rerun-if-env-changed=RUST_LOG");
    println!("cargo:rerun-if-env-changed=BPF_LOG");

    clang_args(level, source_loc)
}

/// Similar to [`clang_args_from_env`], but takes an explicit [`Level`].
pub fn clang_args(level: Option<Level>, source_loc: bool) -> Vec<OsString> {
    let log_level = match level {
        Some(Level::ERROR) => 1,
        Some(Level::WARN) => 2,
        Some(Level::INFO) => 3,
        Some(Level::DEBUG) => 4,
        Some(Level::TRACE) => 5,
        _ => 0,
    };
    if log_level == 0 {
        return vec![];
    }

    let log_level = format!("BPF_LOG_LEVEL={log_level}");
    let mut args = vec![
        OsString::from("-I"),
        OsString::from(include_path_root()),
        OsString::from("-D"),
        OsString::from(log_level),
    ];
    if source_loc {
        args.extend(vec![
            OsString::from("-D"),
            OsString::from("BPF_LOG_FILE_INFO=1"),
        ]);
    }

    args
}

/// Returns the root path of the include directory. Note that arguments returned
/// by [`clang_args_from_env`] and [`clang_args`] already contain this path.
#[inline]
pub fn include_path_root() -> OsString {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("include");
    println!("cargo:rerun-if-changed={:?}", path);
    OsString::from(path)
}
