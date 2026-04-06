use std::{
    env,
    path::{Path, PathBuf},
};
use tracing::{Level, metadata::ParseLevelError};

#[inline]
pub fn clang_args_from_env() -> Result<String, String> {
    let level = std::env::var("BPF_LOG").or(std::env::var("RUST_LOG"));
    let level = level
        .map_err(|e| e.to_string())
        .and_then(|v| v.parse().map_err(|e: ParseLevelError| e.to_string()))?;
    Ok(clang_args(level))
}

pub fn clang_args(level: Level) -> String {
    let log_level = if level == Level::ERROR {
        1
    } else if level == Level::WARN {
        2
    } else if level == Level::INFO {
        3
    } else if level == Level::DEBUG {
        4
    } else if level == Level::TRACE {
        5
    } else {
        0
    };
    println!("cargo:rerun-if-env-changed=RUST_LOG");
    println!("cargo:rerun-if-env-changed=BPF_LOG");

    format!("BPF_LOG_LEVEL={log_level}")
}

#[inline]
pub fn include_path_root() -> PathBuf {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("include");
    println!("cargo:rerun-if-changed={:?}", path);
    path
}
