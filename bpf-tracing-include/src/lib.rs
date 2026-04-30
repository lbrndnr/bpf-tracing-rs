use std::{env, ffi::OsString, path::Path};
use tracing::level_filters::{LevelFilter, ParseLevelFilterError};

fn level_filter_from_env(
    var: Result<String, std::env::VarError>,
) -> Result<LevelFilter, ParseLevelFilterError> {
    // if the env var is missing, i.e. var is var error,
    // the we can safely return the off filter level
    match var {
        Ok(v) => v.parse(),
        Err(_) => Ok(LevelFilter::OFF),
    }
}

/// Returns the clang arguments used to compile an eBPF program with bpf-tracing.
/// The vector contains the path to the include directory along with other clang
/// definitions. The log level is determined by the `BPF_LOG` or `RUST_LOG`
/// environment variables. If `source_loc` is `true`, tracing messages will
/// include source location information.
#[inline]
pub fn clang_args_from_default_env(
    source_loc: bool,
) -> Result<Vec<OsString>, ParseLevelFilterError> {
    println!("cargo:rerun-if-env-changed=RUST_LOG");
    println!("cargo:rerun-if-env-changed=BPF_LOG");

    let level = std::env::var("BPF_LOG").or(std::env::var("RUST_LOG"));
    let level = level_filter_from_env(level)?;

    Ok(clang_args(level, source_loc))
}

/// Similar to [`clang_args_from_default_env`], but takes the name of the environment
/// variable that determines the log level.
#[inline]
pub fn clang_args_from_env(
    env_var: &str,
    source_loc: bool,
) -> Result<Vec<OsString>, ParseLevelFilterError> {
    println!("cargo:rerun-if-env-changed={env_var}");

    let level = std::env::var(env_var);
    let level = level_filter_from_env(level)?;

    Ok(clang_args(level, source_loc))
}

/// Similar to [`clang_args_from_default_env`], but takes an explicit log [`LevelFilter`].
pub fn clang_args(level: LevelFilter, source_loc: bool) -> Vec<OsString> {
    let mut args = vec![OsString::from("-I"), OsString::from(include_path_root())];
    let log_level = match level {
        LevelFilter::OFF => 0,
        LevelFilter::ERROR => 1,
        LevelFilter::WARN => 2,
        LevelFilter::INFO => 3,
        LevelFilter::DEBUG => 4,
        LevelFilter::TRACE => 5,
    };
    if log_level == 0 {
        return args;
    }

    let log_level = format!("BPF_LOG_LEVEL={log_level}");
    args.extend_from_slice(&[OsString::from("-D"), OsString::from(log_level)]);
    if source_loc {
        args.extend_from_slice(&[OsString::from("-D"), OsString::from("BPF_LOG_FILE_INFO=1")]);
    }

    args
}

/// Returns the root path of the include directory. Note that arguments returned
/// by [`clang_args_from_default_env`] and [`clang_args`] already contain this path.
#[inline]
pub fn include_path_root() -> OsString {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("include");
    println!("cargo:rerun-if-changed={:?}", path);
    OsString::from(path)
}
