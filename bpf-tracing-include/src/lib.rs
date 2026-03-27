use std::{env, fs, io, path::PathBuf};

static HEADER: &[u8] = include_bytes!("bpf_tracing.h");

pub fn create_include_dir() -> Result<String, io::Error> {
    let include_dir = PathBuf::from(env::var("OUT_DIR").unwrap()).join("include");
    fs::create_dir_all(&include_dir)?;

    let hdr = include_dir.join("bpf_tracing.h");
    fs::write(&hdr, HEADER)?;

    let include_dir = include_dir.to_str().unwrap().to_string();

    Ok(include_dir)
}
