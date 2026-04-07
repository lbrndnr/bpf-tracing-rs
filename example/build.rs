use libbpf_cargo::SkeletonBuilder;
use std::{env, ffi::OsString, fs, path::PathBuf};

fn main() {
    let manifest_dir =
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script");
    let manifest_dir = PathBuf::from(&manifest_dir);

    let src = PathBuf::from(&manifest_dir)
        .join("src")
        .join("monitor.bpf.c");
    println!("cargo:rerun-if-changed={src:?}");

    let out_dir = env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script");
    let out_dir = PathBuf::from(&out_dir);
    fs::create_dir_all(&out_dir).unwrap();
    let out = out_dir.clone().join("monitor.skel.rs");

    let include_dir = bpf_tracing_include::include_path_root();
    let mut args = vec![
        OsString::from("-I"),
        OsString::from("../include"),
        OsString::from("-I"),
        OsString::from(&include_dir),
    ];
    args.extend(bpf_tracing_include::clang_args_from_env(false));

    SkeletonBuilder::new()
        .source(&src)
        .clang_args(args)
        .build_and_generate(&out)
        .unwrap();
}
