use std::{
    env,
    path::{Path, PathBuf},
};

#[inline]
pub fn create_include_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("include")
}
