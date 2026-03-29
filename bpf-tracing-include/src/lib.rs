use std::{
    env,
    path::{Path, PathBuf},
};

#[inline]
pub fn include_path_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("include")
}
