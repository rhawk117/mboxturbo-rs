//! Fixture helpers shared by the index and export benches: environment knobs, the fixture
//! directory, and generation of the synthetic mailbox with a recorded length beside it.

#![expect(
    clippy::mod_module_files,
    clippy::redundant_pub_crate,
    reason = "`mod.rs` mirrors tests/common, and redundant_pub_crate contradicts rustc's \
              unreachable_pub, which is the lint this workspace keeps"
)]

#[path = "../../tests/common/mod.rs"]
#[expect(
    clippy::missing_docs_in_private_items,
    reason = "the generator is shared with the integration tests, where the lint does not reach it"
)]
mod generator;

use std::env::{self, VarError};
use std::error::Error;
use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::time::Instant;

pub(crate) use generator::{Spec, Summary, file_name, generate};

/// Result of a bench step.
pub(crate) type Outcome<T> = Result<T, Box<dyn Error>>;

/// Reads `name` as a number, or `default` when it is unset.
pub(crate) fn env_number(name: &str, default: u64) -> Outcome<u64> {
    match env::var(name) {
        Ok(text) => Ok(text.parse()?),
        Err(VarError::NotPresent) => Ok(default),
        Err(error) => Err(error.into()),
    }
}

/// Directory holding the fixture and the temporary export.
pub(crate) fn bench_directory() -> Outcome<PathBuf> {
    match env::var_os("MBOXTURBO_BENCH_DIR") {
        Some(directory) => Ok(directory.into()),
        None => match env::var_os("CARGO_TARGET_DIR") {
            Some(directory) => Ok(directory.into()),
            None => Ok(PathBuf::from(env::var("CARGO_MANIFEST_DIR")?)
                .join("..")
                .join("..")
                .join("target")),
        },
    }
}

/// `path` with `suffix` appended to its file name, in the same directory.
fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// The byte count recorded beside the fixture at `path`, or `None` when no record exists or it is
/// not a number, which makes the fixture untrusted.
fn recorded_length(path: &Path) -> Outcome<Option<u64>> {
    match fs::read_to_string(sibling(path, ".len")) {
        Ok(text) => text
            .trim()
            .parse()
            .map_or_else(|_| Ok(None), |bytes| Ok(Some(bytes))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// The length of the fixture at `path` when it exists and matches its recorded byte count.
fn reusable_length(path: &Path) -> Outcome<Option<u64>> {
    let actual = match fs::metadata(path) {
        Ok(metadata) => metadata.len(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    Ok((recorded_length(path)? == Some(actual)).then_some(actual))
}

/// Generates the fixture to a partial file and renames it to `path`, so a killed run leaves
/// nothing at `path`, then records its byte count beside it.
fn generate_atomically(path: &Path, spec: &Spec) -> Outcome<Summary> {
    let length_path = sibling(path, ".len");
    match fs::remove_file(&length_path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error.into()),
        _ => {},
    }
    let partial = sibling(path, ".partial");
    let summary = generate(&partial, spec)?;
    fs::rename(&partial, path)?;
    fs::write(&length_path, summary.bytes.to_string())?;
    Ok(summary)
}

/// The fixture path for `spec` under `directory`, generated unless one of its recorded length
/// already exists, and says which.
pub(crate) fn ensure_fixture(directory: &Path, spec: &Spec) -> Outcome<PathBuf> {
    fs::create_dir_all(directory)?;
    let path = directory.join(file_name(spec));
    let mut out = io::stdout().lock();
    if let Some(bytes) = reusable_length(&path)? {
        writeln!(out, "reused {} ({bytes} bytes)", path.display())?;
    } else {
        let started = Instant::now();
        let summary = generate_atomically(&path, spec)?;
        writeln!(
            out,
            "generated {} ({} messages, {} dated, {} bytes) in {} ms",
            path.display(),
            summary.messages,
            summary.dated,
            summary.bytes,
            started.elapsed().as_millis()
        )?;
    }
    Ok(path)
}
