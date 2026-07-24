//! Shared test helpers: repo-relative path resolution and the corpus fallback.
//!
//! Every path a test touches is resolved from `CARGO_MANIFEST_DIR`, never
//! hardcoded. A hardcoded absolute path silently defeats git-worktree isolation
//! (concurrent agents in separate worktrees all write to the SAME directory, so
//! each run's "evidence" is a mix of everybody's binaries) and is simply wrong on
//! any machine but the one it was written on — this tree carried
//! `C:\Users\User\Downloads\sd` in five test files, none of which could run here.
//!
//! `CARGO_MANIFEST_DIR` is the crate under test (`crates/shell`), so `../..` is
//! that checkout's root — correct in a worktree too.

#![allow(dead_code)] // each test binary uses only the helpers it needs

use std::path::{Path, PathBuf};

/// Repository root of the checkout currently being tested.
pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
}

/// `<repo>/_qa`, the QA tree root.
pub fn qa_dir() -> PathBuf {
    repo_root().join("_qa")
}

/// A path under `<repo>/_qa`, e.g. `qa_path("decomp")`.
pub fn qa_path(rel: &str) -> PathBuf {
    qa_dir().join(rel)
}

/// `<repo>/_qa/fixtures/corpus`, where the compiled corpus DLLs land.
pub fn corpus_dir() -> PathBuf {
    qa_dir().join("fixtures").join("corpus")
}

/// A QA OUTPUT directory (created if absent). Output dirs are gitignored; the
/// fixtures they are derived from are not.
pub fn qa_out_dir(rel: &str) -> PathBuf {
    let p = qa_path(rel);
    let _ = std::fs::create_dir_all(&p);
    p
}

/// The binary a "real binary" test should run against.
///
/// `DS_REAL_BIN` wins. Otherwise fall back to a corpus DLL, which is built from
/// in-tree source by `_qa/fixtures/corpus/compile_all.bat` — so the default is
/// something this repo can actually produce, rather than a personal path to a
/// binary that exists on exactly one machine. Returns `None` when nothing is
/// available, letting the caller skip with a clear message instead of failing.
pub fn real_bin() -> Option<String> {
    if let Ok(b) = std::env::var("DS_REAL_BIN") {
        if !b.trim().is_empty() {
            return Some(b);
        }
    }
    for cand in ["board.dll", "torture.dll", "math_ops.dll"] {
        let p = corpus_dir().join(cand);
        if p.exists() {
            return Some(p.to_string_lossy().into_owned());
        }
    }
    None
}

/// Message to print when [`real_bin`] yields nothing, so a skip explains itself.
pub const NO_REAL_BIN: &str =
    "[skip] no test binary: set DS_REAL_BIN=<path>, or build the corpus with \
     _qa/fixtures/corpus/compile_all.bat";

/// Stack size the app gives its decompile workers (see `session.rs`).
///
/// The structurer recurses over the region tree. Its depth ceiling is
/// deterministic, but the stack-exhaustion safety net underneath it is not: on a
/// smaller stack the engine cuts a region earlier and emits a `goto` where the
/// shipped product would have kept the structure. libtest threads get 2 MiB,
/// which is roughly a seventh of what the real workers have — so a test left on
/// the default stack measures a configuration no user ever runs, and can report
/// a difference that does not exist in the product.
pub const WORKER_STACK: usize = 64 * 1024 * 1024;

/// Run `f` on a thread with the production worker stack, and return its result.
pub fn on_worker_stack<T, F>(f: F) -> T
where
    F: FnOnce() -> T + Send,
    T: Send,
{
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .stack_size(WORKER_STACK)
            .spawn_scoped(scope, f)
            .expect("spawn worker-stack thread")
            .join()
            .expect("worker-stack thread panicked")
    })
}
