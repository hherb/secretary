//! Locates the fuzz-corpus input files `differential_replay_full_corpus`
//! replays for one target.

use std::path::PathBuf;

pub fn corpus_dirs(target: &str) -> Vec<PathBuf> {
    // CARGO_MANIFEST_DIR resolves to `core/` at compile time, so all paths
    // below are anchored on the secretary-core package root regardless of
    // the working directory the test was invoked from.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut dirs = vec![];
    // Runtime corpus (gitignored, may not exist locally).
    let runtime = manifest.join("fuzz/corpus").join(target);
    if runtime.is_dir() {
        dirs.push(runtime);
    }
    // Committed seeds (always present).
    let seeds = manifest.join("fuzz/seeds").join(target);
    if seeds.is_dir() {
        dirs.push(seeds);
    }
    // Committed diff regressions.
    let diffs = manifest.join("tests/data/diff_regressions").join(target);
    if diffs.is_dir() {
        dirs.push(diffs);
    }
    dirs
}
