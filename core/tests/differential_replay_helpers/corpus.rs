//! Locates the fuzz-corpus input files `differential_replay_full_corpus`
//! replays for one target.

use std::path::PathBuf;

/// One corpus directory, and whether git tracks what is in it.
///
/// The split exists for `MIN_CORPUS_INPUTS`, not for the replay: every
/// directory here is replayed, but only the COMMITTED ones may be counted
/// toward the floor. Counting the runtime corpus made the floor fail open on
/// exactly the machine it was meant to protect — with `fuzz/corpus/` holding
/// tens of thousands of gitignored files, deleting a committed seed still
/// cleared the floor by a wide margin, so the guarantee "deleting an input
/// reds" held only where `corpus/` was absent, i.e. CI and a fresh worktree
/// (#656 review).
pub struct CorpusDir {
    pub path: PathBuf,
    pub committed: bool,
}

pub fn corpus_dirs(target: &str) -> Vec<CorpusDir> {
    // CARGO_MANIFEST_DIR resolves to `core/` at compile time, so all paths
    // below are anchored on the secretary-core package root regardless of
    // the working directory the test was invoked from.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut dirs = vec![];
    // Runtime corpus (gitignored, may not exist locally). NOT committed, so
    // it is replayed but never counted toward the floor. This is also the
    // directory behind #655: it grows without bound, and a checkout that has
    // fuzzed replays all of it, which presents as a hang.
    let runtime = manifest.join("fuzz/corpus").join(target);
    if runtime.is_dir() {
        dirs.push(CorpusDir {
            path: runtime,
            committed: false,
        });
    }
    // Committed seeds (always present).
    let seeds = manifest.join("fuzz/seeds").join(target);
    if seeds.is_dir() {
        dirs.push(CorpusDir {
            path: seeds,
            committed: true,
        });
    }
    // Committed diff regressions.
    let diffs = manifest.join("tests/data/diff_regressions").join(target);
    if diffs.is_dir() {
        dirs.push(CorpusDir {
            path: diffs,
            committed: true,
        });
    }
    dirs
}
