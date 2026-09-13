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

/// One input the replay feeds both decoders.
#[derive(Debug, PartialEq)]
pub struct CorpusInput {
    pub path: PathBuf,
    pub committed: bool,
}

/// Every input under `dirs`, in a STABLE order: the directories in the order
/// given, each one's files sorted by name. `.gitkeep` and anything that is not
/// a regular file are skipped.
///
/// Listing up front (#655) is what lets a progress line say `done/total`, and
/// sorting makes a failure list the same from run to run — `read_dir` order is
/// whatever the filesystem returns.
pub fn inputs_in(dirs: &[CorpusDir]) -> std::io::Result<Vec<CorpusInput>> {
    let mut inputs = Vec::new();
    for dir in dirs {
        let mut paths = Vec::new();
        for entry in std::fs::read_dir(&dir.path)? {
            let path = entry?.path();
            if path.is_file() && path.file_name().and_then(|s| s.to_str()) != Some(".gitkeep") {
                paths.push(path);
            }
        }
        paths.sort();
        inputs.extend(paths.into_iter().map(|path| CorpusInput {
            path,
            committed: dir.committed,
        }));
    }
    Ok(inputs)
}

/// Every corpus input for `target`; see [`corpus_dirs`] and [`inputs_in`].
pub fn corpus_inputs(target: &str) -> std::io::Result<Vec<CorpusInput>> {
    inputs_in(&corpus_dirs(target))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn inputs_are_listed_per_directory_in_order_sorted_by_name_and_tagged() {
        let root = tempfile::tempdir().expect("tempdir");
        let runtime = root.path().join("runtime");
        let seeds = root.path().join("seeds");
        fs::create_dir_all(runtime.join("nested")).unwrap();
        fs::create_dir_all(&seeds).unwrap();
        for (dir, name) in [
            (&runtime, "b"),
            (&runtime, "a"),
            (&seeds, "z"),
            (&seeds, ".gitkeep"),
        ] {
            fs::write(dir.join(name), b"x").unwrap();
        }
        let dirs = [
            CorpusDir {
                path: runtime.clone(),
                committed: false,
            },
            CorpusDir {
                path: seeds.clone(),
                committed: true,
            },
        ];

        let inputs = inputs_in(&dirs).expect("listing");

        assert_eq!(
            inputs,
            vec![
                CorpusInput {
                    path: runtime.join("a"),
                    committed: false
                },
                CorpusInput {
                    path: runtime.join("b"),
                    committed: false
                },
                CorpusInput {
                    path: seeds.join("z"),
                    committed: true
                },
            ]
        );
    }
}
