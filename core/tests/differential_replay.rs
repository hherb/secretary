//! Out-of-loop differential replay: feeds the runtime fuzz corpus
//! (and any committed diff_regressions/) through both Rust decoders
//! and the Python clean-room decoder in
//! `core/tests/python/conformance.py`, asserting agreement on
//! accept/reject and (where applicable) on re-encoded bytes.
//!
//! Gated by feature `differential-replay`. Off by default to keep
//! `cargo test` Rust-only.
//!
//! See docs/superpowers/specs/2026-04-30-fuzz-harness-design.md §
//! "Out-of-loop differential replay".

#![cfg(feature = "differential-replay")]

use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

// Per-input wall-clock budget for the Python clean-room decoder. Generous
// enough to absorb `uv`'s cold-cache wheel compilation on the first call
// (cryptography in particular can take ~10–15s); tight enough that an
// adversarial infinite-loop input is caught instead of hanging the whole
// `cargo test --features differential-replay` run.
const PER_INPUT_TIMEOUT: Duration = Duration::from_secs(60);

const TARGETS: &[&str] = &[
    "vault_toml",
    "record",
    "contact_card",
    "bundle_file",
    "manifest_file",
    "manifest_body",
    "block_file",
];

fn corpus_dirs(target: &str) -> Vec<PathBuf> {
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

/// Re-encode one fuzz-corpus input through the Rust decoder for that target.
///
/// Returns [`SecretBytes`](secretary_core::crypto::secret::SecretBytes), not
/// `Vec<u8>`. The `"record"` arm's output is a canonical re-encoding of a
/// decrypted record — every field value it holds — and `record::encode`
/// returns `SecretBytes` by construction as of #558/#565 precisely so that
/// no caller can hold it unwrapped. Unwrapping here with
/// `.expose().to_vec()` to satisfy the old `Vec<u8>` signature would
/// reintroduce exactly the buffer that change eliminates, in a harness whose
/// whole job is replaying a corpus of decoded records — so the wrapper is
/// threaded through the signature instead.
///
/// Five of the other six arms wrap too — `manifest_body`, added later, is
/// the second arm that does not, for the reason its own comment below
/// gives. Their outputs are not decrypted plaintext
/// (a `ContactCard` is the artifact handed to other users; the three `*_file`
/// encoders emit on-disk forms whose bodies are already AEAD ciphertext), so
/// wrapping them buys nothing directly — but a uniform return type keeps the
/// one arm that *does* matter from being the odd one out, which is how it
/// came to be unwrapped in the first place.
fn rust_decode(
    target: &str,
    bytes: &[u8],
) -> Result<secretary_core::crypto::secret::SecretBytes, String> {
    use secretary_core::crypto::secret::SecretBytes;
    use secretary_core::*;
    match target {
        "vault_toml" => {
            let s = std::str::from_utf8(bytes).map_err(|e| format!("utf8: {}", e))?;
            unlock::vault_toml::decode(s)
                .map(|_| SecretBytes::new(Vec::new())) // crash-only target; no roundtrip compare
                .map_err(|e| format!("{:?}", e))
        }
        "record" => vault::record::decode(bytes)
            .and_then(|r| vault::record::encode(&r))
            .map_err(|e| format!("{:?}", e)),
        "contact_card" => identity::card::ContactCard::from_canonical_cbor(bytes)
            .and_then(|c| c.to_canonical_cbor())
            .map(SecretBytes::new)
            .map_err(|e| format!("{:?}", e)),
        "bundle_file" => unlock::bundle_file::decode(bytes)
            .map(|f| SecretBytes::new(unlock::bundle_file::encode(&f)))
            .map_err(|e| format!("{:?}", e)),
        "manifest_file" => vault::manifest::decode_manifest_file(bytes)
            .and_then(|f| vault::manifest::encode_manifest_file(&f))
            .map(SecretBytes::new)
            .map_err(|e| format!("{:?}", e)),
        // Unlike `manifest_file` above, `encode_manifest` already returns
        // `SecretBytes` (the manifest *body*, §4.2/§4.3, is decrypted
        // plaintext) — so this arm needs no `SecretBytes::new` wrap, the
        // same reason the "record" arm above has none.
        "manifest_body" => vault::manifest::decode_manifest(bytes)
            .and_then(|m| vault::manifest::encode_manifest(&m))
            .map_err(|e| format!("{:?}", e)),
        "block_file" => vault::block::decode_block_file(bytes)
            .and_then(|f| vault::block::encode_block_file(&f))
            .map(SecretBytes::new)
            .map_err(|e| format!("{:?}", e)),
        _ => panic!("unknown target {}", target),
    }
}

/// What the Python child reported.
///
/// The third arm is the point (#595). Before it existed, `python_decode`
/// returned `Result<Vec<u8>, String>`, so a TIMEOUT, a non-zero exit, an
/// unparseable stdout or a `uv` that could not resolve its dependencies all
/// collapsed into `Err` — and `Err` on both sides is scored as AGREEMENT by
/// the match in `differential_replay_full_corpus`. A completely
/// non-functional Python side therefore "agreed" on every input the Rust
/// decoder rejects, which is 13 of the 27 committed `manifest_body` seeds.
/// A harness failure is not a verdict and must never reach that match.
enum PyOutcome {
    /// The Python decoder accepted, and re-encoded to these bytes.
    Accept(Vec<u8>),
    /// The Python decoder deliberately rejected the input. A verdict.
    Reject(String),
    /// This harness failed. Never a verdict — always a test failure.
    Harness(String),
}

fn python_decode(target: &str, input_path: &std::path::Path) -> PyOutcome {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let conformance = manifest.join("tests/python/conformance.py");

    let mut child = Command::new("uv")
        .arg("run")
        .arg("--with")
        .arg("cryptography")
        .arg("--with")
        .arg("pynacl")
        .arg("--with")
        .arg("pqcrypto")
        .arg("--with")
        .arg("argon2-cffi")
        .arg("--with")
        .arg("blake3")
        .arg("--with")
        .arg("cbor2")
        .arg(&conformance)
        .arg("--diff-replay")
        .arg(target)
        .arg(input_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn uv run conformance.py");

    // Drain BOTH pipes on their own threads, started before the wait loop
    // below. The pipes must not be read after `wait` returns: the child is
    // `uv run`, whose cold-cache wheel builds can emit far more than a
    // pipe buffer holds (64 KiB on macOS), and a child blocked writing
    // stderr never exits — the wait loop would spin to `PER_INPUT_TIMEOUT`
    // and the timeout would then be scored as a Python verdict. An earlier
    // comment here reasoned only about stdout ("a single short JSON line,
    // so the pipe buffers cannot fill"), which is true of stdout and says
    // nothing about the stderr this same function also pipes (#595).
    let mut stdout_pipe = child.stdout.take().expect("piped stdout");
    let mut stderr_pipe = child.stderr.take().expect("piped stderr");
    let stdout_thread = std::thread::spawn(move || {
        let mut buf = String::new();
        let _ = stdout_pipe.read_to_string(&mut buf);
        buf
    });
    let stderr_thread = std::thread::spawn(move || {
        let mut buf = String::new();
        let _ = stderr_pipe.read_to_string(&mut buf);
        buf
    });

    // Bounded wait. Poll try_wait on a 50ms cadence; if the deadline
    // elapses, kill the child and report a timeout — this prevents one
    // pathological corpus input from hanging the whole test run.
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if start.elapsed() > PER_INPUT_TIMEOUT => {
                let _ = child.kill();
                let _ = child.wait();
                return PyOutcome::Harness(format!(
                    "python timeout after {}s on {}",
                    PER_INPUT_TIMEOUT.as_secs(),
                    input_path.display()
                ));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => return PyOutcome::Harness(format!("wait: {}", e)),
        }
    };

    // Both readers hit EOF when the child exits, so these join promptly.
    let stdout_buf = stdout_thread.join().unwrap_or_default();
    let stderr_buf = stderr_thread.join().unwrap_or_default();

    // Exit 3 is the script's own "I failed" code; any other non-zero exit
    // (a signal, a `uv` resolution failure, an unhandled crash) is equally
    // a harness failure. `stderr` is carried through in both cases —
    // previously it was formatted into an `Err` that the agreement arm
    // discarded, so a broken Python side left no trace at all.
    if !status.success() {
        return PyOutcome::Harness(format!(
            "python exit={:?} stderr={}",
            status.code(),
            stderr_buf.trim()
        ));
    }
    let json: serde_json::Value = match serde_json::from_str(stdout_buf.trim()) {
        Ok(v) => v,
        Err(e) => {
            return PyOutcome::Harness(format!(
                "python output not JSON: {:?} ({:?}) stderr={}",
                stdout_buf,
                e,
                stderr_buf.trim()
            ))
        }
    };
    match json["status"].as_str() {
        Some("accept") => {
            let b64 = json["reencoded_b64"].as_str().unwrap_or("");
            use base64::Engine as _;
            match base64::engine::general_purpose::STANDARD.decode(b64) {
                Ok(v) => PyOutcome::Accept(v),
                Err(e) => PyOutcome::Harness(format!("base64: {}", e)),
            }
        }
        Some("reject") => PyOutcome::Reject(format!(
            "{}: {}",
            json["error_class"].as_str().unwrap_or("unknown"),
            json["detail"].as_str().unwrap_or("")
        )),
        Some("error") => PyOutcome::Harness(format!(
            "python reported an internal error: {} {} stderr={}",
            json["error_class"].as_str().unwrap_or("unknown"),
            json["detail"].as_str().unwrap_or(""),
            stderr_buf.trim()
        )),
        // Default-deny: an unrecognised status is a harness failure, not a
        // verdict — the same posture the repo's hygiene guards take.
        other => PyOutcome::Harness(format!(
            "python output has unrecognised status {:?}: {}",
            other, stdout_buf
        )),
    }
}

#[test]
fn differential_replay_full_corpus() {
    let mut disagreements: Vec<String> = vec![];
    let mut harness_failures: Vec<String> = vec![];
    for target in TARGETS {
        // Per-target input floor (#595). `corpus_dirs` skips any directory
        // that does not exist, with no `else` — so a renamed or moved
        // `fuzz/seeds/` made every target iterate ZERO inputs and this test
        // passed having verified nothing. That is the same fail-open shape
        // `Path.rglob` produced in the payload guard (#496), and this
        // target's own module doc records it happening here. Populating the
        // directory fixed the symptom; this fixes the mechanism.
        let mut seen = 0usize;
        let dirs = corpus_dirs(target);
        for dir in &dirs {
            for entry in fs::read_dir(dir).expect("read corpus dir") {
                let path = entry.expect("dir entry").path();
                if !path.is_file() {
                    continue;
                }
                if path.file_name().and_then(|s| s.to_str()) == Some(".gitkeep") {
                    continue;
                }
                seen += 1;
                let bytes = fs::read(&path).expect("read input");

                let rust = rust_decode(target, &bytes);
                let python = python_decode(target, &path);

                // A harness failure is not a verdict, so it never reaches
                // the agreement match below: that match reads a Rust `Err`
                // beside a `PyOutcome::Reject` as "both implementations
                // rejected", and a Python crash or timeout establishes
                // nothing at all about the input.
                if let PyOutcome::Harness(msg) = &python {
                    harness_failures.push(format!("[{}] {}: {}", target, path.display(), msg));
                    continue;
                }

                let ok = match (&rust, &python) {
                    // Both reject → agreement (don't compare error classes for now;
                    // can tighten later if we standardize them).
                    (Err(_), PyOutcome::Reject(_)) => true,
                    // Both accept: for crash-only target (vault_toml) compare nothing;
                    // for the rest, compare re-encoded bytes.
                    (Ok(r_bytes), PyOutcome::Accept(p_bytes)) => {
                        if *target == "vault_toml" {
                            true
                        } else {
                            // `.expose()` reads through the wrapper for the
                            // comparison; it does not materialise a second
                            // copy the way `.to_vec()` would.
                            r_bytes.expose() == p_bytes.as_slice()
                        }
                    }
                    // Mismatch: one accepted, one rejected.
                    _ => false,
                };

                if !ok {
                    disagreements.push(format!(
                        "[{}] {}: rust={} python={}",
                        target,
                        path.display(),
                        match &rust {
                            Ok(v) => format!("Ok({} bytes)", v.len()),
                            Err(e) => format!("Err({})", e),
                        },
                        match &python {
                            PyOutcome::Accept(v) => format!("Ok({} bytes)", v.len()),
                            PyOutcome::Reject(e) => format!("Err({})", e),
                            PyOutcome::Harness(_) => unreachable!("filtered above"),
                        },
                    ));
                }
            }
        }
        assert!(
            seen > 0,
            "target {target}: no corpus inputs found — searched {dirs:?}. \
             A target that replays nothing passes vacuously; either commit \
             seeds under core/fuzz/seeds/{target}/ or remove it from TARGETS."
        );
        eprintln!("[{target}] replayed {seen} input(s)");
    }
    // Harness failures first: a broken Python side makes every verdict
    // below meaningless, so report it as the primary cause rather than
    // burying it under whatever disagreements it happened to produce.
    assert!(
        harness_failures.is_empty(),
        "differential harness failures ({}) — the Python side did not produce a verdict:\n{}",
        harness_failures.len(),
        harness_failures.join("\n")
    );
    if !disagreements.is_empty() {
        panic!(
            "differential disagreements ({}):\n{}",
            disagreements.len(),
            disagreements.join("\n")
        );
    }
}
