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

fn rust_decode(target: &str, bytes: &[u8]) -> Result<Vec<u8>, String> {
    use secretary_core::*;
    match target {
        "vault_toml" => {
            let s = std::str::from_utf8(bytes).map_err(|e| format!("utf8: {}", e))?;
            unlock::vault_toml::decode(s)
                .map(|_| Vec::new()) // crash-only target; no roundtrip compare
                .map_err(|e| format!("{:?}", e))
        }
        "record" => vault::record::decode(bytes)
            .and_then(|r| vault::record::encode(&r))
            .map_err(|e| format!("{:?}", e)),
        "contact_card" => identity::card::ContactCard::from_canonical_cbor(bytes)
            .and_then(|c| c.to_canonical_cbor())
            .map_err(|e| format!("{:?}", e)),
        "bundle_file" => unlock::bundle_file::decode(bytes)
            .map(|f| unlock::bundle_file::encode(&f))
            .map_err(|e| format!("{:?}", e)),
        "manifest_file" => vault::manifest::decode_manifest_file(bytes)
            .and_then(|f| vault::manifest::encode_manifest_file(&f))
            .map_err(|e| format!("{:?}", e)),
        "block_file" => vault::block::decode_block_file(bytes)
            .and_then(|f| vault::block::encode_block_file(&f))
            .map_err(|e| format!("{:?}", e)),
        _ => panic!("unknown target {}", target),
    }
}

fn python_decode(target: &str, input_path: &std::path::Path) -> Result<Vec<u8>, String> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let conformance = manifest.join("tests/python/conformance.py");

    let mut child = Command::new("uv")
        .arg("run")
        .arg("--with").arg("cryptography")
        .arg("--with").arg("pynacl")
        .arg("--with").arg("pqcrypto")
        .arg("--with").arg("argon2-cffi")
        .arg("--with").arg("blake3")
        .arg("--with").arg("cbor2")
        .arg(&conformance)
        .arg("--diff-replay")
        .arg(target)
        .arg(input_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn uv run conformance.py");

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
                return Err(format!(
                    "python timeout after {}s on {}",
                    PER_INPUT_TIMEOUT.as_secs(),
                    input_path.display()
                ));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => return Err(format!("wait: {}", e)),
        }
    };

    // Conformance.py emits a single short JSON line, so the pipe buffers
    // cannot fill before the child exits — reading after wait is safe here.
    let mut stdout_buf = String::new();
    let mut stderr_buf = String::new();
    child
        .stdout
        .take()
        .expect("piped stdout")
        .read_to_string(&mut stdout_buf)
        .map_err(|e| format!("read stdout: {}", e))?;
    child
        .stderr
        .take()
        .expect("piped stderr")
        .read_to_string(&mut stderr_buf)
        .map_err(|e| format!("read stderr: {}", e))?;

    if !status.success() {
        return Err(format!(
            "python exit={:?} stderr={}",
            status.code(),
            stderr_buf
        ));
    }
    let json: serde_json::Value = serde_json::from_str(stdout_buf.trim())
        .unwrap_or_else(|e| panic!("python output not JSON: {} ({:?})", stdout_buf, e));
    match json["status"].as_str() {
        Some("accept") => {
            let b64 = json["reencoded_b64"].as_str().unwrap_or("");
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD
                .decode(b64)
                .map_err(|e| format!("base64: {}", e))
        }
        Some("reject") => Err(json["error_class"].as_str().unwrap_or("unknown").to_string()),
        _ => panic!("python output missing status: {}", stdout_buf),
    }
}

#[test]
fn differential_replay_full_corpus() {
    let mut disagreements: Vec<String> = vec![];
    for target in TARGETS {
        for dir in corpus_dirs(target) {
            for entry in fs::read_dir(&dir).expect("read corpus dir") {
                let path = entry.expect("dir entry").path();
                if !path.is_file() {
                    continue;
                }
                if path.file_name().and_then(|s| s.to_str()) == Some(".gitkeep") {
                    continue;
                }
                let bytes = fs::read(&path).expect("read input");

                let rust = rust_decode(target, &bytes);
                let python = python_decode(target, &path);

                let ok = match (&rust, &python) {
                    // Both reject → agreement (don't compare error classes for now;
                    // can tighten later if we standardize them).
                    (Err(_), Err(_)) => true,
                    // Both accept: for crash-only target (vault_toml) compare nothing;
                    // for the rest, compare re-encoded bytes.
                    (Ok(r_bytes), Ok(p_bytes)) => {
                        if *target == "vault_toml" {
                            true
                        } else {
                            r_bytes == p_bytes
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
                            Ok(v) => format!("Ok({} bytes)", v.len()),
                            Err(e) => format!("Err({})", e),
                        },
                    ));
                }
            }
        }
    }
    if !disagreements.is_empty() {
        panic!(
            "differential disagreements ({}):\n{}",
            disagreements.len(),
            disagreements.join("\n")
        );
    }
}
