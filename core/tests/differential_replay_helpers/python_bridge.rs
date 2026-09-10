//! Shells out to `conformance.py --diff-replay` for one corpus input and
//! parses its verdict.

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

/// What the Python child reported.
///
/// The third arm is the point (#595). Before it existed, `python_decode`
/// returned `Result<Vec<u8>, String>`, so a TIMEOUT, a non-zero exit, an
/// unparseable stdout or a `uv` that could not resolve its dependencies all
/// collapsed into `Err` — and `Err` on both sides is scored as AGREEMENT by
/// the match in `differential_replay_full_corpus`. A completely
/// non-functional Python side therefore "agreed" on every input the Rust
/// decoder rejects, which is 24 of the 38 committed `manifest_body` seeds
/// (20 canonicality rejects + 4 uniqueness rejects; the count moves every
/// time either corpus grows, so re-measure rather than quoting it).
/// A harness failure is not a verdict and must never reach that match.
pub enum PyOutcome {
    /// The Python decoder accepted, and re-encoded to these bytes.
    Accept(Vec<u8>),
    /// The Python decoder deliberately rejected the input. A verdict.
    ///
    /// `rule` is the token the reject shape now carries (#634); `None` when
    /// that rejection carries none.
    Reject {
        rule: Option<String>,
        detail: String,
    },
    /// This harness failed. Never a verdict — always a test failure.
    Harness(String),
}

pub fn python_decode(target: &str, input_path: &std::path::Path) -> PyOutcome {
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
        Some("reject") => PyOutcome::Reject {
            rule: json["rule"].as_str().map(str::to_owned),
            detail: format!(
                "{}: {}",
                json["error_class"].as_str().unwrap_or("unknown"),
                json["detail"].as_str().unwrap_or("")
            ),
        },
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
