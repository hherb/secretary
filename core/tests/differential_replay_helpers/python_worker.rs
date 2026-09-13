//! One long-lived `conformance.py --diff-replay-serve` process, asked about
//! corpus inputs one at a time (#655).
//!
//! The replay used to spawn `uv run conformance.py --diff-replay` PER input.
//! Decoding costs 0.2-0.4 ms; the spawn ~0.16 s. On a checkout that has
//! fuzzed, `core/fuzz/corpus/` held 74,924 inputs, so the replay took ~3.3 h
//! while printing nothing. One worker answers the same corpus in about a
//! minute. Everything the per-input spawn guaranteed is kept per input:
//!
//! - **A bounded wait.** Each answer must arrive within the timeout, or the
//!   worker's whole process group is killed and the input is a harness
//!   failure. `uv run` SPAWNS the interpreter rather than exec'ing it, so
//!   killing `uv` alone would orphan a Python spinning on a pathological
//!   input.
//! - **An answer tied to its question.** Every response echoes the path it
//!   answers, and a mismatch is a harness failure: a desynchronised stream
//!   would otherwise score every later input against the wrong verdict.
//! - **A fresh process after trouble.** Any transport failure (timeout, a
//!   dead worker, a non-JSON line, a mismatched echo) discards the worker; the
//!   next input starts another. An `error` VERDICT does not — the worker is
//!   healthy, and respawning on every error would bring the per-input cost
//!   straight back on a corpus where Python errors on everything.
//! - **No silent spin on a worker that cannot come up.** After
//!   `MAX_CONSECUTIVE_WORKER_FAILURES` inputs in a row get no verdict, the
//!   replayer stops starting workers and fails the rest immediately. By then
//!   the run is already failing, and each further input would pay a start-up —
//!   or a full timeout, for a `uv` stuck resolving — across tens of thousands
//!   of inputs. Any verdict resets the count.
//!
//!   An earlier draft counted only workers that failed before their FIRST
//!   reply, claiming that kept a healthy worker's run of slow inputs from
//!   abandoning the corpus. The mutation harness disproved it (its row read
//!   `UNEXPECTED_GREEN`): a respawned worker is always fresh, so a second slow
//!   input already counts as a "startup" failure, and the distinction moved
//!   the cap by one input. A rule that cannot be told apart from the simpler
//!   one is not kept.
//!
//! What a reused interpreter gives up is per-input PROCESS isolation. Section
//! DRS in `conformance.py` checks serve and single-shot verdicts agree input by
//! input on the committed corpus; see its LIMIT for what that does not cover.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;

use super::python_bridge::{parse_verdict, PyOutcome};

/// Per-input wall-clock budget. Generous enough to absorb `uv`'s cold-cache
/// wheel compilation on the FIRST request, which pays the worker's start-up
/// (cryptography in particular can take ~10–15 s); tight enough that an
/// adversarial infinite-loop input is caught instead of hanging the run.
pub const PER_INPUT_TIMEOUT: Duration = Duration::from_secs(60);

/// Inputs in a row that may get no verdict, after which no further worker is
/// started.
pub const MAX_CONSECUTIVE_WORKER_FAILURES: usize = 3;

/// How long a worker whose output has closed is given to finish exiting, so
/// its real exit code is reported rather than the SIGKILL that would follow.
const EXIT_GRACE: Duration = Duration::from_secs(1);

/// How long a retired worker's stderr reader is given to drain what the
/// worker wrote before it ended.
const STDERR_DRAIN_GRACE: Duration = Duration::from_secs(1);

/// How much of a worker's stderr is kept for failure messages. Bounded,
/// because a decoder that writes a line per input would otherwise accumulate
/// megabytes across a large corpus for a message that needs the tail.
const STDERR_TAIL_BYTES: usize = 64 * 1024;

/// Asks corpus inputs of a serve-mode worker, starting one as needed.
///
/// A struct because it holds genuine state: the live process, and how many
/// inputs in a row have got no verdict.
pub struct PyReplayer<F: FnMut() -> Command> {
    make_command: F,
    timeout: Duration,
    worker: Option<Worker>,
    consecutive_failures: usize,
    spawned: usize,
}

impl<F: FnMut() -> Command> PyReplayer<F> {
    /// `make_command` builds the worker command afresh for every start —
    /// in the replay, [`super::python_bridge::serve_command`].
    pub fn new(make_command: F, timeout: Duration) -> Self {
        PyReplayer {
            make_command,
            timeout,
            worker: None,
            consecutive_failures: 0,
            spawned: 0,
        }
    }

    /// How many worker processes this replayer has started.
    pub fn spawned(&self) -> usize {
        self.spawned
    }

    /// The Python verdict for one input.
    ///
    /// Every failure to obtain a verdict is a [`PyOutcome::Harness`] naming
    /// the input; none is ever a `Reject`, which the caller would score as
    /// agreement with a Rust rejection (#595).
    pub fn decode(&mut self, target: &str, path: &Path) -> PyOutcome {
        if self.consecutive_failures >= MAX_CONSECUTIVE_WORKER_FAILURES {
            return PyOutcome::Harness(format!(
                "not replayed: {}: the last {} inputs got no verdict from a Python \
                 worker, so no further worker is started — the first failures \
                 above say why",
                path.display(),
                self.consecutive_failures
            ));
        }
        let Some(path_text) = path.to_str() else {
            return PyOutcome::Harness(format!(
                "{} is not valid UTF-8 and cannot be named in a JSON request",
                path.display()
            ));
        };
        let request = serde_json::json!({ "target": target, "path": path_text }).to_string();

        let mut worker = match self.worker.take() {
            Some(worker) => worker,
            None => match Worker::spawn((self.make_command)()) {
                Ok(worker) => {
                    self.spawned += 1;
                    worker
                }
                Err(why) => {
                    self.consecutive_failures += 1;
                    return PyOutcome::Harness(format!("{why} (for {path_text})"));
                }
            },
        };

        match worker
            .ask(&request, self.timeout)
            .and_then(|line| response_for(&line, path_text))
        {
            Ok(response) => {
                self.consecutive_failures = 0;
                self.worker = Some(worker);
                let context = response["traceback"].as_str().unwrap_or("");
                parse_verdict(&response, context)
            }
            Err(why) => {
                self.consecutive_failures += 1;
                let ended = worker.retire();
                PyOutcome::Harness(format!("{why} on {path_text}; worker {ended}"))
            }
        }
    }
}

impl<F: FnMut() -> Command> Drop for PyReplayer<F> {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            worker.retire();
        }
    }
}

/// The response to a request about `path`, or why the line is not one. Pure.
///
/// The echoed `path` must match: line ORDER alone is what a desynchronised
/// stream silently breaks, and every later input would then be scored against
/// its neighbour's verdict.
fn response_for(line: &str, path: &str) -> Result<Value, String> {
    let response: Value = serde_json::from_str(line)
        .map_err(|e| format!("the worker wrote a line that is not JSON ({e}): {line:?}"))?;
    match response.get("path").and_then(Value::as_str) {
        Some(echoed) if echoed == path => Ok(response),
        echoed => Err(format!(
            "the worker answered for {echoed:?} while asked about {path:?}"
        )),
    }
}

/// Append `bytes` to `tail`, keeping only the last `cap` bytes. Pure.
fn push_tail(tail: &mut Vec<u8>, bytes: &[u8], cap: usize) {
    tail.extend_from_slice(bytes);
    if tail.len() > cap {
        let excess = tail.len() - cap;
        tail.drain(..excess);
    }
}

/// One running `--diff-replay-serve` process.
struct Worker {
    child: Child,
    /// `None` once `retire` has closed it.
    stdin: Option<ChildStdin>,
    /// stdout, one line per message, read on its own thread so a wait can
    /// be bounded.
    lines: Receiver<std::io::Result<String>>,
    /// The last `STDERR_TAIL_BYTES` of stderr, drained on its own thread so a
    /// chatty worker can never block on a full pipe.
    stderr_tail: Arc<Mutex<Vec<u8>>>,
    stderr_done: Receiver<()>,
}

impl Worker {
    fn spawn(mut command: Command) -> Result<Worker, String> {
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // Its own process group, so a timeout can kill `uv` AND the
        // interpreter it forked. See `kill_process_group`.
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let mut child = command
            .spawn()
            .map_err(|e| format!("could not start a Python worker: {e}"))?;
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        let mut stderr = child.stderr.take().expect("piped stderr");

        let (line_tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let failed = line.is_err();
                if line_tx.send(line).is_err() || failed {
                    break;
                }
            }
        });

        let stderr_tail = Arc::new(Mutex::new(Vec::new()));
        let (done_tx, stderr_done) = mpsc::channel();
        let tail = Arc::clone(&stderr_tail);
        std::thread::spawn(move || {
            let mut chunk = [0u8; 4096];
            while let Ok(n @ 1..) = stderr.read(&mut chunk) {
                let mut guard = tail.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                push_tail(&mut guard, &chunk[..n], STDERR_TAIL_BYTES);
            }
            let _ = done_tx.send(());
        });

        Ok(Worker {
            child,
            stdin: Some(stdin),
            lines,
            stderr_tail,
            stderr_done,
        })
    }

    /// Send one request line; wait at most `timeout` for one response line.
    fn ask(&mut self, request: &str, timeout: Duration) -> Result<String, String> {
        let stdin = self.stdin.as_mut().expect("a live worker has its stdin");
        writeln!(stdin, "{request}")
            .and_then(|()| stdin.flush())
            .map_err(|e| format!("could not write to the worker: {e}"))?;
        match self.lines.recv_timeout(timeout) {
            Ok(Ok(line)) => Ok(line),
            Ok(Err(e)) => Err(format!("could not read from the worker: {e}")),
            Err(RecvTimeoutError::Timeout) => Err(format!(
                "python timeout after {:.1}s",
                timeout.as_secs_f64()
            )),
            Err(RecvTimeoutError::Disconnected) => Err("the worker closed its output".into()),
        }
    }

    /// End the worker and describe how it ended.
    ///
    /// Its stdin is closed first, which is a healthy worker's cue to exit at
    /// EOF. A worker that is exiting gets `EXIT_GRACE` to finish, so its own
    /// exit code is reported; one still running after that (a timeout, a hang)
    /// has its whole process group killed.
    fn retire(mut self) -> String {
        drop(self.stdin.take());
        let deadline = std::time::Instant::now() + EXIT_GRACE;
        let status = loop {
            match self.child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                _ => {
                    kill_process_group(&mut self.child);
                    break self.child.wait().ok();
                }
            }
        };
        // Reap anything left in the group even when the leader exited on its
        // own: a forked interpreter can outlive `uv`.
        kill_process_group(&mut self.child);
        let _ = self.stderr_done.recv_timeout(STDERR_DRAIN_GRACE);
        let tail = self
            .stderr_tail
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        format!(
            "ended with {}; stderr: {}",
            status.map_or_else(|| "an unknown status".to_owned(), |s| s.to_string()),
            String::from_utf8_lossy(&tail).trim()
        )
    }
}

/// Kill `child`'s whole process group — `uv run` forks the interpreter, and
/// SIGKILL to `uv` alone would leave it running.
///
/// Through the `kill` utility rather than `libc::killpg`, because the
/// workspace forbids `unsafe`. The group was created by
/// `CommandExt::process_group(0)` at spawn, so its id is the child's pid.
/// Errors are ignored: a group that has already gone is the goal.
fn kill_process_group(child: &mut Child) {
    #[cfg(unix)]
    {
        let _ = Command::new("kill")
            .args(["-KILL", &format!("-{}", child.id())])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    let _ = child.kill();
}

#[cfg(test)]
mod tests;
