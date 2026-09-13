//! Unit tests for `python_worker`, driving fake workers written in `sh` so
//! every transport failure is reproducible without a Python process.

use super::*;
use std::time::Instant;

const QUICK: Duration = Duration::from_millis(400);

fn sh(script: impl Into<String>) -> impl FnMut() -> Command {
    let script = script.into();
    move || {
        let mut c = Command::new("sh");
        c.arg("-c").arg(&script);
        c
    }
}

/// Is `pid` still a live process? Polls briefly: a SIGKILL is delivered
/// asynchronously, and an orphan is reaped by init a moment later.
///
/// Asks the kernel directly (`kill(pid, 0)`). This used to run the `kill -0`
/// utility and read "could not run it" as "not alive", so on a machine with
/// no `kill` on PATH the group-kill test passed having checked nothing. Any
/// answer other than "alive" or "no such process" now panics.
fn still_alive_after_grace(pid: &str) -> bool {
    let raw: i32 = pid.parse().expect("the recorded pid is a number");
    let pid = rustix::process::Pid::from_raw(raw).expect("the recorded pid is not 0");
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let alive = match rustix::process::test_kill_process(pid) {
            Ok(()) => true,
            Err(rustix::io::Errno::SRCH) => false,
            Err(e) => panic!("could not ask whether {raw} is alive: {e}"),
        };
        if !alive || Instant::now() > deadline {
            return alive;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A worker that answers every request with a reject naming `/p`.
const ECHO_P: &str = r#"while read -r line; do printf '%s\n' '{"status":"reject","error_class":"X","detail":"d","rule":null,"path":"/p"}'; done"#;

#[test]
fn one_worker_answers_many_inputs() {
    let mut replayer = PyReplayer::new(sh(ECHO_P), QUICK);
    for _ in 0..3 {
        assert!(matches!(
            replayer.decode("record", Path::new("/p")),
            PyOutcome::Reject { .. }
        ));
    }
    assert_eq!(replayer.spawned(), 1);
}

#[test]
fn an_answer_for_a_different_path_is_a_harness_failure_and_retires_the_worker() {
    let mut replayer = PyReplayer::new(sh(ECHO_P), QUICK);
    match replayer.decode("record", Path::new("/q")) {
        PyOutcome::Harness(msg) => assert!(msg.contains("/p") && msg.contains("/q"), "{msg}"),
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        replayer.decode("record", Path::new("/p")),
        PyOutcome::Reject { .. }
    ));
    assert_eq!(
        replayer.spawned(),
        2,
        "a desynchronised worker must not be reused"
    );
}

#[test]
fn a_worker_that_dies_is_a_harness_failure_naming_its_exit_and_stderr() {
    let mut replayer = PyReplayer::new(sh("read -r line; echo gone-away >&2; exit 7"), QUICK);
    match replayer.decode("record", Path::new("/p")) {
        PyOutcome::Harness(msg) => {
            assert!(msg.contains('7') && msg.contains("gone-away"), "{msg}")
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_non_json_answer_is_a_harness_failure() {
    let mut replayer = PyReplayer::new(sh("while read -r l; do echo not-json; done"), QUICK);
    assert!(matches!(
        replayer.decode("record", Path::new("/p")),
        PyOutcome::Harness(_)
    ));
}

#[test]
fn an_error_verdict_is_a_harness_failure_but_keeps_the_worker() {
    let script = r#"while read -r line; do printf '%s\n' '{"status":"error","error_class":"E","detail":"d","path":"/p","traceback":"TB"}'; done"#;
    let mut replayer = PyReplayer::new(sh(script), QUICK);
    for _ in 0..2 {
        match replayer.decode("record", Path::new("/p")) {
            PyOutcome::Harness(msg) => assert!(msg.contains("TB"), "{msg}"),
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(
        replayer.spawned(),
        1,
        "a healthy worker reporting an error is reused"
    );
}

#[test]
fn a_silent_worker_times_out_and_its_whole_process_group_is_killed() {
    // `sh` forks `sleep` into the background and waits on it, as `uv run`
    // forks Python. Killing only `sh` would leave `sleep` running — the
    // shape of an orphaned interpreter spinning on a pathological input.
    let dir = tempfile::tempdir().expect("tempdir");
    let pid_file = dir.path().join("grandchild.pid");
    let script = format!(
        "read -r line; sleep 30 & echo $! > '{}'; wait",
        pid_file.display()
    );
    let mut replayer = PyReplayer::new(sh(script), QUICK);
    match replayer.decode("record", Path::new("/p")) {
        PyOutcome::Harness(msg) => assert!(msg.contains("timeout"), "{msg}"),
        other => panic!("{other:?}"),
    }
    let pid = std::fs::read_to_string(&pid_file).expect("the worker recorded its child");
    assert!(
        !still_alive_after_grace(pid.trim()),
        "the worker's forked child {} outlived the timeout kill",
        pid.trim()
    );
}

/// The other half of the group kill: no timeout at all. The leader exits
/// UNSUCCESSFULLY on its own, the way a `uv` that died would, and leaves its
/// forked child running with every stream redirected away, so nothing but the
/// group kill after the reap can end it.
#[test]
fn a_leader_that_dies_leaving_a_forked_child_has_its_group_killed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pid_file = dir.path().join("orphan.pid");
    let script = format!(
        "read -r line; sleep 30 </dev/null >/dev/null 2>&1 & echo $! > '{}'; exit 1",
        pid_file.display()
    );
    let mut replayer = PyReplayer::new(sh(script), QUICK);
    assert!(matches!(
        replayer.decode("record", Path::new("/p")),
        PyOutcome::Harness(_)
    ));
    let pid = std::fs::read_to_string(&pid_file).expect("the worker recorded its child");
    assert!(
        !still_alive_after_grace(pid.trim()),
        "the dead leader's forked child {} was left running",
        pid.trim()
    );
}

#[test]
fn a_worker_that_cannot_stay_up_is_abandoned_after_the_failure_cap() {
    let mut replayer = PyReplayer::new(sh("exit 1"), QUICK);
    let inputs = MAX_CONSECUTIVE_WORKER_FAILURES + 5;
    for _ in 0..inputs {
        assert!(matches!(
            replayer.decode("record", Path::new("/p")),
            PyOutcome::Harness(_)
        ));
    }
    assert_eq!(replayer.spawned(), MAX_CONSECUTIVE_WORKER_FAILURES);
}

#[test]
fn a_verdict_resets_the_failure_count() {
    // Answers one request, then dies on the next: failures never come
    // MAX_CONSECUTIVE_WORKER_FAILURES in a row, so the cap never trips.
    let script = r#"read -r line; printf '%s\n' '{"status":"reject","error_class":"X","detail":"d","rule":null,"path":"/p"}'; read -r line; exit 1"#;
    let mut replayer = PyReplayer::new(sh(script), QUICK);
    let rounds = MAX_CONSECUTIVE_WORKER_FAILURES + 2;
    for _ in 0..rounds {
        assert!(matches!(
            replayer.decode("record", Path::new("/p")),
            PyOutcome::Reject { .. }
        ));
        assert!(matches!(
            replayer.decode("record", Path::new("/p")),
            PyOutcome::Harness(_)
        ));
    }
    assert_eq!(
        replayer.spawned(),
        rounds,
        "the cap tripped across verdicts"
    );
}

/// A group id of 0 is the caller's own group and 1 is `kill(-1)`, every
/// process the user owns — the blast radius the `kill` utility's
/// misparse actually reached on Linux CI. Neither may ever be signalled.
#[test]
fn a_group_id_that_would_widen_the_kill_is_refused() {
    assert_eq!(worker_group(0), None);
    assert_eq!(worker_group(1), None);
    assert_eq!(worker_group(u32::MAX), None, "not representable as a pid");
    assert_eq!(
        worker_group(4242).map(rustix::process::Pid::as_raw_nonzero),
        std::num::NonZeroI32::new(4242)
    );
}

#[test]
fn the_stderr_tail_keeps_only_the_last_cap_bytes() {
    let mut tail = b"abc".to_vec();
    push_tail(&mut tail, b"defgh", 4);
    assert_eq!(tail, b"efgh");
    push_tail(&mut tail, b"i", 4);
    assert_eq!(tail, b"fghi");
}

#[test]
fn a_response_must_be_json_and_echo_the_path_it_answers() {
    assert!(response_for(r#"{"status":"accept","path":"/p"}"#, "/p").is_ok());
    assert!(response_for("not json", "/p").is_err());
    assert!(response_for(r#"{"status":"accept"}"#, "/p").is_err());
    assert!(response_for(r#"{"status":"accept","path":"/q"}"#, "/p").is_err());
}

#[test]
fn a_command_that_cannot_be_spawned_is_a_harness_failure() {
    let mut replayer = PyReplayer::new(
        || Command::new("/nonexistent/secretary-diff-replay-worker"),
        QUICK,
    );
    assert!(matches!(
        replayer.decode("record", Path::new("/p")),
        PyOutcome::Harness(_)
    ));
}
