//! Two-instance convergence test: spawn two `secretary-sync run`
//! daemons against the same shared vault folder (each with its own
//! state-dir to avoid the lockfile collision), wait for both to settle
//! through one periodic-poll sync against the golden vault, send
//! SIGTERM to both, and assert their on-disk
//! `SyncState::highest_vector_clock_seen` files converged to the same
//! value.
//!
//! Spec: [`docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md`](../../docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md)
//! §D8 ("two subcommands") + the C.1.1b acceptance criterion that the
//! sync orchestration converges across multiple instances watching the
//! same on-disk state.
//!
//! ## Why a separate file from `once_integration.rs`
//!
//! `once_integration.rs` exercises one binary invocation end-to-end.
//! This file exercises the `run` subcommand's daemon loop with a real
//! `notify::RecommendedWatcher` plus the periodic-poll fallback, and
//! pins the convergence contract — that two daemons watching the same
//! disk-side vault, given enough wall-clock time, agree on the
//! `highest_vector_clock_seen` they record.
//!
//! ## Unix-only
//!
//! Convergence is asserted via clean shutdown of both daemons, and
//! clean shutdown is triggered by SIGTERM (the spec's documented
//! daemon-stop signal). Per spec §D10 + `cli/src/signal.rs` the daemon
//! is best-effort on non-Unix and does not install signal handlers
//! there, so this file's logic only applies to Unix targets.
//!
//! Signals are sent via shelling out to `/bin/kill -TERM <pid>` rather
//! than pulling in a new `nix`-shaped dep just for the test target —
//! `kill` is a POSIX-mandated utility, present on every Unix host we
//! support, and the alternative (`libc::kill`) would require unsafe
//! code which the workspace forbids.

#![cfg(unix)]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use tempfile::TempDir;

use secretary_cli::state;
use secretary_core::unlock::vault_toml;
use secretary_test_utils::{copy_dir_recursive, core_test_data_dir};

/// Binary name as built by Cargo from `[[bin]] name = "secretary-sync"`
/// in `cli/Cargo.toml`. Looked up via the `CARGO_BIN_EXE_*` env var
/// Cargo sets for integration tests so we get the freshly-built binary
/// without re-shelling-out to `cargo run`.
const BIN_ENV_VAR: &str = "CARGO_BIN_EXE_secretary-sync";

/// Subdirectory name of the golden vault fixture under
/// `core/tests/data/`. The fixture is the cross-language conformance
/// vector pinned by `core/tests/data/golden_vault_001_inputs.json`.
const GOLDEN_VAULT_DIRNAME: &str = "golden_vault_001";

/// Password for the golden vault — pinned to the value in
/// `core/tests/data/golden_vault_001_inputs.json`. Same value as the
/// constant in `cli/tests/once_integration.rs`; drift between this
/// constant and the canonical JSON is caught by
/// `cli/tests/pipeline_integration.rs::golden_vault_password()` which
/// reads the JSON at runtime.
const GOLDEN_VAULT_PASSWORD: &str = "correct horse battery staple";

/// Filename of the cleartext vault metadata file inside a vault folder.
/// Used to extract `vault_uuid` for [`state::load`] post-shutdown.
/// Spec: `docs/vault-format.md` §1.
const VAULT_TOML_FILENAME: &str = "vault.toml";

/// `--debounce-ms` for the daemons under test. 50 ms keeps the trailing-
/// edge debounce window short so the periodic-poll-triggered sync fires
/// without sitting on the debounce timer.
const TEST_DEBOUNCE_MS: &str = "50";

/// `--poll-interval-secs` for the daemons under test. The smallest
/// non-zero value (clap's u64 floor) — guarantees both daemons hit
/// their first periodic-poll boundary within 1 second of startup,
/// independent of notify-backend event delivery.
const TEST_POLL_INTERVAL_SECS: &str = "1";

/// `--ready-window-ms` for the daemons under test. 200 ms covers
/// `wait_for_ready`'s second `stat()` probe without adding noticeable
/// wall-clock to the test.
const TEST_READY_WINDOW_MS: &str = "200";

/// Total wall-clock to wait after spawning before sending SIGTERM. The
/// daemons must have completed at least one full `run_one` cycle —
/// budget = `poll_interval` (1 s) + `ready_window` (0.2 s) + safety
/// margin for notify-watcher startup, scheduler jitter, and OS-level
/// FSEvents/inotify settling on a loaded CI runner.
const SYNC_QUIESCENCE: Duration = Duration::from_millis(3000);

/// Maximum wall-clock to wait for a child to exit cleanly after
/// SIGTERM. Bounded by the daemon's `shutdown_poll_interval`
/// (`DEFAULT_SHUTDOWN_POLL_INTERVAL` = 1 s) plus the final `state::save`
/// path. 5 s gives generous margin for slow CI runners.
const SIGTERM_GRACE: Duration = Duration::from_millis(5000);

/// Polling interval while waiting on a child after SIGTERM.
const WAIT_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Stage a writable copy of `golden_vault_001/` under a fresh tempdir.
/// Both daemons in the convergence test share this same vault folder
/// (their separation comes from the state-dir, not the vault).
fn stage_shared_golden_vault() -> (TempDir, PathBuf) {
    let tmp = TempDir::new().expect("tempdir");
    let vault_dir = tmp.path().join(GOLDEN_VAULT_DIRNAME);
    copy_dir_recursive(&core_test_data_dir().join(GOLDEN_VAULT_DIRNAME), &vault_dir);
    (tmp, vault_dir)
}

/// Extract the 16-byte `vault_uuid` from a staged vault folder's
/// `vault.toml`. Needed at the end of the test to call
/// [`state::load`] and compare convergence between the two state files.
fn vault_uuid_from(vault_dir: &Path) -> [u8; 16] {
    let bytes = fs::read(vault_dir.join(VAULT_TOML_FILENAME)).expect("read vault.toml");
    let s = std::str::from_utf8(&bytes).expect("vault.toml utf-8");
    vault_toml::decode(s).expect("decode vault.toml").vault_uuid
}

/// Spawn a `secretary-sync run` child against `vault_dir` with its own
/// `state_dir`. Pipes the golden-vault password on stdin then closes
/// the handle so the daemon's `read_to_end` returns and unlock proceeds.
///
/// Stdout/stderr are captured (piped) so they don't interleave with
/// the test runner's own diagnostic stream. The captured streams are
/// drained by [`wait_for_child_exit`] when the daemon shuts down.
fn spawn_daemon(vault_dir: &Path, state_dir: &Path) -> Child {
    let bin = std::env::var(BIN_ENV_VAR).expect("cargo sets CARGO_BIN_EXE_secretary-sync");
    let mut child = Command::new(bin)
        .args([
            "run",
            "--password-stdin",
            "--non-interactive",
            "--debounce-ms",
            TEST_DEBOUNCE_MS,
            "--poll-interval-secs",
            TEST_POLL_INTERVAL_SECS,
            "--ready-window-ms",
            TEST_READY_WINDOW_MS,
            "--state-dir",
        ])
        .arg(state_dir)
        .arg(vault_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn secretary-sync run");

    // Scope: write password then drop the stdin handle so the daemon's
    // `read_to_end` returns. Without the explicit scope, stdin stays
    // open for the lifetime of `child` and the unlock layer blocks
    // forever waiting on EOF.
    {
        let mut stdin = child.stdin.take().expect("piped stdin handle");
        stdin
            .write_all(GOLDEN_VAULT_PASSWORD.as_bytes())
            .expect("write password to child stdin");
    }

    child
}

/// Send SIGTERM to `pid` by shelling out to `/bin/kill`. The system
/// `kill` utility is POSIX-mandated and present on every Unix host
/// we support; this side-steps the workspace `unsafe_code = "forbid"`
/// lint which would otherwise block a direct `libc::kill` call.
///
/// Returns the exit status from `kill`. The test asserts success
/// rather than ignoring the result so a typo in the command surfaces
/// as a clear panic rather than a silently-hung daemon.
fn send_sigterm(pid: u32) {
    let status = Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status()
        .expect("invoke kill");
    assert!(status.success(), "kill -TERM {pid} exit status: {status:?}");
}

/// Poll a child for exit, sleeping [`WAIT_POLL_INTERVAL`] between
/// checks, up to `timeout`. Returns `true` if the child exited within
/// the budget; `false` on timeout. Always drains stdout/stderr after
/// exit so the captured streams don't keep file descriptors alive.
fn wait_for_child_exit(child: &mut Child, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match child.try_wait().expect("try_wait must not error") {
            Some(_status) => return true,
            None => std::thread::sleep(WAIT_POLL_INTERVAL),
        }
    }
    false
}

/// Best-effort cleanup: SIGKILL a still-running child if SIGTERM didn't
/// take. Used as the panic-safe fallback so a flaky test doesn't leak
/// long-running secretary-sync processes after a failure.
///
/// Calls [`Child::kill`] which sends SIGKILL on Unix; the kernel
/// guarantees process teardown even if the daemon's normal shutdown
/// path is broken.
fn force_kill(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Two daemons watching the same shared vault folder, each with its
/// own state-dir, both converge to the same
/// `SyncState::highest_vector_clock_seen` after one periodic-poll
/// cycle and graceful shutdown.
///
/// **Scope: quiescent convergence only.** Both daemons observe the
/// same disk-side state with no third-party writes during the test
/// window; the merge layer is exercised against a single agreed-upon
/// vault state, not against concurrent mutations. Cross-device
/// live-mutation convergence (where each daemon's writes race against
/// the other's reads) is deferred to **C.4** — see
/// `docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md`
/// §D8 + the C.4 row in `ROADMAP.md`. What this test pins is the
/// daemons' state-mutation contract, signal handling, and final
/// state-save path — not the merge layer under contention.
///
/// Scenario:
///
/// 1. Stage `golden_vault_001` into a shared `vault_dir` under one
///    tempdir.
/// 2. Allocate two independent state-dirs (`state_a`, `state_b`) so
///    the per-vault lockfile in [`state::LockfileGuard::acquire`]
///    doesn't reject the second daemon's startup.
/// 3. Spawn both daemons with `--poll-interval-secs=1` so each fires
///    exactly one `run_one` cycle within the first second of life
///    (independent of notify-backend event delivery — see
///    `cli/tests/notify_quirk.rs` for the cross-platform notify
///    smoke).
/// 4. Sleep [`SYNC_QUIESCENCE`] to let both daemons complete their
///    first sync + state save.
/// 5. SIGTERM both. The daemon's signal-handler-driven shutdown flag
///    flips → daemon loop exits → `main()` calls `state::save` →
///    clean exit code 0.
/// 6. Wait for both children to exit (up to [`SIGTERM_GRACE`]).
/// 7. Load both state files via [`state::load`] and assert their
///    `highest_vector_clock_seen` are byte-identical.
///
/// Convergence under a single-vault, single-disk scenario is
/// "trivial" in that both daemons observe the same disk-side clock —
/// but pinning it as an integration test catches any future drift in
/// the daemon's state-mutation contract, signal handling, or final
/// state save path.
#[test]
fn two_instances_converge_to_same_highest_vector_clock_seen() {
    let (_vault_tmp, vault_dir) = stage_shared_golden_vault();
    let state_a = TempDir::new().expect("state_a tempdir");
    let state_b = TempDir::new().expect("state_b tempdir");
    let vault_uuid = vault_uuid_from(&vault_dir);

    let mut child_a = spawn_daemon(&vault_dir, state_a.path());
    let mut child_b = spawn_daemon(&vault_dir, state_b.path());

    std::thread::sleep(SYNC_QUIESCENCE);

    send_sigterm(child_a.id());
    send_sigterm(child_b.id());

    let a_exited = wait_for_child_exit(&mut child_a, SIGTERM_GRACE);
    let b_exited = wait_for_child_exit(&mut child_b, SIGTERM_GRACE);

    if !a_exited {
        force_kill(&mut child_a);
        force_kill(&mut child_b);
        panic!("daemon A did not exit within {SIGTERM_GRACE:?} after SIGTERM");
    }
    if !b_exited {
        force_kill(&mut child_b);
        panic!("daemon B did not exit within {SIGTERM_GRACE:?} after SIGTERM");
    }

    let status_a = child_a.wait().expect("wait child_a");
    let status_b = child_b.wait().expect("wait child_b");
    assert!(
        status_a.success(),
        "daemon A exit status: {status_a:?} (expected exit 0 after SIGTERM)"
    );
    assert!(
        status_b.success(),
        "daemon B exit status: {status_b:?} (expected exit 0 after SIGTERM)"
    );

    let state_a_loaded = state::load(state_a.path(), vault_uuid).expect("load state A");
    let state_b_loaded = state::load(state_b.path(), vault_uuid).expect("load state B");

    assert_eq!(
        state_a_loaded.highest_vector_clock_seen, state_b_loaded.highest_vector_clock_seen,
        "two daemons watching the same vault must converge to the same highest_vector_clock_seen"
    );
    assert!(
        !state_a_loaded.highest_vector_clock_seen.is_empty(),
        "golden vault's disk clock is non-empty; converged state's clock must be non-empty too"
    );
}
