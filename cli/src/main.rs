//! `secretary-sync` entry point. See
//! [`docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md`](../../docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md)
//! §"Public surface" + §"Daemon loop sketch".
//!
//! [`main`] parses args, runs the cross-flag validation that landed in
//! Task 1, installs logging (Task 8), then dispatches:
//!
//! - `once` → one sync attempt via [`secretary_cli::pipeline::run_one`]
//!   (Task 5) and exit.
//! - `run`  → install SIGINT/SIGTERM handlers (Task 8), build a
//!   [`DaemonConfig`] from `--debounce-ms` / `--poll-interval-secs` /
//!   `--ready-window-ms`, hand it to
//!   [`secretary_cli::daemon::run_against_vault`] (Task 7).
//!
//! Common to both subcommands: read the password (TTY or stdin),
//! `open_with_password` the on-disk vault, load the per-vault state
//! file, acquire the host-local lockfile, then dispatch.
//!
//! On clean exit (and on most failure paths) `state` is persisted via
//! [`secretary_cli::state::save`] before returning so the next
//! invocation picks up where this one left off — see
//! [`secretary_cli::pipeline::run_one`]'s state-mutation contract.

use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode as ProcExitCode;
use std::time::Duration;

use clap::Parser;
use tracing::{error, warn};

use secretary_cli::args::{Cli, Command, CommonArgs, RunArgs};
use secretary_cli::daemon::{self, DaemonConfig, DEFAULT_SHUTDOWN_POLL_INTERVAL};
use secretary_cli::exit::ExitCode;
use secretary_cli::pipeline::{run_one, RunOutcome};
use secretary_cli::state::{self, LockfileGuard, StateError};
use secretary_cli::veto::interactive::TtyVetoUx;
use secretary_cli::veto::noninteractive::AutoKeepLocalVetoUx;
use secretary_cli::{logging, signal as cli_signal, unlock};
use secretary_core::crypto::secret::SecretBytes;
use secretary_core::sync::SyncState;
use secretary_core::unlock::{open_with_password, vault_toml, UnlockedIdentity};

/// On-disk filename of the cleartext vault metadata file inside a
/// vault folder. Spec: `docs/vault-format.md` §1.
const VAULT_TOML_FILENAME: &str = "vault.toml";
/// On-disk filename of the AEAD-sealed identity bundle inside a vault
/// folder. Spec: `docs/vault-format.md` §5 (note the `.enc` extension —
/// AEAD-sealed, not raw CBOR).
const IDENTITY_BUNDLE_FILENAME: &str = "identity.bundle.enc";
/// Fallback `--state-dir` when neither `--state-dir` nor
/// `dirs::data_dir()` produces a path. The current working directory is
/// a safe last-resort that lets minimal headless installs (no `$HOME`,
/// no XDG vars) at least run; the operator can pin a better location
/// via `--state-dir` once they notice the state-file sprawl.
const STATE_DIR_FALLBACK: &str = ".";

fn main() -> ProcExitCode {
    let cli = Cli::parse();
    let code = run(cli) as i32;
    ProcExitCode::from(u8::try_from(code).unwrap_or(1))
}

/// Drive a parsed [`Cli`] to an [`ExitCode`]. Split out from [`main`]
/// so the early-exit ladder is easier to read than a top-level
/// `process::exit` cascade — every failure point logs once and
/// returns the matching exit code.
fn run(cli: Cli) -> ExitCode {
    let (common, vault, daemon_args) = decompose(&cli.command);

    if let Err(e) = common.validate() {
        // Validation must happen BEFORE logging::try_init so the
        // typed Display surfaces on stderr in the canonical form the
        // `cli/tests/main_validate.rs` suite pins. Tracing's
        // timestamped envelope would still contain the message, but
        // eprintln keeps the stderr layout deterministic for the
        // operator who hit `--non-interactive` without
        // `--password-stdin`.
        eprintln!("error: {e}");
        return ExitCode::UsageError;
    }

    // Second-init failure (a parent harness already installed a
    // subscriber, or the operator re-execs the binary inside an
    // already-instrumented test runner) is non-fatal: log a warning
    // to stderr and proceed without spamming the operator with a
    // crash report for a log-init quirk.
    if let Err(e) = logging::try_init(common.verbose, common.log_format) {
        eprintln!("warning: log subscriber init failed: {e}");
    }

    let password = match read_password(common) {
        Ok(p) => p,
        Err(e) => return fail_generic(format_args!("unlock read failed: {e}")),
    };
    let vault_toml_bytes = match std::fs::read(vault.join(VAULT_TOML_FILENAME)) {
        Ok(b) => b,
        Err(e) => return fail_generic(format_args!("read vault.toml failed: {e}")),
    };
    let bundle_bytes = match std::fs::read(vault.join(IDENTITY_BUNDLE_FILENAME)) {
        Ok(b) => b,
        Err(e) => return fail_generic(format_args!("read {IDENTITY_BUNDLE_FILENAME} failed: {e}")),
    };
    let identity = match open_with_password(&vault_toml_bytes, &bundle_bytes, &password) {
        Ok(i) => i,
        Err(e) => return fail_generic(format_args!("vault unlock failed: {e}")),
    };
    let vault_uuid = match parse_vault_uuid(&vault_toml_bytes) {
        Ok(u) => u,
        Err(e) => return fail_generic(format_args!("decode vault.toml failed: {e}")),
    };

    let state_dir = resolve_state_dir(common);
    let mut state = match state::load(&state_dir, vault_uuid) {
        Ok(s) => s,
        Err(e) => return fail_generic(format_args!("state load failed: {e}")),
    };
    // LockfileHeld returns *before* state is mutated, so we deliberately
    // skip the `state::save` at the bottom of this function on that
    // branch — the in-memory `state` came straight from `state::load`
    // and re-saving it would race the holder's writes. Any other
    // acquire failure (FS error, permission) is handled the same way:
    // bail before touching disk-side state.
    let _lock_guard = match LockfileGuard::acquire(&state_dir, vault_uuid) {
        Ok(g) => g,
        Err(StateError::LockfileHeld(path)) => {
            error!(
                "lockfile {} held by another secretary-sync process",
                path.display()
            );
            return ExitCode::LockfileHeld;
        }
        Err(e) => return fail_generic(format_args!("lockfile acquire failed: {e}")),
    };

    let interactive = !common.non_interactive;
    let exit_code = match daemon_args {
        Some(run_args) => dispatch_run_subcommand(
            run_args,
            vault,
            &identity,
            &password,
            &mut state,
            interactive,
        ),
        None => dispatch_once_subcommand(vault, &identity, &password, &mut state, interactive),
    };

    if let Err(e) = state::save(&state_dir, &state) {
        warn!("final state save failed: {e}");
    }

    exit_code
}

/// Borrow the components both subcommands share (`CommonArgs`,
/// `vault_folder`) plus the daemon-only `RunArgs` if this is `run`.
/// Returning the borrowed pieces side-by-side keeps the dispatch in
/// [`run`] linear instead of two parallel match ladders.
fn decompose(cmd: &Command) -> (&CommonArgs, &Path, Option<&RunArgs>) {
    match cmd {
        Command::Once {
            common,
            vault_folder,
        } => (common, vault_folder.as_path(), None),
        Command::Run {
            common,
            run_args,
            vault_folder,
        } => (common, vault_folder.as_path(), Some(run_args)),
    }
}

/// Resolve the state directory using the documented precedence:
/// `--state-dir` ⟶ `dirs::data_dir()`-derived default ⟶
/// [`STATE_DIR_FALLBACK`]. Falling back to `.` rather than erroring
/// keeps minimal headless installs (no `$HOME`, no XDG vars) at least
/// runnable; the operator can pin a real location via `--state-dir`
/// once they notice the sprawl.
fn resolve_state_dir(common: &CommonArgs) -> PathBuf {
    common
        .state_dir
        .clone()
        .or_else(state::default_state_dir)
        .unwrap_or_else(|| PathBuf::from(STATE_DIR_FALLBACK))
}

/// Extract the 16-byte `vault_uuid` from already-read `vault.toml`
/// bytes. [`UnlockedIdentity`] does not surface `vault_uuid` directly
/// (it carries the IBK + identity bundle, both of which are the secret
/// material), so we re-parse the same `vault.toml` the unlock path
/// already authenticated end-to-end inside `open_with_password`.
/// Re-parse is cheap (small TOML) and keeps the call site honest about
/// where the canonical UUID comes from.
fn parse_vault_uuid(vault_toml_bytes: &[u8]) -> Result<[u8; 16], ParseVaultUuidError> {
    let s = std::str::from_utf8(vault_toml_bytes).map_err(|_| ParseVaultUuidError::NotUtf8)?;
    let vt = vault_toml::decode(s).map_err(|e| ParseVaultUuidError::Decode(e.to_string()))?;
    Ok(vt.vault_uuid)
}

/// Locally-typed error surface for [`parse_vault_uuid`]. Mirrors the
/// shape of [`secretary_core::unlock::UnlockError`] for non-UTF-8 vs.
/// structural-decode failures so callers can distinguish them in logs
/// without pulling in the full `UnlockError` enum.
#[derive(Debug)]
enum ParseVaultUuidError {
    NotUtf8,
    Decode(String),
}

impl std::fmt::Display for ParseVaultUuidError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotUtf8 => f.write_str("vault.toml is not valid UTF-8"),
            Self::Decode(s) => write!(f, "vault.toml decode failed: {s}"),
        }
    }
}

/// Read the unlock password from the operator-selected source.
///
/// `--password-stdin` ⟶ read until EOF from `stdin().lock()`;
/// otherwise prompt on the TTY via `rpassword`. The
/// `--non-interactive without --password-stdin` combination is rejected
/// upstream by [`CommonArgs::validate`], so the TTY arm is only ever
/// reached when interactive mode is allowed.
fn read_password(common: &CommonArgs) -> Result<SecretBytes, unlock::UnlockReadError> {
    if common.password_stdin {
        let stdin = io::stdin();
        let mut handle = stdin.lock();
        unlock::read_password_from_reader(&mut handle)
    } else {
        unlock::read_password_from_tty()
    }
}

/// Log `msg` via `tracing::error!` and return [`ExitCode::GenericError`].
/// Tiny helper that eliminates the repetitive `error!(...); return
/// GenericError` pair throughout [`run`].
fn fail_generic(msg: std::fmt::Arguments<'_>) -> ExitCode {
    error!("{msg}");
    ExitCode::GenericError
}

/// `once` dispatch: one sync attempt via [`run_one`], then map the
/// outcome to an [`ExitCode`].
fn dispatch_once_subcommand(
    vault: &Path,
    identity: &UnlockedIdentity,
    password: &SecretBytes,
    state: &mut SyncState,
    interactive: bool,
) -> ExitCode {
    let now = now_ms();
    let result = if interactive {
        let mut ux = TtyVetoUx::new(io::BufReader::new(io::stdin()), io::stderr());
        run_one(vault, identity, password, state, &mut ux, now)
    } else {
        let mut ux = AutoKeepLocalVetoUx;
        run_one(vault, identity, password, state, &mut ux, now)
    };
    match result {
        Ok(outcome) => outcome_to_exit_code(outcome),
        Err(e) => {
            error!("pipeline error: {e}");
            ExitCode::from_sync_error(&e)
        }
    }
}

/// `run` dispatch: install signal handlers, build the [`DaemonConfig`],
/// hand off to [`daemon::run_against_vault`]. Clean shutdown is
/// [`ExitCode::Success`]; any `SyncError` raised by the loop is mapped
/// via [`ExitCode::from_sync_error`].
fn dispatch_run_subcommand(
    run_args: &RunArgs,
    vault: &Path,
    identity: &UnlockedIdentity,
    password: &SecretBytes,
    state: &mut SyncState,
    interactive: bool,
) -> ExitCode {
    let guard = match cli_signal::install_shutdown_handlers() {
        Ok(g) => g,
        Err(e) => return fail_generic(format_args!("signal handler install failed: {e}")),
    };
    let config = DaemonConfig {
        debounce: Duration::from_millis(run_args.debounce_ms),
        poll_interval: if run_args.poll_interval_secs > 0 {
            Some(Duration::from_secs(run_args.poll_interval_secs))
        } else {
            None
        },
        shutdown_poll_interval: DEFAULT_SHUTDOWN_POLL_INTERVAL,
        shutdown_flag: guard.flag().clone(),
    };
    let ready_window = Duration::from_millis(run_args.ready_window_ms);
    let result = if interactive {
        let mut ux = TtyVetoUx::new(io::BufReader::new(io::stdin()), io::stderr());
        daemon::run_against_vault(
            vault,
            identity,
            password,
            state,
            &mut ux,
            config,
            ready_window,
        )
    } else {
        let mut ux = AutoKeepLocalVetoUx;
        daemon::run_against_vault(
            vault,
            identity,
            password,
            state,
            &mut ux,
            config,
            ready_window,
        )
    };
    match result {
        Ok(()) => ExitCode::Success,
        Err(e) => {
            error!("daemon error: {e}");
            ExitCode::from_sync_error(&e)
        }
    }
}

/// Map a [`RunOutcome`] to its [`ExitCode`]. Every variant except
/// `RollbackRejected` maps to `Success` — the disk-side state was
/// merged (or already in sync); the operator just needs to know the
/// command completed.
fn outcome_to_exit_code(outcome: RunOutcome) -> ExitCode {
    match outcome {
        RunOutcome::RollbackRejected(_) => ExitCode::RollbackRejected,
        RunOutcome::NothingToDo
        | RunOutcome::AppliedAutomatically
        | RunOutcome::SilentMerge
        | RunOutcome::MergedAndCommitted { .. } => ExitCode::Success,
    }
}

/// Wall-clock milliseconds since the UNIX epoch, saturating on
/// overflow (mirrors [`secretary_cli::daemon`]'s private helper —
/// keeping a local copy avoids exposing a `now_ms` API on the daemon
/// module just to share five lines).
fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}
