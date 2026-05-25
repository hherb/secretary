//! Binary-level integration tests for the `CommonArgs::validate` wiring
//! in `cli/src/main.rs`. Pins the contract that `--non-interactive`
//! without `--password-stdin` exits with `ExitCode::UsageError` (2)
//! before any further work, without printing a stub "not yet
//! implemented" message.
//!
//! These tests complement the parser-level unit tests in
//! `cli/src/args.rs::tests::validate_*` (which exercise the typed
//! [`secretary_cli::args::ArgsValidationError`] surface directly).
//! The binary-level tests close the gap — they prove `main()` actually
//! calls `validate()` and surfaces the correct exit code, rather than
//! just defining a method that nobody invokes.

use assert_cmd::Command;
use predicates::prelude::*;

const BIN_NAME: &str = "secretary-sync";

/// `once --non-interactive` without `--password-stdin` exits 2
/// (UsageError) with a stderr message that includes the typed error's
/// `Display` impl. Pins the wiring from `args::CommonArgs::validate`
/// → `ExitCode::UsageError` for the `once` subcommand.
#[test]
fn once_non_interactive_without_password_stdin_exits_usage_error() {
    Command::cargo_bin(BIN_NAME)
        .expect("binary built")
        .args(["once", "--non-interactive", "/tmp/vault"])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains(
            "--non-interactive requires --password-stdin",
        ));
}

/// Same rule for the `run` subcommand — [`secretary_cli::args::CommonArgs`]
/// is shared, so the dispatch in `main.rs` must apply the validation
/// to both. Pins the wiring symmetry.
#[test]
fn run_non_interactive_without_password_stdin_exits_usage_error() {
    Command::cargo_bin(BIN_NAME)
        .expect("binary built")
        .args(["run", "--non-interactive", "/tmp/vault"])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains(
            "--non-interactive requires --password-stdin",
        ));
}

/// `--password-stdin` alone (without `--non-interactive`) MUST pass
/// the args-layer validation. The subcommand body is still a Task 9
/// stub today, so the process exits 1 (`GenericError`) with the "not
/// yet implemented" message — but critically NOT 2 (UsageError).
/// Pins the negative side of the validation contract.
#[test]
fn once_password_stdin_alone_passes_args_validation() {
    Command::cargo_bin(BIN_NAME)
        .expect("binary built")
        .args(["once", "--password-stdin", "/tmp/vault"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("not yet implemented"));
}

/// Both flags together — the canonical headless invocation. Passes
/// validation, falls through to the Task 9 stub.
#[test]
fn once_non_interactive_with_password_stdin_passes_args_validation() {
    Command::cargo_bin(BIN_NAME)
        .expect("binary built")
        .args([
            "once",
            "--non-interactive",
            "--password-stdin",
            "/tmp/vault",
        ])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("not yet implemented"));
}
