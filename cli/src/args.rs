//! `clap` derive types for `secretary-sync` arg parsing.
//!
//! See [`docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md`](../../../docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md)
//! §"Public surface" for the flag table and defaults.

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use thiserror::Error;

#[derive(Parser, Debug)]
#[command(
    name = "secretary-sync",
    about = "Headless sync orchestration for a Secretary vault folder",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Single sync attempt then exit.
    Once {
        #[command(flatten)]
        common: CommonArgs,
        /// Vault folder to sync.
        vault_folder: PathBuf,
    },
    /// Long-running daemon (notify-based file watcher + debounce + optional poll).
    Run {
        #[command(flatten)]
        common: CommonArgs,
        #[command(flatten)]
        run_args: RunArgs,
        /// Vault folder to watch + sync.
        vault_folder: PathBuf,
    },
}

#[derive(clap::Args, Debug)]
pub struct CommonArgs {
    /// Read password from stdin until EOF.
    #[arg(long)]
    pub password_stdin: bool,

    /// No TTY prompts; require --password-stdin; auto-KeepLocal on vetoes.
    #[arg(long)]
    pub non_interactive: bool,

    /// Where to persist <vault_uuid_hex>.state.cbor + .lock. Defaults to OS data dir.
    #[arg(long)]
    pub state_dir: Option<PathBuf>,

    /// Log output format.
    #[arg(long, default_value = "human")]
    pub log_format: LogFormat,

    /// Verbosity. -v → debug; -vv → core debug.
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
}

#[derive(clap::Args, Debug)]
pub struct RunArgs {
    /// Debounce window for notify event bursts (ms).
    #[arg(long, default_value_t = 500)]
    pub debounce_ms: u64,

    /// Periodic safety-net poll (secs). 0 = off.
    #[arg(long, default_value_t = 0)]
    pub poll_interval_secs: u64,

    /// Size-stability window for partial-download detection (ms).
    #[arg(long, default_value_t = 2000)]
    pub ready_window_ms: u64,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogFormat {
    Human,
    Json,
}

/// Cross-flag validation failures surfaced at the args-parse layer
/// (before any I/O, before any unlock attempt).
///
/// Currently single-variant: `--non-interactive` without
/// `--password-stdin` would otherwise block on a TTY prompt that
/// `--non-interactive` mode explicitly forbids — better to reject the
/// invocation than to hang. The CLI dispatch maps this to
/// [`crate::exit::ExitCode::UsageError`] (exit 2).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ArgsValidationError {
    /// `--non-interactive` was passed without `--password-stdin`. With
    /// no TTY allowed and no stdin password channel selected, the
    /// unlock layer has nowhere to read the password from. Mirrors the
    /// typed [`crate::unlock::UnlockReadError::NonInteractiveWithoutStdin`]
    /// variant at the args layer so the failure surfaces before any
    /// unlock attempt.
    #[error("--non-interactive requires --password-stdin to provide the password")]
    NonInteractiveWithoutStdin,
}

impl CommonArgs {
    /// Validate cross-flag constraints. Currently enforces the
    /// `--non-interactive ↔ --password-stdin` pair: a headless run with
    /// no stdin channel for the password is unreachable, so reject it
    /// before we open any vault file.
    ///
    /// `--password-stdin` alone (without `--non-interactive`) remains
    /// valid: the operator may pipe the password but still want
    /// interactive veto prompts.
    pub fn validate(&self) -> Result<(), ArgsValidationError> {
        if self.non_interactive && !self.password_stdin {
            return Err(ArgsValidationError::NonInteractiveWithoutStdin);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `secretary-sync once <folder>` with no flags parses to default CommonArgs.
    #[test]
    fn parse_once_with_defaults() {
        let cli =
            Cli::try_parse_from(["secretary-sync", "once", "/tmp/vault"]).expect("parse failed");
        match cli.command {
            Command::Once {
                common,
                vault_folder,
            } => {
                assert_eq!(vault_folder, PathBuf::from("/tmp/vault"));
                assert!(!common.password_stdin);
                assert!(!common.non_interactive);
                assert!(common.state_dir.is_none());
                assert_eq!(common.log_format, LogFormat::Human);
                assert_eq!(common.verbose, 0);
            }
            _ => panic!("expected Once subcommand"),
        }
    }

    /// `secretary-sync run` with all flags parses each correctly.
    #[test]
    fn parse_run_with_all_flags() {
        let cli = Cli::try_parse_from([
            "secretary-sync",
            "run",
            "--password-stdin",
            "--non-interactive",
            "--state-dir",
            "/etc/secretary",
            "--log-format",
            "json",
            "-vv",
            "--debounce-ms",
            "750",
            "--poll-interval-secs",
            "60",
            "--ready-window-ms",
            "3000",
            "/srv/vault",
        ])
        .expect("parse failed");
        match cli.command {
            Command::Run {
                common,
                run_args,
                vault_folder,
            } => {
                assert_eq!(vault_folder, PathBuf::from("/srv/vault"));
                assert!(common.password_stdin);
                assert!(common.non_interactive);
                assert_eq!(common.state_dir, Some(PathBuf::from("/etc/secretary")));
                assert_eq!(common.log_format, LogFormat::Json);
                assert_eq!(common.verbose, 2);
                assert_eq!(run_args.debounce_ms, 750);
                assert_eq!(run_args.poll_interval_secs, 60);
                assert_eq!(run_args.ready_window_ms, 3000);
            }
            _ => panic!("expected Run subcommand"),
        }
    }

    /// Missing required positional vault_folder argument → parse error.
    #[test]
    fn parse_once_missing_folder_fails() {
        let result = Cli::try_parse_from(["secretary-sync", "once"]);
        assert!(result.is_err());
    }

    /// `--ready-window-ms` defaults to 2000 (spec §"Public surface" D6 mobile-aware default).
    #[test]
    fn run_args_default_ready_window_is_2000() {
        let cli = Cli::try_parse_from(["secretary-sync", "run", "/tmp/vault"]).expect("parse");
        if let Command::Run { run_args, .. } = cli.command {
            assert_eq!(
                run_args.ready_window_ms, 2000,
                "spec freezes default at 2000 ms"
            );
        } else {
            panic!("expected Run");
        }
    }

    /// `validate()` accepts the default flag-set (neither flag set).
    #[test]
    fn validate_accepts_default_flags() {
        let cli =
            Cli::try_parse_from(["secretary-sync", "once", "/tmp/vault"]).expect("parse failed");
        let Command::Once { common, .. } = cli.command else {
            panic!("expected Once");
        };
        common.validate().expect("default flags must validate");
    }

    /// `validate()` accepts `--password-stdin` alone (operator pipes
    /// the password but still wants interactive veto prompts).
    #[test]
    fn validate_accepts_password_stdin_without_non_interactive() {
        let cli = Cli::try_parse_from(["secretary-sync", "once", "--password-stdin", "/tmp/vault"])
            .expect("parse failed");
        let Command::Once { common, .. } = cli.command else {
            panic!("expected Once");
        };
        common
            .validate()
            .expect("--password-stdin alone must validate");
    }

    /// `validate()` accepts the both-flags-set combination — the
    /// canonical headless invocation.
    #[test]
    fn validate_accepts_non_interactive_with_password_stdin() {
        let cli = Cli::try_parse_from([
            "secretary-sync",
            "once",
            "--non-interactive",
            "--password-stdin",
            "/tmp/vault",
        ])
        .expect("parse failed");
        let Command::Once { common, .. } = cli.command else {
            panic!("expected Once");
        };
        common
            .validate()
            .expect("--non-interactive + --password-stdin must validate");
    }

    /// `--non-interactive` without `--password-stdin` must error with
    /// the typed `NonInteractiveWithoutStdin` variant. This is the
    /// args-layer counterpart to the typed
    /// `UnlockReadError::NonInteractiveWithoutStdin` surface, fired
    /// before any vault I/O.
    #[test]
    fn validate_rejects_non_interactive_without_password_stdin() {
        let cli =
            Cli::try_parse_from(["secretary-sync", "once", "--non-interactive", "/tmp/vault"])
                .expect("parse failed");
        let Command::Once { common, .. } = cli.command else {
            panic!("expected Once");
        };
        let err = common.validate().expect_err("must reject");
        assert_eq!(err, ArgsValidationError::NonInteractiveWithoutStdin);
    }

    /// The same rule applies to the `run` subcommand, since
    /// [`CommonArgs`] is shared.
    #[test]
    fn validate_rejects_run_non_interactive_without_password_stdin() {
        let cli = Cli::try_parse_from(["secretary-sync", "run", "--non-interactive", "/tmp/vault"])
            .expect("parse failed");
        let Command::Run { common, .. } = cli.command else {
            panic!("expected Run");
        };
        let err = common.validate().expect_err("must reject");
        assert_eq!(err, ArgsValidationError::NonInteractiveWithoutStdin);
    }
}
