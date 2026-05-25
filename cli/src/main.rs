//! `secretary-sync` entry point. See
//! [`docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md`](../../docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md).
//!
//! As of C.2 Task 5, `cli/` is a library + binary hybrid: this binary
//! re-exports the orchestration surface through [`secretary_cli`] (see
//! [`src/lib.rs`](lib.rs)) so integration tests in `cli/tests/*.rs` can
//! reach the modules without spawning the binary.

use clap::Parser;
use secretary_cli::{args, exit};

fn main() {
    let cli = args::Cli::parse();
    // Args-layer cross-flag validation runs before any I/O so a
    // headless invocation that can't reach a password (e.g.
    // `--non-interactive` without `--password-stdin`) fails fast
    // with `ExitCode::UsageError` rather than hanging on a TTY
    // prompt that `--non-interactive` mode forbids. The subcommand
    // bodies remain stubs (Task 9 wires the dispatch); this guard
    // is the only behavior `secretary-sync` has today beyond
    // parsing, and is the load-bearing consumer of
    // `CommonArgs::validate`.
    let common = match &cli.command {
        args::Command::Once { common, .. } | args::Command::Run { common, .. } => common,
    };
    if let Err(e) = common.validate() {
        eprintln!("error: {e}");
        std::process::exit(exit::ExitCode::UsageError as i32);
    }
    let code = match cli.command {
        args::Command::Once { .. } => {
            eprintln!("secretary-sync once: not yet implemented");
            exit::ExitCode::GenericError
        }
        args::Command::Run { .. } => {
            eprintln!("secretary-sync run: not yet implemented");
            exit::ExitCode::GenericError
        }
    };
    std::process::exit(code as i32);
}
