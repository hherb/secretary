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
