//! `secretary-sync` entry point. See
//! [`docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md`](../../docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md).

use clap::Parser;

mod args;
mod exit;
mod state;

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
