#![forbid(unsafe_code)]
//! Entry point for the Secretary browser-autofill native-messaging host.
//!
//! The browser launches this binary and speaks to it over stdin/stdout only —
//! there is no socket. `main` builds the [`Context`] from the helper-local
//! config (an absent config = "not enrolled", which is fine), then drives the
//! [`run`] read→dispatch→write loop and maps the result to an exit code.

use std::process::ExitCode;

use secretary_browser_host::{run, Context};

fn main() -> ExitCode {
    // A malformed config is fatal: the host must not silently run un-enrolled
    // when the user did configure it. An *absent* config is fine (not enrolled).
    let ctx = match Context::from_default_config() {
        Ok(ctx) => ctx,
        Err(e) => {
            eprintln!("secretary-browser-host: config error: {e}");
            return ExitCode::FAILURE;
        }
    };

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();

    match run(&ctx, &mut reader, &mut writer) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("secretary-browser-host: {e}");
            ExitCode::FAILURE
        }
    }
}
