#![forbid(unsafe_code)]
//! Entry point for the Secretary browser-autofill native-messaging host.
//!
//! The browser launches this binary and speaks to it over stdin/stdout only —
//! there is no socket. The actual work is the [`secretary_browser_host::run`]
//! read→dispatch→write loop; `main` just wires it to the locked standard
//! streams and maps the result to a process exit code.

use std::process::ExitCode;

fn main() -> ExitCode {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();

    match secretary_browser_host::run(&mut reader, &mut writer) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("secretary-browser-host: {e}");
            ExitCode::FAILURE
        }
    }
}
