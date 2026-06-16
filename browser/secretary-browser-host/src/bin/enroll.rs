#![forbid(unsafe_code)]
//! `secretary-browser-enroll` — **development-only** enrollment CLI for the
//! browser-autofill host.
//!
//! Mints a browser-helper device slot on a **casual** vault and writes the
//! helper-local config + the dev secret file so the host's per-fill open can be
//! exercised end to end. This is a stand-in for the design's native-app
//! enrollment (§4); the real desktop UI is a later slice.
//!
//! ```text
//! Usage:
//!   secretary-browser-enroll --vault <PATH> [--config <PATH>] [--secret <PATH>]
//!
//! The master password is read from $SECRETARY_VAULT_PASSWORD if set, else from
//! one line on stdin (it WILL echo — this is a dev tool).
//! ```
//!
//! WARNING: the device secret is written to a cleartext file (the
//! `DevFileSecretSource`). Never use this enroller for a real secret.

use std::io::BufRead;
use std::path::PathBuf;
use std::process::ExitCode;

use secretary_browser_host::config::HostConfig;
use secretary_browser_host::enroll::{default_secret_path, enroll, EnrollError};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("secretary-browser-enroll: {msg}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    eprintln!(
        "WARNING: secretary-browser-enroll is a DEVELOPMENT-ONLY tool. It writes \
         the casual vault's device secret to a CLEARTEXT file. Do not use it for \
         a real vault."
    );

    let args = Args::parse(std::env::args().skip(1))?;

    let config_path = match args.config {
        Some(p) => p,
        None => {
            HostConfig::locate().ok_or("could not locate a default config path; pass --config")?
        }
    };
    let secret_path = args
        .secret
        .unwrap_or_else(|| default_secret_path(&config_path));

    let mut password = read_password()?;
    let result = enroll(&args.vault, password.as_bytes(), &config_path, &secret_path);
    scrub(&mut password);

    match result {
        Ok(config) => {
            println!(
                "enrolled device {} on {}",
                config.device_uuid,
                args.vault.display()
            );
            println!("  config: {}", config_path.display());
            println!("  secret: {} (DEV cleartext)", secret_path.display());
            Ok(())
        }
        Err(EnrollError::Vault(e)) => Err(format!("enroll failed (wrong password?): {e}")),
        Err(EnrollError::Io(e)) => Err(format!("enroll I/O error: {e}")),
    }
}

/// Read the master password from the env var or one line of stdin.
fn read_password() -> Result<String, String> {
    if let Ok(p) = std::env::var("SECRETARY_VAULT_PASSWORD") {
        return Ok(p);
    }
    eprint!("master password (will echo): ");
    let stdin = std::io::stdin();
    let mut line = String::new();
    stdin
        .lock()
        .read_line(&mut line)
        .map_err(|e| format!("failed to read password from stdin: {e}"))?;
    // Trim the trailing newline only (passwords may contain spaces).
    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }
    Ok(line)
}

fn scrub(s: &mut String) {
    let mut buf = std::mem::take(s).into_bytes();
    for b in buf.iter_mut() {
        *b = 0;
    }
}

/// Minimal hand-rolled arg parsing (the crate has no clap dep; this dev tool
/// does not warrant adding one).
struct Args {
    vault: PathBuf,
    config: Option<PathBuf>,
    secret: Option<PathBuf>,
}

impl Args {
    fn parse(mut it: impl Iterator<Item = String>) -> Result<Self, String> {
        let mut vault = None;
        let mut config = None;
        let mut secret = None;
        while let Some(arg) = it.next() {
            match arg.as_str() {
                "--vault" => vault = Some(PathBuf::from(next_value(&mut it, "--vault")?)),
                "--config" => config = Some(PathBuf::from(next_value(&mut it, "--config")?)),
                "--secret" => secret = Some(PathBuf::from(next_value(&mut it, "--secret")?)),
                "-h" | "--help" => {
                    return Err(
                        "usage: secretary-browser-enroll --vault <PATH> [--config <PATH>] \
                         [--secret <PATH>]"
                            .to_string(),
                    )
                }
                other => return Err(format!("unexpected argument: {other}")),
            }
        }
        Ok(Self {
            vault: vault.ok_or("missing required --vault <PATH>")?,
            config,
            secret,
        })
    }
}

fn next_value(it: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    it.next().ok_or_else(|| format!("{flag} requires a value"))
}
