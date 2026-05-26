//! `tracing-subscriber` initialization for `secretary-sync`.
//!
//! Spec: [`docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md`](../../../docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md)
//! §"Public surface" — Logging.
//!
//! Two-layer design so the verbosity-ladder logic is fully unit-testable
//! without touching process-global state:
//!
//! - [`resolve_directive`] is a pure function mapping a `--verbose`
//!   count to a `&'static str` env-filter directive. No env reads, no
//!   subscriber installation.
//! - [`try_init`] is the side-effectful production entry point. It
//!   composes [`resolve_directive`] with an optional `RUST_LOG`
//!   override, builds an [`EnvFilter`], and installs the global
//!   subscriber via `tracing_subscriber::fmt::SubscriberBuilder::try_init`.
//!   Returns `Err(TryInitError)` instead of panicking if a subscriber
//!   was already installed (e.g. by a test runner harness or a prior
//!   call), so the production callsite can fail-fast at startup while
//!   downstream code does not require the second-init-panics contract.

use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::fmt;

use crate::args::LogFormat;

/// Boxed error type returned by [`try_init`]. Matches
/// `tracing_subscriber::fmt::SubscriberBuilder::try_init`'s native
/// error type — a global subscriber install failure is rare enough that
/// surfacing the upstream error verbatim (typically "a global default
/// trace dispatcher has already been set") is more useful than
/// inventing a typed wrapper.
pub type TryInitError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Default directive when `--verbose` is unset: `info` for the CLI,
/// `warn` for the core. Operators see what's happening at a high level
/// without the core's per-operation chatter.
pub const DEFAULT_DIRECTIVE: &str = "secretary_sync=info,secretary_core=warn";

/// Single-`-v` directive: `debug` for the CLI, `info` for the core.
/// The first step up turns on CLI-internal lifecycle and decision logs
/// while keeping the core's chatter to operator-meaningful events.
pub const VERBOSE_DIRECTIVE: &str = "secretary_sync=debug,secretary_core=info";

/// Double-`-vv` (or higher) directive: `debug` for both. Used for
/// in-depth debugging of the crypto/CRDT paths. Higher counts saturate
/// at this level — there is no `trace` ladder rung in v1.
pub const DOUBLE_VERBOSE_DIRECTIVE: &str = "secretary_sync=debug,secretary_core=debug";

/// Map a `--verbose` count to the env-filter directive that should be
/// installed when `RUST_LOG` is unset.
///
/// Pure function — does not read the environment, does not install a
/// subscriber, does not allocate. Saturates at `-vv` (count ≥ 2).
pub fn resolve_directive(verbose: u8) -> &'static str {
    match verbose {
        0 => DEFAULT_DIRECTIVE,
        1 => VERBOSE_DIRECTIVE,
        _ => DOUBLE_VERBOSE_DIRECTIVE,
    }
}

/// Initialize the global tracing subscriber with the chosen format and
/// the [`resolve_directive`]-derived directive (or `RUST_LOG` if set).
///
/// Returns the directive string that was applied so the caller can log
/// a courtesy "starting at log level X" line on first init.
///
/// **One-shot semantics:** `tracing_subscriber` allows exactly one
/// global subscriber per process. A second call returns
/// [`TryInitError`] without panicking — the production `main.rs`
/// surfaces this as a startup failure; tests avoid the multi-call path
/// by exercising only the pure [`resolve_directive`] surface.
pub fn try_init(verbose: u8, format: LogFormat) -> Result<&'static str, TryInitError> {
    let directive = resolve_directive(verbose);
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(directive));
    // Diagnostics go to stderr so the binary's stdout stays usable for
    // operators redirecting it (`secretary-sync once vault > out`). The
    // `tracing-subscriber::fmt()` default is stdout, which would pollute
    // any such stream and breaks the established Unix CLI convention.
    match format {
        LogFormat::Human => fmt()
            .with_env_filter(env_filter)
            .with_writer(std::io::stderr)
            .try_init()?,
        LogFormat::Json => fmt()
            .with_env_filter(env_filter)
            .with_writer(std::io::stderr)
            .json()
            .try_init()?,
    }
    Ok(directive)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `--verbose` unset (count = 0) resolves to the default directive.
    #[test]
    fn resolve_directive_zero_returns_default() {
        assert_eq!(resolve_directive(0), DEFAULT_DIRECTIVE);
    }

    /// Single `-v` resolves to the verbose directive.
    #[test]
    fn resolve_directive_one_returns_verbose() {
        assert_eq!(resolve_directive(1), VERBOSE_DIRECTIVE);
    }

    /// `-vv` resolves to the double-verbose directive.
    #[test]
    fn resolve_directive_two_returns_double_verbose() {
        assert_eq!(resolve_directive(2), DOUBLE_VERBOSE_DIRECTIVE);
    }

    /// Higher counts saturate at double-verbose — no trace rung in v1.
    /// Pinning `u8::MAX` keeps any future "add a trace ladder rung"
    /// change from silently flipping the saturation point.
    #[test]
    fn resolve_directive_saturates_at_double_verbose() {
        assert_eq!(resolve_directive(3), DOUBLE_VERBOSE_DIRECTIVE);
        assert_eq!(resolve_directive(u8::MAX), DOUBLE_VERBOSE_DIRECTIVE);
    }

    /// The default directive must parse cleanly as an `EnvFilter`.
    /// Catches the failure mode where someone edits the constant string
    /// and breaks the directive syntax — the production `try_init` path
    /// would silently swallow this and fall back to the default
    /// `EnvFilter`, masking the bug.
    #[test]
    fn default_directive_parses_as_env_filter() {
        EnvFilter::try_new(DEFAULT_DIRECTIVE).expect("default directive must be valid");
    }

    /// `-v` directive must parse cleanly as an `EnvFilter`.
    #[test]
    fn verbose_directive_parses_as_env_filter() {
        EnvFilter::try_new(VERBOSE_DIRECTIVE).expect("verbose directive must be valid");
    }

    /// `-vv` directive must parse cleanly as an `EnvFilter`.
    #[test]
    fn double_verbose_directive_parses_as_env_filter() {
        EnvFilter::try_new(DOUBLE_VERBOSE_DIRECTIVE)
            .expect("double-verbose directive must be valid");
    }

    /// The three rungs of the ladder must be distinct — a copy-paste
    /// error that made `-v` resolve to the same directive as `-vv`
    /// would silently render the verbosity flag meaningless.
    #[test]
    fn ladder_rungs_are_distinct() {
        assert_ne!(DEFAULT_DIRECTIVE, VERBOSE_DIRECTIVE);
        assert_ne!(VERBOSE_DIRECTIVE, DOUBLE_VERBOSE_DIRECTIVE);
        assert_ne!(DEFAULT_DIRECTIVE, DOUBLE_VERBOSE_DIRECTIVE);
    }
}
