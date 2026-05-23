//! Password sourcing — TTY prompt or `--password-stdin` stream.
//!
//! Spec: [`docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md`](../../docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md)
//! §D2 (`--password-stdin` is the only headless unlock channel).
//!
//! The pure-function piece — [`read_password_from_reader`] — takes any
//! [`Read`] so unit tests can drive it from an in-memory `Cursor` without
//! touching a real TTY. The interactive TTY path lives in
//! [`read_password_from_tty`] (thin wrapper around `rpassword`).
//!
//! ## Zeroize discipline
//!
//! Both paths funnel the password bytes into a freshly allocated
//! [`SecretBytes`] via [`SecretBytes::new`] (ownership move, single
//! allocation). [`SecretBytes`] derives `ZeroizeOnDrop`, and the
//! `Zeroize` impl for `Vec<u8>` wipes the entire backing slice up to
//! `capacity` — including any bytes past `len` (e.g. the trailing
//! newline byte popped off before construction). The intermediate
//! `Vec<u8>` / `String` allocation is moved into the wrapper, never
//! copied, so the password never lives in an unzeroized heap location
//! after this module returns control.
//!
//! See [`CLAUDE.md`](../../CLAUDE.md) "Memory hygiene: zeroize discipline".

use std::io::{self, Read};

use thiserror::Error;

use secretary_core::crypto::secret::SecretBytes;

/// Prompt rendered to the TTY in interactive unlock mode. Trailing space
/// is intentional — `rpassword::prompt_password` does not append one.
const PASSWORD_PROMPT: &str = "Vault password: ";

#[allow(dead_code)] // TODO(#113): consumed by Task 5 pipeline.
#[derive(Debug, Error)]
pub enum UnlockReadError {
    #[error("--non-interactive requires --password-stdin to provide the password")]
    NonInteractiveWithoutStdin,
    #[error("I/O error reading password: {0}")]
    Io(#[from] io::Error),
    #[error("password is empty after stripping trailing newline")]
    Empty,
}

/// Strategy for sourcing the unlock password. Carried by the CLI's
/// top-level dispatch into [`pipeline::run_one`] (Task 5), which selects
/// between the TTY prompt and a `Read`-backed stream based on
/// `--password-stdin`.
///
/// Generic over `R: Read` so unit tests (and Task 5's
/// pipeline-orchestration tests) can drive the `Stream` arm from a
/// `Cursor<Vec<u8>>` without touching stdin or a TTY.
#[allow(dead_code)] // TODO(#113): consumed by Task 5 pipeline.
pub enum PasswordSource<'a, R: Read> {
    /// Read interactively from the TTY via `rpassword` — no echo.
    Tty,
    /// Read from any `Read` impl (production: `stdin().lock()`; tests:
    /// `Cursor<Vec<u8>>`) until EOF.
    Stream(&'a mut R),
}

/// Read a password from `--password-stdin` (or any `Read` for testing)
/// and return it in a zeroize-on-drop [`SecretBytes`].
///
/// Strips exactly one trailing line ending (`\n` or `\r\n`) — operators
/// commonly pipe `echo "secret" | secretary-sync --password-stdin ...`
/// and the shell appends a newline. Multiple trailing newlines past the
/// first are preserved verbatim (the password legitimately ends in a
/// newline character).
///
/// Returns [`UnlockReadError::Empty`] if the remaining buffer is empty
/// after the strip — this catches both `echo "" | ...` and a bare `\n`
/// on stdin, either of which would otherwise pass an empty password
/// down to `open_with_password` and surface a less obvious unlock
/// failure further in.
#[allow(dead_code)] // TODO(#113): consumed by Task 5 pipeline.
pub fn read_password_from_reader<R: Read>(reader: &mut R) -> Result<SecretBytes, UnlockReadError> {
    let mut buf: Vec<u8> = Vec::new();
    reader.read_to_end(&mut buf)?;
    if buf.last() == Some(&b'\n') {
        buf.pop();
        if buf.last() == Some(&b'\r') {
            buf.pop();
        }
    }
    if buf.is_empty() {
        return Err(UnlockReadError::Empty);
    }
    // Move ownership of `buf` into the SecretBytes — its ZeroizeOnDrop
    // derive then wipes the entire `capacity`-sized backing slice on
    // drop, including any bytes past `len` (e.g. the popped trailing
    // newline byte). No double allocation, no `zeroize` direct dep in
    // `cli/Cargo.toml`.
    Ok(SecretBytes::new(buf))
}

/// Read a password from the TTY via `rpassword::prompt_password`. Used
/// in interactive mode (no `--password-stdin`). Returns
/// [`UnlockReadError::Empty`] if the operator submitted an empty line.
///
/// The returned [`SecretBytes`] is constructed via [`SecretBytes::new`]
/// from `String::into_bytes` — the underlying allocation moves, so the
/// password never lives in an unzeroized `String` after this call.
#[allow(dead_code)] // TODO(#113): consumed by Task 5 pipeline.
pub fn read_password_from_tty() -> Result<SecretBytes, UnlockReadError> {
    let s = rpassword::prompt_password(PASSWORD_PROMPT)?;
    let bytes = s.into_bytes();
    if bytes.is_empty() {
        return Err(UnlockReadError::Empty);
    }
    Ok(SecretBytes::new(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A password with no trailing newline at all is preserved verbatim.
    #[test]
    fn reader_returns_password_bytes() {
        let mut input = Cursor::new(b"hunter2".to_vec());
        let secret = read_password_from_reader(&mut input).expect("read failed");
        assert_eq!(secret.expose(), b"hunter2");
    }

    /// A single trailing `\n` is stripped.
    #[test]
    fn reader_strips_trailing_newline() {
        let mut input = Cursor::new(b"hunter2\n".to_vec());
        let secret = read_password_from_reader(&mut input).expect("read failed");
        assert_eq!(secret.expose(), b"hunter2");
    }

    /// A single trailing `\r\n` (Windows / cat-from-CRLF-file) is stripped.
    #[test]
    fn reader_strips_trailing_crlf() {
        let mut input = Cursor::new(b"hunter2\r\n".to_vec());
        let secret = read_password_from_reader(&mut input).expect("read failed");
        assert_eq!(secret.expose(), b"hunter2");
    }

    /// Only ONE trailing line ending is stripped — two trailing `\n`
    /// keeps the inner `\n` as part of the password (the operator
    /// intentionally piped a multi-line value).
    #[test]
    fn reader_only_strips_one_newline() {
        let mut input = Cursor::new(b"hunter2\n\n".to_vec());
        let secret = read_password_from_reader(&mut input).expect("read failed");
        assert_eq!(secret.expose(), b"hunter2\n");
    }

    /// A lone `\r` (no `\n` after it) is NOT stripped — we only treat
    /// `\r\n` as a line ending when the `\n` is present.
    #[test]
    fn reader_lone_cr_is_preserved() {
        let mut input = Cursor::new(b"hunter2\r".to_vec());
        let secret = read_password_from_reader(&mut input).expect("read failed");
        assert_eq!(secret.expose(), b"hunter2\r");
    }

    /// Empty stdin → typed `Empty` error (not a silent empty-password
    /// pass-through to `open_with_password`).
    #[test]
    fn reader_empty_input_errors() {
        let mut input = Cursor::new(Vec::<u8>::new());
        let err = read_password_from_reader(&mut input).unwrap_err();
        assert!(
            matches!(err, UnlockReadError::Empty),
            "expected Empty, got {err:?}"
        );
    }

    /// A bare `\n` reduces to empty after the strip → typed `Empty`
    /// error.
    #[test]
    fn reader_newline_only_errors_as_empty() {
        let mut input = Cursor::new(b"\n".to_vec());
        let err = read_password_from_reader(&mut input).unwrap_err();
        assert!(
            matches!(err, UnlockReadError::Empty),
            "expected Empty, got {err:?}"
        );
    }

    /// A bare `\r\n` reduces to empty after the strip → typed `Empty`
    /// error.
    #[test]
    fn reader_crlf_only_errors_as_empty() {
        let mut input = Cursor::new(b"\r\n".to_vec());
        let err = read_password_from_reader(&mut input).unwrap_err();
        assert!(
            matches!(err, UnlockReadError::Empty),
            "expected Empty, got {err:?}"
        );
    }

    /// Both [`PasswordSource`] variants can be constructed under the
    /// `<R: Read>` bound — guards against future refactors that
    /// accidentally tighten the bound or rename a variant.
    #[test]
    fn password_source_variants_compile() {
        let _ = PasswordSource::<Cursor<Vec<u8>>>::Tty;
        let mut cursor = Cursor::new(b"x".to_vec());
        let _ = PasswordSource::Stream(&mut cursor);
    }
}
