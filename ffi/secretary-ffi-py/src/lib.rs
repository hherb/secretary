//! Python bindings for secretary-core via PyO3.
//!
//! The crate-level `#![allow(unsafe_code)]` is the minimal escape hatch
//! for PyO3's #[pymodule] / #[pyfunction] macros, which expand to unsafe
//! blocks (the CPython C-API bridge is inherently unsafe). The crate-local
//! lint relaxation (workspace `forbid` → crate-local `deny`) is required
//! because `forbid` is non-overridable by inner #[allow]; see Cargo.toml.
//!
//! The `#[allow]` is **crate-level** rather than item-level because the
//! function-style `#[pymodule]` macro generates code at crate scope (an
//! `extern "C"` PyInit symbol alongside the entry-point function); a
//! narrower item-level `#[allow]` doesn't cover that expansion. The
//! tradeoff: a future contributor who adds a hand-rolled `unsafe` block
//! anywhere in this crate gets silence rather than a `deny` error. The
//! crate is intentionally tiny and reviewed; new `unsafe` blocks should
//! be challenged in code review.
//!
//! Rationale: docs/superpowers/specs/2026-05-03-ffi-b1-py-bindings-boilerplate-design.md

#![allow(unsafe_code)]

use pyo3::prelude::*;

/// Returns the vault format version exposed by the core crate.
///
/// Kept as a free function so Rust callers (and the Rust unit tests below)
/// can use it without going through PyO3 / a Python interpreter.
pub fn version() -> u16 {
    secretary_core::version::FORMAT_VERSION
}

/// Python-exposed addition. B.1 round-trip target. Uses `wrapping_add`
/// to make the overflow contract explicit (matches default Rust `+`
/// semantics in release builds, which silently wrap); B.2 will reconsider
/// when fallible crypto operations make `PyResult` first-class.
#[pyfunction]
fn add(a: u32, b: u32) -> u32 {
    a.wrapping_add(b)
}

/// Python-exposed wrapper around `version()`. Renamed at the PyO3 layer
/// from the Rust ident `version_py` to the Python name `version` so the
/// Python-side surface stays clean.
#[pyfunction]
#[pyo3(name = "version")]
fn version_py() -> u32 {
    u32::from(version())
}

/// `#[pymodule]` entrypoint. The function name (`secretary_ffi_py`) is the
/// Python module name that `import` looks up; it must match the wheel name
/// declared in `pyproject.toml` (`[tool.maturin] module-name`).
#[pymodule]
fn secretary_ffi_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(add, m)?)?;
    m.add_function(wrap_pyfunction!(version_py, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_returns_format_version() {
        assert_eq!(version(), secretary_core::version::FORMAT_VERSION);
    }

    #[test]
    fn add_returns_arithmetic_sum() {
        assert_eq!(add(2, 3), 5);
    }

    #[test]
    fn add_wraps_on_overflow() {
        // Pin the wrapping contract: u32::MAX + 1 wraps to 0. A future
        // change to checked_add / saturating_add (or a switch to PyResult
        // ergonomics in B.2) is a deliberate test failure rather than a
        // silent contract change.
        assert_eq!(add(u32::MAX, 1), 0);
    }
}
