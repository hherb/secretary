#![forbid(unsafe_code)]
//! uniffi binding stub. The `.udl` file and uniffi macros are intentionally
//! not wired up yet — that wiring belongs with B.1.1's binding-pipeline
//! commit. This file currently holds the pure-Rust contract for the
//! round-trip surface (`version`, `add`) so the contract has Rust unit
//! tests independent of the FFI layer.

/// Smoke test: returns the vault format version exposed by the core crate.
///
/// Mirrors the Python crate's `version()` for parity across the two
/// binding flavors. B.1.1 keeps it as a Rust free function so the unit
/// tests below can exercise it without going through uniffi.
pub fn version() -> u16 {
    secretary_core::version::FORMAT_VERSION
}

/// Smoke-test addition. B.1.1 round-trip target.
///
/// Uses `wrapping_add` to make the overflow contract explicit (matches
/// default Rust `+` semantics in release builds, which silently wrap),
/// matching the Python crate's `add` contract for cross-binding parity.
/// B.2 will reconsider when fallible crypto operations make uniffi's
/// error-marshalling story first-class.
pub fn add(a: u32, b: u32) -> u32 {
    a.wrapping_add(b)
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
        // change to checked_add / saturating_add (or a switch to a fallible
        // signature in B.2) is a deliberate test failure rather than a
        // silent contract change.
        assert_eq!(add(u32::MAX, 1), 0);
    }
}
