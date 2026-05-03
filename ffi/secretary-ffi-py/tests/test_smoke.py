"""B.1 round-trip smoke tests for the secretary_ffi_py PyO3 extension.

These tests assert the same surface as the Rust #[cfg(test)] unit tests in
src/lib.rs, exercised through the maturin-built wheel and Python's import
machinery. They prove the binding pipeline (PyO3 + maturin + uv venv +
import) works end-to-end.
"""

import secretary_ffi_py


def test_add_returns_arithmetic_sum() -> None:
    assert secretary_ffi_py.add(2, 3) == 5


def test_add_wraps_on_overflow() -> None:
    # Mirror the Rust unit test in src/lib.rs that pins the wrapping
    # contract through the FFI boundary. u32::MAX = 4_294_967_295.
    assert secretary_ffi_py.add(4_294_967_295, 1) == 0


def test_version_matches_format_version() -> None:
    # FORMAT_VERSION is pinned at 1 in core/src/version.rs; if the Rust
    # core bumps the format version this test will fail and demand an
    # explicit update — that's intentional, the wire-format constant is
    # security-critical and shouldn't drift silently.
    assert secretary_ffi_py.version() == 1
