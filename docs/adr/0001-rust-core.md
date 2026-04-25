# ADR 0001 — Rust core with Python / Swift / Kotlin clients via FFI

**Status:** Accepted (2026-04-25)
**Supersedes:** none
**Superseded by:** none

## Context

Secretary must run on desktop (macOS, Windows, Linux), web, iOS, and Android. The cryptographic core — primitives, vault format, key handling, conflict resolution — must be identical across all five clients to ensure interoperability and to keep the security boundary auditable. The original sketch contemplated:

1. **Pure Python** for desktop/web (NiceGUI), with a separate Kotlin Multiplatform (KMP) shared library for mobile (iOS+Android). Two crypto implementations to keep in sync.
2. **All-Rust** including UI (Slint, iced, egui, or Dioxus). One codebase but Rust GUI maturity is mixed and the web story is weaker.
3. **Rust core + per-platform UI** in the language native to each platform.

The author is a Python expert and Rust novice (knows the concepts, has not written Rust). Solo developer, finite time. The product handles long-lived secrets on multi-decade timelines, so memory hygiene (zeroizing keys, avoiding interpreter-managed copies of secrets) carries real weight.

## Decision

A single Rust crate `secretary-core` holds all security-critical code: cryptographic primitives, secrets-in-memory wrappers, vault parsing/serialization, key derivation, conflict resolution, hybrid KEM and hybrid signature, contact-card handling, recovery-key wrap.

Clients link to `secretary-core` via FFI:

- **Desktop + web:** Python with NiceGUI, calling Rust through PyO3 bindings (`secretary-ffi-py`).
- **iOS:** Swift with SwiftUI, calling Rust through uniffi (`secretary-ffi-uniffi` → `.framework`).
- **Android:** Kotlin with Jetpack Compose, calling Rust through uniffi (`secretary-ffi-uniffi` → `.aar`).

KMP is *not* used. The Rust core is the shared layer; KMP would have been a parallel mechanism only useful for sharing UI/business logic between iOS and Android above the core, and that benefit does not justify the complexity in v1.

UI is written separately per platform in its native idiom (NiceGUI HTML, SwiftUI, Compose). No attempt to share UI code across platforms.

## Consequences

**Positive:**
- One source of truth for crypto and vault format; impossible to drift.
- Rust's type system, ownership, and `zeroize` discipline give substantially stronger memory hygiene for secrets than Python or Kotlin.
- Pure-Rust dependencies (RustCrypto, dalek) are MIT/Apache-2.0, AGPL-compatible, and avoid C-library FFI inside the security boundary.
- The author learns Rust on a small, well-bounded codebase (the core) — the borrow checker is most tolerant in pure-data, no-UI code, which is the friendliest place for a Rust beginner.
- Aligns with the architecture used by Bitwarden, 1Password, Signal, Mullvad — well-trodden territory with good tooling.

**Negative:**
- Two languages in the project (Rust + Python/Swift/Kotlin) mean two toolchains to install and two test runners to wire up.
- FFI boundaries require care: error types must be expressible in both directions, secrets must not leak across the boundary inadvertently.
- Rust compile times slow CI relative to a pure-Python project. Mitigated by `sccache` and incremental compilation.
- The author spends initial weeks ramping on Rust idioms, slowing first-feature delivery. Accepted as an investment.

**Mitigations / non-goals:**
- The FFI layer is kept thin. Complex types do not cross the boundary; the FFI exposes a small surface of opaque handles plus high-level operations (open vault, list blocks, decrypt block, save record, etc.).
- The Rust core is `#![forbid(unsafe_code)]`. The few `unsafe` blocks needed for FFI lifetimes are isolated to `ffi/` crates.

## Revisit when

- Rust GUI ecosystem matures meaningfully — at that point a Rust UI for desktop+web could replace Python while keeping the same core unchanged.
- A second Rust-fluent contributor joins, at which point a Rust-only stack becomes more tractable.
