# Observable Trash Relocation (#376) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the silently-swallowed best-effort `blocks/ → trash/` relocation result at both `trash_block` and the open-time sweep with a structured `tracing::warn!` that distinguishes EXDEV (mis-configured cross-mount `trash/`) from other I/O failures.

**Architecture:** One new `pub(crate)` module `core/src/vault/trash_relocation.rs` exposing `log_relocation(block_uuid, result) -> RelocationOutcome`. It matches the relocation `Result` once, emits the appropriate `warn!`, and returns the outcome (the return value is the test seam, so routing is asserted without a tracing subscriber). Two call sites swap `let _ = <reloc>` for `let _ = log_relocation(&uuid, <reloc>)`. On-disk behavior is unchanged — relocation stays best-effort; only observability is added.

**Tech Stack:** Rust (stable, rustc ≥ 1.85 for `io::ErrorKind::CrossesDevices`; project tracks rolling stable at 1.96), `tracing` (already a `core` dep).

## Global Constraints

- Workspace is `#![forbid(unsafe_code)]` — no `unsafe`.
- Clippy must stay clean: `cargo clippy --release --workspace --tests -- -D warnings`.
- `cargo fmt --all --check` must be clean.
- Rustdoc must be warning-clean: `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps -p secretary-core`.
- No magic numbers: EXDEV detection via `std::io::ErrorKind::CrossesDevices`, never a raw OS errno constant.
- No `core` crypto / on-disk-format / FFI / spec-byte change. No new `VaultError`/`FfiVaultError` variant.
- Match the existing helper convention: `format_uuid_hyphenated` takes `&[u8; 16]` (a literal, not a `UUID_LEN` import — `UUID_LEN` is private).
- Build/test always `--release` (crypto crates are slow in debug).
- Commit message trailer: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.

---

### Task 1: New `trash_relocation` module (pure logging helper + unit tests)

**Files:**
- Create: `core/src/vault/trash_relocation.rs`
- Modify: `core/src/vault/mod.rs` (add module declaration, after `mod repair;` at line 32)
- Test: same file, `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: `crate::vault::orchestrators::format_uuid_hyphenated` (`pub(crate)`, `fn(&[u8; 16]) -> String`).
- Produces:
  - `pub(crate) enum RelocationOutcome { Relocated, CrossDevice, OtherFailure }` (derives `Debug, PartialEq, Eq`).
  - `pub(crate) fn log_relocation(block_uuid: &[u8; 16], result: Result<(), std::io::Error>) -> RelocationOutcome`.

- [ ] **Step 1: Write the failing tests**

Create `core/src/vault/trash_relocation.rs` with the test module only (the impl comes in Step 3, so this compiles-and-fails on the missing items):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};

    const UUID: [u8; 16] = [0x11; 16];

    #[test]
    fn ok_result_is_relocated_and_emits_nothing() {
        assert_eq!(log_relocation(&UUID, Ok(())), RelocationOutcome::Relocated);
    }

    #[test]
    fn cross_device_error_maps_to_cross_device() {
        let err = Error::from(ErrorKind::CrossesDevices);
        assert_eq!(log_relocation(&UUID, Err(err)), RelocationOutcome::CrossDevice);
    }

    #[test]
    fn other_io_error_maps_to_other_failure() {
        let err = Error::from(ErrorKind::PermissionDenied);
        assert_eq!(log_relocation(&UUID, Err(err)), RelocationOutcome::OtherFailure);
    }
}
```

Add the module declaration to `core/src/vault/mod.rs` immediately after `mod repair;` (line 32):

```rust
pub(crate) mod trash_relocation;
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --release -p secretary-core trash_relocation`
Expected: FAIL — compile error, `cannot find function log_relocation` / `cannot find type RelocationOutcome`.

- [ ] **Step 3: Write minimal implementation**

Prepend the impl above the test module in `core/src/vault/trash_relocation.rs`:

```rust
//! Observability for the best-effort `blocks/ → trash/` relocation (#376).
//!
//! The physical move is organizational, not a security boundary: a trashed
//! block's ciphertext is equally decryptable in `trash/` as in `blocks/`
//! (same bytes, same recipient wraps), and every relocation outcome leaves a
//! correct, restorable vault. Before #376 a persistent failure (EXDEV
//! cross-mount `trash/`, permissions) was silently swallowed. This module
//! turns that swallow into a structured `tracing::warn!` so a mis-configured
//! vault is observable to an operator, while keeping the move best-effort.

use crate::vault::orchestrators::format_uuid_hyphenated;

/// Outcome of a best-effort `blocks/ → trash/` relocation, for logging only.
///
/// `Relocated` covers success (and the already-relocated no-op). `CrossDevice`
/// is EXDEV — `trash/` on a different filesystem than `blocks/`, an actionable
/// mis-config. `OtherFailure` is any other I/O error (permissions, transient
/// FS error). All three leave the vault correct and the block restorable.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RelocationOutcome {
    Relocated,
    CrossDevice,
    OtherFailure,
}

/// Emit the operator-facing `warn!` for a relocation attempt and return its
/// outcome. Callers drop the return value; it exists so the kind → message
/// routing is unit-testable without capturing a `tracing` subscriber. Single
/// source of truth for the mapping — matched exactly once.
pub(crate) fn log_relocation(
    block_uuid: &[u8; 16],
    result: Result<(), std::io::Error>,
) -> RelocationOutcome {
    match &result {
        Ok(()) => RelocationOutcome::Relocated,
        Err(e) if e.kind() == std::io::ErrorKind::CrossesDevices => {
            tracing::warn!(
                block_uuid = %format_uuid_hyphenated(block_uuid),
                "trash relocation skipped: trash/ is on a different filesystem than blocks/ \
                 (EXDEV); the trashed ciphertext remains a benign, still-restorable orphan in \
                 blocks/ — co-locate trash/ on the same mount to enable relocation"
            );
            RelocationOutcome::CrossDevice
        }
        Err(e) => {
            tracing::warn!(
                block_uuid = %format_uuid_hyphenated(block_uuid),
                error = %e,
                "trash relocation failed; trashed ciphertext remains a benign, still-restorable \
                 orphan in blocks/"
            );
            RelocationOutcome::OtherFailure
        }
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --release -p secretary-core trash_relocation`
Expected: PASS — 3 tests (`ok_result_is_relocated_and_emits_nothing`, `cross_device_error_maps_to_cross_device`, `other_io_error_maps_to_other_failure`).

- [ ] **Step 5: Lint + format the new module**

Run: `cargo clippy --release -p secretary-core --tests -- -D warnings && cargo fmt --all --check`
Expected: clean (no warnings, no diff).

- [ ] **Step 6: Commit**

```bash
git add core/src/vault/trash_relocation.rs core/src/vault/mod.rs
git commit -m "feat(core): observable trash relocation helper (#376)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Wire `log_relocation` into `trash_block`

**Files:**
- Modify: `core/src/vault/orchestrators.rs` (the `trash_block` step-6 relocation at ~line 2156, and its `# Crash consistency` doc paragraph at ~line 2059-2078)

**Interfaces:**
- Consumes: `crate::vault::trash_relocation::log_relocation` (from Task 1).
- Produces: nothing new (behavior-preserving call-site change).

- [ ] **Step 1: Add the import**

At the top of `core/src/vault/orchestrators.rs`, in the existing `use crate::vault::...` cluster, add:

```rust
use crate::vault::trash_relocation::log_relocation;
```

- [ ] **Step 2: Swap the swallow for the logging helper**

Replace the step-6 block (currently):

```rust
    let _ = std::fs::create_dir_all(folder.join(TRASH_SUBDIR))
        .and_then(|()| std::fs::rename(&src, &dst));

    Ok(())
```

with:

```rust
    // #376: no longer swallowed silently — log_relocation emits a structured
    // warn! on persistent failure (EXDEV cross-mount trash/ distinguished from
    // other I/O errors) and returns the outcome, which we drop. The move stays
    // best-effort; every outcome leaves the vault correct and the block
    // restorable.
    let _ = log_relocation(
        &block_uuid,
        std::fs::create_dir_all(folder.join(TRASH_SUBDIR))
            .and_then(|()| std::fs::rename(&src, &dst)),
    );

    Ok(())
```

- [ ] **Step 3: Update the `# Crash consistency` doc paragraph**

In the `trash_block` doc comment, find the sentence ending `it degrades to the same best-effort residue as any other rename failure.` and append one sentence:

```rust
/// residue as any other rename failure. Since #376 the failure is no longer
/// silent: [`log_relocation`](crate::vault::trash_relocation::log_relocation)
/// emits a `tracing::warn!` (EXDEV distinguished from other I/O errors) so an
/// operator can observe the lingering-orphan state; the relocation itself
/// stays best-effort.
```

- [ ] **Step 4: Build + run the trash_block suite to confirm no behavior change**

Run: `cargo test --release --workspace --test crash_recovery && cargo test --release -p secretary-core trash_block`
Expected: PASS — all existing trash/restore/sweep tests green (on-disk outcome unchanged).

- [ ] **Step 5: Lint, format, doc**

Run: `cargo clippy --release -p secretary-core --tests -- -D warnings && cargo fmt --all --check && RUSTDOCFLAGS="-D warnings" cargo doc --no-deps -p secretary-core`
Expected: clean (the intra-doc link to `log_relocation` resolves — it is `pub(crate)`, and rustdoc links to crate-private items are permitted when the linking item is itself crate-internal; if `private-intra-doc-links` warns, demote to a plain code span).

- [ ] **Step 6: Commit**

```bash
git add core/src/vault/orchestrators.rs
git commit -m "feat(core): trash_block logs relocation failure instead of swallowing (#376)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Wire `log_relocation` into the open-time sweep + document the legacy arm

**Files:**
- Modify: `core/src/vault/repair/sweep.rs` (the relocation at lines 55-56, the doc line at ~22, and the legacy `fingerprint == None` arm at lines 27-30)

**Interfaces:**
- Consumes: `crate::vault::trash_relocation::log_relocation` (from Task 1).
- Produces: nothing new (behavior-preserving call-site change + doc).

- [ ] **Step 1: Add the import**

In `core/src/vault/repair/sweep.rs`, extend the existing `use crate::vault::...` imports with:

```rust
use crate::vault::trash_relocation::log_relocation;
```

- [ ] **Step 2: Swap the swallow for the logging helper**

Replace (lines 55-56):

```rust
        let _ = std::fs::create_dir_all(&trash_dir)
            .and_then(|()| std::fs::rename(&blocks_path, &trash_path));
```

with:

```rust
        // #376: log a persistent relocation failure (EXDEV / permissions)
        // instead of swallowing it. Best-effort is unchanged — a vault that
        // cannot complete the move stays in the benign orphan state that
        // restore_block resumes from.
        let _ = log_relocation(
            &entry.block_uuid,
            std::fs::create_dir_all(&trash_dir)
                .and_then(|()| std::fs::rename(&blocks_path, &trash_path)),
        );
```

- [ ] **Step 3: Update the module doc line**

In the `complete_pending_trash_renames` doc comment, replace:

```rust
/// Idempotent; every I/O failure is swallowed (a vault that cannot
/// complete the move, e.g. cross-filesystem trash/, stays in the benign
/// orphan state that `restore_block` resumes from).
```

with:

```rust
/// Idempotent; every I/O failure is logged at `tracing::warn!` (#376, via
/// `log_relocation`, EXDEV distinguished) and otherwise tolerated — a vault
/// that cannot complete the move, e.g. cross-filesystem trash/, stays in the
/// benign orphan state that `restore_block` resumes from.
```

- [ ] **Step 4: Expand the legacy `fingerprint == None` arm comment**

Replace (lines 27-30):

```rust
        // Legacy pre-#293 entry: no signed commitment → no safe gate.
        let Some(committed_fp) = entry.fingerprint else {
            continue;
        };
```

with:

```rust
        // Legacy pre-#293 entry: no signed content commitment, so there is no
        // safe gate against a planted blocks/ file — the sweep cannot relocate
        // it. Deliberately NOT migrated (#376): no tagged release ever wrote a
        // fingerprint==None entry, so no such vault exists in the wild; and
        // because relocation is organizational-only, a never-swept legacy
        // orphan is harmless — restore_block still recovers it via the §6.1
        // hybrid-verify + suffix-equality fallback the spec documents for
        // legacy entries.
        let Some(committed_fp) = entry.fingerprint else {
            continue;
        };
```

- [ ] **Step 5: Run the sweep suite to confirm no behavior change**

Run: `cargo test --release --workspace --test crash_recovery`
Expected: PASS — including `sweep_skips_legacy_entry_without_fingerprint`, `open_vault_sweep_relocates_interrupted_trash`, `sweep_skips_orphan_with_wrong_fingerprint`, `sweep_skips_live_uuid`.

- [ ] **Step 6: Lint, format, doc**

Run: `cargo clippy --release -p secretary-core --tests -- -D warnings && cargo fmt --all --check && RUSTDOCFLAGS="-D warnings" cargo doc --no-deps -p secretary-core`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add core/src/vault/repair/sweep.rs
git commit -m "feat(core): open-time sweep logs relocation failure; document legacy arm (#376)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Full-workspace verification

**Files:** none (verification only).

- [ ] **Step 1: Full workspace test**

Run: `cargo test --release --workspace`
Expected: PASS — entire suite green.

- [ ] **Step 2: Full workspace lint + format + doc gates**

Run: `cargo clippy --release --workspace --tests -- -D warnings && cargo fmt --all --check && RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace`
Expected: all clean.

- [ ] **Step 3: Confirm no unintended surface change**

Run: `git diff --stat main...HEAD`
Expected: only `core/src/vault/trash_relocation.rs` (new), `core/src/vault/mod.rs`, `core/src/vault/orchestrators.rs`, `core/src/vault/repair/sweep.rs`, and the two `docs/superpowers/` files. No FFI, no `docs/vault-format.md`, no `docs/crypto-design.md`, no manifest/format code.

---

## Post-plan wrap (handled outside task execution)

- README / ROADMAP: no change expected — an internal observability fix below the per-slice/milestone granularity those docs track. Confirm no reference to trash relocation logging exists that would need updating.
- Close #376 on merge with a comment recording the deliberate non-actions: concern #1 (secure-overwrite = category error, tracked for a future purge op as #399) and concern #3 (legacy migration = YAGNI).
- Update the handoff doc + retarget `NEXT_SESSION.md` symlink, commit on this branch before opening the PR.
