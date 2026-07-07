# Design: observable trash relocation (#376)

**Date:** 2026-07-07
**Issue:** #376 — *trash_block best-effort rename: lingering decryptable ciphertext + lost EXDEV signal*
**Refs:** #350 (manifest-first `trash_block`), #375, #351 (restore resume), #293 (signed content commitment)
**Scope:** `core` only. No crypto / on-disk-format / FFI / spec-byte change.

## Problem

Since #350, `trash_block` is manifest-first: the signed-manifest write is the commit point and
the physical `blocks/ → trash/` rename is best-effort, with **all** failures swallowed
(`let _ = create_dir_all(...).and_then(rename)`). The open-time sweep
`complete_pending_trash_renames` swallows identically. The #375/#350 review flagged three
residual concerns. This design resolves each explicitly:

1. **Decryptable ciphertext lingers in `blocks/`** on cross-filesystem (`EXDEV`) or persistent
   permission failure.
2. **Lost operator signal.** The pre-#350 `trash_block` returned a typed `EXDEV` `Io` error
   signalling a mis-configured vault (`trash/` on a different mount). That signal is now
   silently discarded.
3. **Legacy `fingerprint == None` trash entries** are skipped by the sweep at the first check
   (no signed commitment ⇒ no safe gate), so such an orphan can never be swept.

## Decisions

### Concern #1 (secure-overwrite) — **not done, by design (category error).**

Trash is restorable by design: `restore_block` resumes from exactly the orphaned `blocks/` file.
A trashed block's ciphertext is **equally decryptable** whether it sits in `blocks/` or in
`trash/` — both are the same bytes wrapped to the same recipients. The `blocks/ → trash/` move is
*organizational*, not a security boundary. A "secure-overwrite fallback for the un-relocatable
ciphertext" would therefore destroy the block's restorability while providing **no** exposure
reduction over a correctly-relocated `trash/` file. Secure overwrite belongs to a hypothetical
future *purge / empty-trash* operation (which does not exist in the codebase today), not to
`trash_block`. Recorded in the issue on close.

### Concern #2 (lost operator signal) — **the fix.**

Replace the silent swallow at both call sites with a structured `tracing::warn!`, distinguishing
cross-device (`EXDEV`, actionable — operator should co-locate `trash/`) from other I/O failures.
`tracing` is already a `core` dependency (used by `sync::ingest` as a logging facade). Detection
uses `std::io::ErrorKind::CrossesDevices` (stable on the project's rolling-stable toolchain, rustc
1.96) — **no platform magic-number `EXDEV` constant**. Control flow is unchanged: relocation stays
best-effort, every outcome still leaves a correct, restorable vault.

### Concern #3 (legacy migration) — **not done, by design (YAGNI + documented).**

No tagged release exists (`git tag` is empty); no v1 client has ever written a `fingerprint == None`
trash entry, so no such vault exists in the wild. Because relocation is organizational-only
(see #1), a never-swept legacy orphan is a harmless benign orphan, and `restore_block` still works
via the §6.1 hybrid-verify + suffix-equality fallback the spec already documents for legacy
entries. The sweep's legacy arm gets an expanded comment recording this rationale; **no migration
code**. Recorded in the issue on close.

## Architecture

One new small module, one concept: *make a best-effort relocation observable*.

**New file `core/src/vault/trash_relocation.rs`** (~70 lines incl. docs + tests), registered
`pub(crate) mod trash_relocation;` in `core/src/vault/mod.rs`. Shared by the two call sites that
today swallow the relocation result.

```rust
/// Outcome of a best-effort blocks/ → trash/ relocation, for logging only.
/// Relocation is organizational (§7): every outcome leaves a correct,
/// restorable vault. This exists so a *persistent* failure is observable
/// instead of silently swallowed (#376).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RelocationOutcome { Relocated, CrossDevice, OtherFailure }

/// Emit the operator-facing warn! for a relocation attempt and return the
/// outcome. Callers drop the return; the return value is the test seam so
/// routing is asserted without capturing a tracing subscriber. Single
/// source of truth for the kind → message mapping.
pub(crate) fn log_relocation(
    block_uuid: &[u8; UUID_LEN],
    result: Result<(), std::io::Error>,
) -> RelocationOutcome {
    match &result {
        Ok(()) => RelocationOutcome::Relocated,
        Err(e) if e.kind() == std::io::ErrorKind::CrossesDevices => {
            tracing::warn!(block_uuid = %format_uuid_hyphenated(block_uuid),
                "trash relocation skipped: trash/ is on a different filesystem than blocks/ \
                 (EXDEV); the trashed ciphertext remains a benign, still-restorable orphan in \
                 blocks/ — co-locate trash/ on the same mount to enable relocation");
            RelocationOutcome::CrossDevice
        }
        Err(e) => {
            tracing::warn!(block_uuid = %format_uuid_hyphenated(block_uuid), error = %e,
                "trash relocation failed; trashed ciphertext remains a benign, still-restorable \
                 orphan in blocks/");
            RelocationOutcome::OtherFailure
        }
    }
}
```

One function, matched once — no duplicated classification, no `unwrap`, no `unreachable!`. The
kind → outcome decision is fully covered by the return value. Imports `format_uuid_hyphenated`
(`pub(crate)` in `orchestrators`) and `UUID_LEN`.

## Call-site changes (behavior-preserving)

- **`core/src/vault/orchestrators.rs` `trash_block` step 6:**
  `let _ = create_dir_all(...).and_then(rename)` →
  `let _ = log_relocation(&block_uuid, create_dir_all(...).and_then(rename));`.
  Update the `# Crash consistency` doc paragraph: swallow → "logged at `warn!` (EXDEV
  distinguished)".
- **`core/src/vault/repair/sweep.rs`:** same swap using `entry.block_uuid`. Update the doc line
  "every I/O failure is swallowed" → "logged at `warn!`". Expand the legacy `fingerprint == None`
  arm's comment with the YAGNI rationale above.

## Testing (TDD — tests first)

Unit tests in `trash_relocation.rs` `#[cfg(test)]`, no filesystem needed:

1. `Ok(())` → `Relocated`
2. `Err(io::Error::from(ErrorKind::CrossesDevices))` → `CrossDevice`
3. `Err(io::Error::from(ErrorKind::PermissionDenied))` → `OtherFailure`

The existing `core/tests/crash_recovery.rs` sweep tests
(`open_vault_sweep_relocates_interrupted_trash`, `sweep_skips_legacy_entry_without_fingerprint`,
`sweep_skips_orphan_with_wrong_fingerprint`, `sweep_skips_live_uuid`) and the full
`trash_block` / `restore_block` suite must stay green — they assert the on-disk outcome, which is
unchanged. The `warn!` emits into the void without a subscriber, so no test flakes.

## Non-goals / guardrails

- No secure-overwrite; no purge operation (out of scope — tracked as #399, which also records
  why a purge's real "make unrecoverable" story is cryptographic (crypto-shred an owner-only
  block) rather than filesystem overwrite, and why overwrite is unreliable on SSD/CoW storage).
- No legacy migration; no manifest re-sign.
- No `docs/vault-format.md` change: §7 (lines 459, 468) documents the best-effort move and
  EXDEV-pending state but makes no normative claim that the failure is *silent*; logging is an
  observability concern, not on-disk format.
- No new `FfiVaultError`/`VaultError` variant; no FFI surface touched.

## Acceptance

```bash
cd /Users/hherb/src/secretary
cargo test --release --workspace --test crash_recovery          # sweep suite green
cargo test --release -p secretary-core trash_relocation         # new unit tests pass
cargo test --release --workspace                                # full suite green
cargo clippy --release --workspace --tests -- -D warnings       # clean
cargo fmt --all --check                                         # clean
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps -p secretary-core # clean
```

Close #376 with a comment recording the deliberate non-actions on concerns #1 (category error)
and #3 (YAGNI).
