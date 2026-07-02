# Vault crash-recovery-on-open (#350) — design

**Date:** 2026-07-02. **Issue:** [#350](https://github.com/hherb/secretary/issues/350)
(audit Medium — availability/crash-consistency; fail-closed, no confidentiality impact).
**Scope:** `secretary-core` + normative spec only. No byte-format, KAT, conformance,
or FFI-surface change. FFI/bridge projection and platform "repair now?" UX are a
filed follow-up.

## Problem

Two crash windows leave a vault that refuses to open:

1. **`trash_block`** renames `blocks/<uuid>.cbor.enc → trash/<uuid>.cbor.enc.<ts>`
   *before* the manifest write. A crash between leaves the manifest still listing
   the block; the next `open_vault` runs `verify_block_fingerprints`, reads the
   now-missing `blocks/` file, and fails `VaultError::Io(NotFound)` — the whole
   vault appears unopenable.
2. **`save_block` / `rewrite_block_with_recipients`** write the block first
   (correct §9 order); a crash before the manifest write leaves the on-disk block
   newer than the manifest's signed fingerprint. The next open fails
   `BlockFingerprintMismatch` (bridge folds to `CorruptVault`).

Spec §6.5 promises "detect the inconsistency on next read, re-load the block,
re-fingerprint, and offer to update the manifest" — no such path exists, and the
documented sync-based recovery needs an `UnlockedIdentity` obtainable only from
the `open_vault` that is refusing to open.

## Decisions (brainstormed 2026-07-02)

| Axis | Decision |
|---|---|
| Repair UX | `open_vault` fails with a **typed recoverable error**; a new **explicit `repair_vault` orchestrator** performs gated adoption. No silent self-heal at open. |
| PR scope | Core + spec only; FFI projection is a follow-up issue. |
| Trash residue | `open_vault` runs a **best-effort rename-completion sweep** (rename-only, fingerprint-gated, no manifest mutation). |
| EXDEV / rename failure | `trash_block`'s **manifest write is the commit point**; the rename is best-effort physical completion — failure (incl. EXDEV) still returns `Ok`. |

## A. `trash_block` reorder — manifest-first

New sequence:

1. Locate the `BlockEntry` (`BlockNotFound` if absent); capture its `fingerprint`.
2. **Stage** the new manifest state on clones: entry removed, `TrashEntry
   { block_uuid, tombstoned_at_ms: now_ms, tombstoned_by, fingerprint: Some(fp) }`
   appended, vault-level clock ticked.
3. Sign + atomic-write the staged manifest. **This is the commit point.** On any
   error up to and including this write, `open.manifest` / `open.manifest_file`
   are genuinely untouched (see "latent contract fix" below).
4. Assign the staged state into `open.manifest` / `open.manifest_file`.
5. Best-effort: lazy-mkdir `trash/`, then `rename(blocks/<uuid>.cbor.enc,
   trash/<uuid>.cbor.enc.<now_ms>)`. Failure (crash, EXDEV, permissions) is
   swallowed — the block is already trashed; the file remains as a benign orphan
   `open_vault` ignores, covered by the sweep (B) and the existing #351
   restore-resume path.

**Latent contract fix.** Today's code mutates `open.manifest` before the write, so
a failed manifest write leaves in-memory state diverged from disk despite the doc
comment claiming "On `Err`: not modified". Staging on clones makes the documented
contract true. (`save_block`'s equivalent staging is out of scope here unless the
implementation shows it shares the helper naturally.)

**Crash residue (new order):** signed manifest says trashed; file still in
`blocks/`. `open_vault` succeeds (orphans are not listed, hence not verified);
`restore_block` already resumes from exactly this shape via the #351 path
(`matches.is_empty() && committed_fp.is_some() && target.is_file()`, gated on the
signed `TrashEntry.fingerprint`).

## B. `open_vault` best-effort trash-completion sweep

New `pub(crate) fn complete_pending_trash_renames(folder: &Path, manifest:
&Manifest)` called from `open_vault` after manifest verification and
`verify_block_fingerprints` (and from `repair_vault` after its write). Per
`TrashEntry`:

- `fingerprint: None` (legacy) → skip.
- UUID live in `manifest.blocks` (trash → re-save same UUID shape) → skip.
- `trash/<uuid>.cbor.enc.<tombstoned_at_ms>` already exists → skip.
- `blocks/<uuid>.cbor.enc` missing → skip.
- Read `blocks/` bytes; BLAKE3-256 ≠ the signed `TrashEntry.fingerprint` → skip.
- Otherwise `create_dir_all(trash/)` + `rename` to the §7 trash path.

Rename-only; idempotent; every I/O failure swallowed (best-effort). No manifest
mutation, no signing, no trust-state change. The gate is the *signed* fingerprint,
so an attacker who plants an arbitrary `blocks/` file cannot steer the sweep.

## C. Typed errors from `open_vault`

- **`VaultError::BlockFileMissing { block_uuid }`** (new): replaces the anonymous
  `Io(NotFound)` inside `verify_block_fingerprints` (also closes the #88
  debuggability gap for this path). **Not repairable** — repair cannot invent
  bytes; the likely cause is a torn cloud sync (manifest delivered before the
  block file) and the recovery is "retry after sync completes".
- **`BlockFingerprintMismatch`** (existing, unchanged): remains the typed signal
  for the `save_block`-residue shape; it is the app's "offer repair" trigger.
- **`VaultError::RepairRejected { block_uuid, detail: String }`** (new): repair
  gate failures (D). `detail` is diagnostic prose (no secrets; mirrors
  `RestoreVerificationFailed`'s shape).

Bridge mappers fold both new variants to `FfiVaultError::CorruptVault` (same
pattern as #371's `ContactCardUuidMismatch`): **no `FfiVaultError` surface
change**, but the workspace-wide `VaultError` match sweep applies (bridge mappers,
core KAT matches). Swift/Kotlin conformance harnesses are untouched (no
`FfiVaultError` variant added).

## D. `repair_vault` orchestrator

```rust
pub fn repair_vault(
    folder: &Path,
    unlocker: Unlocker<'_>,
    local_highest_clock: Option<&[VectorClockEntry]>,
    device_uuid: [u8; 16],
    now_ms: u64,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<OpenVault, VaultError>
```

Sibling of `open_vault`, same module. Flow:

1. Unlock + `read_and_verify_manifest` exactly as `open_vault` — same
   verify-before-decrypt, same §10 rollback check against `local_highest_clock`.
   (Shared internals: extract the `Unlocker` match arm into a helper both use.)
2. For each `manifest.blocks` entry, read `blocks/<uuid>.cbor.enc`:
   - missing → `BlockFileMissing` (abort; nothing written);
   - fingerprint matches → healthy, skip;
   - mismatch → **adoption candidate**, gated on ALL of:
     1. Full decode + AEAD-decrypt + hybrid verify (Ed25519 ∧ ML-DSA-65 — both
        halves) under the owner card, reusing `restore_block`'s machinery. The
        decrypt is required anyway: the rebuilt entry's `block_name` lives in the
        plaintext.
     2. Header `vault_uuid` / `block_uuid` cross-checks against the manifest and
        the filename UUID.
     3. **Clock freshness (two-tier; amended 2026-07-02 after Task-6 review).**
        `IncomingDominates` (file header `vector_clock` strictly dominates the
        entry's `vector_clock_summary`) → adopt: this is the `save_block`
        crash-residue shape (the interrupted save ticked the block clock).
        `Equal` → adopt ONLY when the file's resolved recipient set is a
        **strict subset** of the committed `entry.recipients`: re-keys
        (share/revoke) deliberately do NOT tick the block clock, so crashed
        re-keys land in the Equal class, where — because `rewrite_block_with_recipients`
        re-encrypts the same plaintext — the only possible delta is the
        recipient set, and a subset can only NARROW access (fail-closed; a
        keyless attacker replaying retained owner-signed bytes can at worst
        un-share, never re-grant). Everything else → `RepairRejected`:
        dominated (rollback plant), Equal non-subset (includes the
        crashed-**share** superset residue — a documented limitation until an
        informed-consent adoption path ships with the FFI projection; the
        rejection detail names the recipient delta), Equal same-set-different-bytes
        (forgery shape), and concurrent. A `last_mod_ms`-based discriminator
        was considered and REJECTED as unsound: it is caller wall-clock with
        no monotonicity guard, and the Task-6 review demonstrated a concrete
        revoked-recipient re-grant replay through it.
     4. Recipient-fingerprint → `contact_uuid` resolution: owner card first, then
        `contacts/*.card` with self-signature verification (extract
        `restore_block`'s inline resolution into a shared helper). Unresolved →
        `RepairRejected`.
3. Rebuilt `BlockEntry` per adopted block: `fingerprint` = BLAKE3-256 of the
   adopted bytes; `vector_clock_summary` = header clock **verbatim**;
   `created_at_ms` / `last_mod_ms` = header values (repair is not a content
   change — the original write's stamps stand); `block_name` from plaintext;
   `recipients` = resolved set. A crashed **re-key/revocation** therefore repairs
   to the reduced recipient set, not the stale one.
4. **All-or-nothing:** any entry failing its gates aborts the entire repair with
   a typed error; the manifest is not written.
5. If at least one block was adopted: tick the manifest-level clock for
   `device_uuid`, refresh the header (`last_mod_ms = now_ms`), fresh AEAD nonce,
   re-sign, atomic-write (same machinery as `trash_block` step 3).
6. Run the trash-completion sweep (B); return a live `OpenVault` reflecting the
   repaired state — one unlock covers repair + open.
7. A vault with nothing to repair simply opens: `repair_vault` is idempotent and
   safe to call on a healthy vault.

v1 single-owner: the unlocked identity is the owner, so re-signing authority is
inherent — no new trust decision.

## E. Spec + doc updates

- **§6.5:** replace the aspirational recovery sentence with the normative
  contract: typed `BlockFingerprintMismatch` at read; recovery via `repair_vault`
  with the adoption gates (hybrid verify ∧ strict clock dominance ∧ recipient
  resolution) and the all-or-nothing rule; `BlockFileMissing` is not repairable.
- **§7:** manifest-first deletion sequence (manifest commit, then best-effort
  move); EXDEV reworded — no longer aborts the trash, leaves the physical move
  pending until the vault is relocated to one filesystem; document the open-time
  completion sweep.
- **§9:** reframe the ordering rule as the invariant both orderings serve —
  *never persist a manifest state that references block bytes not on disk*
  (content writes: block-first; trash: manifest-first, because the same write
  removes the entry).
- **Doc comments:** rewrite `trash_block`'s "# Crash-consistency gap (#350)"
  section; update `verify_block_fingerprints` recovery guidance (repair_vault /
  BlockFileMissing / the sync-residue note).
- `docs/crypto-design.md` / threat model: no change expected (no new crypto, no
  new trust boundary — repair adopts only owner-signed, clock-advancing state).
  Confirm during implementation.

## F. Tests (TDD; new `core/tests/crash_recovery.rs`, additions to `trash_restore.rs`)

Crash simulation by state surgery: capture `manifest.cbor.enc` bytes before an
op, run the op, restore the old manifest bytes (simulates crash before the
manifest write) — or for the new trash order, skip/undo the rename step.

1. **Trash residue:** manifest-first trash with the rename suppressed →
   `open_vault` succeeds; `TrashEntry` present; that open's sweep relocates the
   file to `trash/<uuid>.cbor.enc.<ts>`; `restore_block` works both before and
   after the sweep.
2. **Sweep negative gates:** live+trashed UUID, fingerprint mismatch, legacy
   `fingerprint: None`, trash file already present — file not moved in each case.
3. **Best-effort rename:** trash with `trash/` unwritable (unix `0o555`,
   cfg-gated) → `Ok`, manifest committed, file still in `blocks/`.
4. **In-memory contract:** manifest write failure (read-only vault dir,
   cfg-gated) → `Err` and `open.manifest` / `open.manifest_file` unchanged.
5. **save_block residue:** old-manifest surgery after a block update →
   `open_vault` fails `BlockFingerprintMismatch` → `repair_vault` adopts; entry
   rebuilt correctly (fingerprint, clock verbatim, name, recipients, stamps);
   subsequent `open_vault` green; content is the new version.
6. **Re-key residue:** same surgery around `rewrite_block_with_recipients`
   (revocation) → repair adopts the reduced recipient set.
7. **Rollback plant:** capture v1 block bytes, save v2, restore v1 bytes into
   `blocks/` → `RepairRejected` (dominated clock), manifest untouched.
8. **Concurrent-clock plant:** owner-signed block written under device B's clock
   transplanted against a manifest summary carrying device A's tick →
   `RepairRejected` (incomparable).
9. **Missing file:** delete a listed block (no TrashEntry) → `BlockFileMissing
   { block_uuid }` from both `open_vault` and `repair_vault`.
10. **Idempotence:** `repair_vault` on a healthy vault opens it, writes nothing
    (manifest bytes byte-identical before/after).

Gates: `cargo test --release --workspace`, clippy `-D warnings`, rustdoc clean,
`uv run core/tests/python/conformance.py` (proves no observable-format drift),
`spec_test_name_freshness.py` after spec edits.

## Out of scope / follow-ups

- FFI bridge projection (`repair_vault` + typed error surfacing) and platform
  "repair now?" UX — file as a new issue on ship.
- Retention-window physical purge of `trash/` (§7 step 5) — still unimplemented,
  unchanged here; the sweep keeps its future input well-formed.
- Tolerating the *old-order* trash residue (block listed + file in trash/ with
  matching fingerprint) at open: dropped — pre-release, no durable vaults exist
  under the old ordering, and the reorder makes it unreachable going forward.
