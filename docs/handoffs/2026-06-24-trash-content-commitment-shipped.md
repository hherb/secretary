# NEXT_SESSION.md — restore_block content commitment (#293) ✅ SHIPPED (PR opening)

**Session date:** 2026-06-24 (started 2026-06-23). Started from a clean baton — PR #292 (#205 restore signed-timestamp selection) had merged to `main` (`77656a31`); cleaned up the prior `.worktrees/restore-signed-ts` worktree + deleted branch. Picked **#293** — the direct residual follow-up to #205 (you chose it over the #207–209 daemon cluster / #210 / #206). Brainstormed → spec → plan → executed via **subagent-driven development** (fresh implementer + spec/quality reviewer per task, final whole-branch review) → fixed review findings → opened PR.

**Status:** ✅ **SHIPPED — branch `feature/trash-content-commitment`, PR opening.** Security fix + 4 new tests; final whole-branch review (opus): **no Critical/Important**, 2 Minors both fixed.

## (1) What we shipped this session

**The vuln (#293, Medium/security — #205 residual):** #205 bound `restore_block` *selection* to the signed `TrashEntry.tombstoned_at_ms`, closing the larger-suffix-plant and authentic-file-removed vectors. A **third** vector survived: an attacker with write access to the synced `trash/` folder (threat-model §2.1) overwrites the suffix-matching file **in place** with a previously-retained, genuinely owner-signed but **older** copy of the same `block_uuid`. The §6.1 hybrid-verify passes (authenticity ≠ currency) and the suffix still equals the signed `tombstoned_at_ms`, so neither #205's suffix-equality nor the signature check defends it → authentic-but-stale rollback (e.g. a rotated password reverts).

**The fix (content commitment, frozen-v1-additive):** `TrashEntry` gains an optional `fingerprint: Option<[u8; 32]>` (BLAKE3-256 of the trashed block bytes). `trash_block` captures it from the trashed block's already-verified `BlockEntry.fingerprint` (the file is moved by `rename`, not rewritten, so the hash is stable). `restore_block` recomputes BLAKE3-256 of the selected file's bytes and **rejects** when it differs from the committed value — **before** the point-of-no-return rename, so manifest + `trash/` stay untouched. A `None` commitment (legacy entry trashed by a pre-#293 client) falls back to the #205 suffix-equality + hybrid-verify path unchanged.

**Why no new error variant / no FFI churn:** a commitment mismatch is a signed-data ↔ on-disk-bytes integrity failure → reuses the existing `VaultError::RestoreVerificationFailed { block_uuid, detail }` (detail contains `"content commitment mismatch"`), which folds to `FfiVaultError::CorruptVault`. **No new `VaultError`/`FfiVaultError` variant → no `.udl`/pyo3/Swift/Kotlin conformance-harness churn.**

**Why no format bump / no downgrade-strip attack:** the field is emitted in canonical CBOR **only when `Some`** (legacy entries byte-identical; reuses the existing `KEY_FINGERPRINT = "fingerprint"` constant — `TrashEntry` is a separate map from `BlockEntry`, no collision; unknown-key forward-compat preserved). `TrashEntry` lives inside the AEAD'd, hybrid-signed manifest body, so an attacker who strips the `fingerprint` to force the legacy path invalidates the signature → `open_vault` fails before restore is reached. The `None` fallback is reachable **only** for genuinely-legacy entries, never attacker-induced.

**Branch commits** (off `main` @ `77656a31`):
| SHA | What |
|---|---|
| `5813d807` | design doc (`docs/superpowers/specs/2026-06-23-trash-content-commitment-design.md`) |
| `b6b54892` | implementation plan (`docs/superpowers/plans/2026-06-23-trash-content-commitment.md`) |
| `ba3174fe` | **feat**: `TrashEntry.fingerprint` optional field + CBOR encode/decode + proptest Some/None + 2 unit round-trip tests |
| `51098f9f` | **feat**: `trash_block` commits the trashed block's content fingerprint |
| `c7fed667` | **fix**: `restore_block` verifies the content commitment before rename + 2 teeth tests |
| `eab7dcb8` | **docs**: vault-format §4.2/§7/§7.1 + threat-model §2.1 + README B.5 (+ bundled non-semantic `cargo fmt` reflow of Tasks 1–3) |
| `842176c3` | **docs+test**: §7.1 commitment-check order accuracy + TrashEntry byte-absence assertion (final-review fixes) |
| (+ handoff commit) | ROADMAP B.5 correction + this baton + retargeted `NEXT_SESSION.md` symlink |

**Tests added:**
- `core/src/vault/manifest.rs` (unit): `trash_entry_fingerprint_some_round_trips` (Some survives encode→decode; key does NOT leak into `unknown`), `trash_entry_fingerprint_none_omits_key` (None → key byte-absent from the isolated `TrashEntry` encoding → legacy-byte-identical).
- `core/tests/trash_restore.rs` (integration): `trash_block_captures_content_commitment` (Some == live `BlockEntry.fingerprint`); `restore_block_rejects_in_place_overwrite_with_stale_signed_copy` — the #293 teeth test (a valid owner-signed *stale* envelope overwrites the suffix-matching file in place; restore rejects with `RestoreVerificationFailed`/"content commitment mismatch", manifest+trash untouched, nothing renamed into `blocks/`; **fails on `main`**); `restore_block_legacy_entry_without_fingerprint_falls_back` (None → restore succeeds via suffix-equality).
- `core/tests/proptest.rs`: `trash_entry_strategy` now generates `Some`/`None`, so the manifest encode/decode proptest covers both shapes.

### Acceptance (all GREEN locally on the branch, verified by the controller, not assumed)
```bash
cd /Users/hherb/src/secretary/.worktrees/trash-content-commitment
cargo test --release --workspace                             # 0 FAILED across all binaries
cargo clippy --release --workspace --tests -- -D warnings    # clean
cargo fmt --all -- --check                                   # clean
uv run core/tests/python/conformance.py                      # PASS (golden vault has no trash entries; new optional key never exercised there → confirms no clean-room drift)
uv run core/tests/python/spec_test_name_freshness.py         # FAIL = the 3 PRE-EXISTING #290 false-positives only (origin_binding / registrable_domain / exact_origin @ threat-model.md L234); NO new drift introduced by this change. Not a CI gate.
```
**CI is the real gate once pushed** — `test.yml` (rust ×2 OS + desktop vitest + swift/kotlin conformance) + `rust-lint.yml` (fmt/clippy) + CodeQL. No new `FfiVaultError` variant means the Swift/Kotlin conformance harnesses are unaffected.

## (2) What's next
**#293 done (PR open). Pick a fresh item.** The #205/#293 trash-rollback surface is now fully closed (selection bound to signed timestamp + content bound to signed fingerprint). Remaining sync/daemon-security cluster (core Rust, no desktop/D.4 worktree conflict):
- **#207/#208/#209** — daemon rollback-detection gaps (discards `Ok(RunOutcome)` so attack-indicator/veto counts never logged; `SyncState` persisted only on clean exit → rollback detection voided for the whole session on crash; state-dir silent `.` fallback + missing 0700 can place rollback state inside the attacker-controlled synced folder). Related; can bundle or sequence. **Recommended next** — coherent core-Rust chunk, no FFI churn.
- **#206** — FFI `share_block` accepts an unverified contact card and overwrites a trusted one (TOFU substitution); verified primitives not projected to PyO3/uniffi. *Larger — touches FFI surface; if it needs a new `FfiVaultError` variant, thread uniffi/pyo3 + Swift/Kotlin `ConformanceErrors.{swift,kt}` and run both `run_conformance.sh` scripts (see [[project_secretary_ffivaulterror_workspace_match]]).*
- **#210** — fuzz monitor dashboard binds `0.0.0.0` with no auth (Python; small, quick win).
- **#251** (`openBlocks` accumulates plaintext until lock) / **#229** (passwords as plain `[UInt8]`/`Data` not zeroized across Swift FFI) — memory hygiene.
- **#290** — allowlist the 3 D.4 freshness false-positives once the `d4-browser-autofill` session settles.

**Acceptance criteria template for the next pick:** a failing test that reproduces the gap on `main`, the typed-error/enforcement surface *proven* (not assumed — security paths), full `cargo test --workspace` + clippy `-D warnings` green, and spec/`conformance.py` updated in lockstep if observable bytes/semantics change.

**Open follow-up issues (carried):** #290 / #284 / #280 / #277 / #273 / #272 / #269 / #255 / #252 / #251 / #247 / #246 / #234 / #232 / #231 / #229 / #224 / #218 / #210 / #209 / #208 / #207 / #206 / #193 / #192 / #190 / #189 / #186 / #183. (#205 + #293 now closed.)

## (3) Open decisions and risks
- **Deliberate scope (frozen v1):** the commitment is an *optional* field in the existing signed `TrashEntry` — no `format_version`/`manifest_version` bump, no v2 manifest. A future change that wants the trash *time* or a *vector-clock* commitment cryptographically bound into the block envelope itself would be a v2 discussion, not this fix.
- **Documented residual (graceful legacy fallback):** blocks trashed by a **pre-#293 client** carry no `TrashEntry.fingerprint` and fall back to suffix-equality + hybrid-verify until re-trashed by an updated client — they remain exposed to the #293 vector. This is the deliberate cost of not breaking restore of already-trashed blocks. An attacker **cannot induce** this state (the commitment is inside the signed manifest; stripping it breaks the signature). Honestly stated in `vault-format.md` §7.1 step 3a + `threat-model.md` §2.1.
- **Spec order vs code order:** the code runs the BLAKE3 commitment check **before** decode/AEAD-decrypt (fail-fast), so a stale-content overwrite surfaces as the content-mismatch error, not a decode/verify error. `vault-format.md` §7.1's step 3a was reworded (commit `842176c3`) to make this execution order explicit while keeping the "3a" label (so the §4.2 + threat-model cross-references stay valid). Don't "tidy" it back to imply 3a runs after the verify.
- **Equality, not `>=` (carried from #205):** selection still binds to the single signed `tombstoned_at_ms`; don't relax to `>=` in a future refactor.
- **Process note (not a code risk):** the Task 1–3 implementers ran clippy + tests but not `cargo fmt --check`, so `eab7dcb8` bundles a non-semantic `cargo fmt` reflow of their long lines alongside the doc edits (all hunks confirmed whitespace-only by review). For future SDD runs, have implementers run `cargo fmt --check` before committing.
- **Risk:** none introduced — honest-vault restore is byte-identical to before (the authentic file's fingerprint equals the committed value); the new check only bites when the on-disk bytes don't match the signed manifest. Full suite + final security review clean.

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# If PR merged: branch + worktree .worktrees/trash-content-commitment can be removed:
#   git worktree remove .worktrees/trash-content-commitment && git branch -D feature/trash-content-commitment
git worktree list && git status -s

# Run any gate locally (from the worktree if the PR is still open):
cargo test --release --workspace
cargo clippy --release --workspace --tests -- -D warnings
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; symlink retargeted in the same commit on the feature branch. New-path handoff → no add/add conflict. Branch was cut from current `origin/main` (`77656a31`, no divergence — verified main had not advanced at handoff time), so no history-binding merge was needed this session.

## Closing inventory
- **State on close:** PR opening on `feature/trash-content-commitment` (7 code/doc commits + handoff). Worktree `.worktrees/trash-content-commitment`.
- **Acceptance:** local GREEN — full workspace suite (0 fail), 4 new teeth-verified tests + proptest Some/None coverage, clippy clean, fmt clean, conformance PASS, freshness adds no new drift. Final whole-branch review (opus): no Critical/Important; 2 Minors fixed (`842176c3`). CI pending on push.
- **README.md:** B.5 restore row updated (content-commitment clause). **ROADMAP.md:** B.5 line corrected (was stale "largest-timestamp" — pre-#205 — now signed-timestamp #205 + content-commitment #293). **CLAUDE.md:** unchanged (no restore-selection invariant documented there; the "both halves" hybrid-verify property it does document is preserved — the commitment check is additive).
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-06-24-trash-content-commitment-shipped.md`.
