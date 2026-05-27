# NEXT_SESSION.md — D.1.1 Task 2 (backend pure modules) shipped

**Session date:** 2026-05-27 (continues from the D.1.1 Task 1 session earlier today; the scaffold landed via PR #131 at `e329087` on `main`. This session adds the four pure backend modules called out in the plan's Task 2.)
**Status:** D.1.1 Task 2 authored on branch `feature/d11-task-2`; PR pending. Predecessors on `main`: D.1.1 spec + ADR 0007 (PR #130, `a5d85b9`) and D.1.1 Task 1 scaffold (PR #131, `e329087`).

## (1) What we shipped this session

Four pure-Rust modules that compile + unit-test in isolation, no I/O, no Tauri runtime, no `secretary-ffi-bridge` runtime dependencies (only typed value imports). Each module ships its own unit tests with the implementation, per CLAUDE.md TDD discipline.

| Artifact | Path | Notes |
|---|---|---|
| Constants table | [`desktop/src-tauri/src/constants.rs`](../../desktop/src-tauri/src/constants.rs) | The 8 named constants from spec §8 (`AUTO_LOCK_*_MS`, `SETTINGS_BLOCK_NAME`, `SETTINGS_RECORD_TYPE`, `SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS`, `ACTIVITY_NOTIFY_MIN_INTERVAL_MS`) + the `deterministic_uuid_16(input) = SHA-256(input)[0..16]` helper. **4 tests** including two frozen-hex tripwires that pin the on-disk UUIDs for the settings block (`04fcc7aa05345f631e7f1ce2db78ba9a`) and settings record (`4145cb7a4531f1ac41af6717e205e1a9`); any future change to those input strings becomes a test failure flagging a vault-format break before it ships. |
| Error types | [`desktop/src-tauri/src/errors.rs`](../../desktop/src-tauri/src/errors.rs) | `AppError` (13 variants) + `AppWarning` (3 variants) — both serde-tagged discriminated unions; developer-facing `detail` fields are `#[serde(skip_serializing)]` so they're logged via `tracing` on the Rust side but never reach the frontend. `From<FfiVaultError>` is an explicit per-variant exhaustive match so any future bridge variant becomes a compile error forcing a deliberate UI-mapping choice. Anti-oracle property preserved at the seam: both `WrongPasswordOrCorrupt` and `WrongMnemonicOrCorrupt` collapse to `AppError::WrongPassword`. **8 tests** (6 serde-shape, 2 mapping spot-checks at the From<FfiVaultError> seam). |
| Idle tracker | [`desktop/src-tauri/src/auto_lock.rs`](../../desktop/src-tauri/src/auto_lock.rs) | `IdleTracker { last_activity_ms }` + `now_ms()` free function. `notify` only advances forward (rejects backward clock skew, preventing spurious auto-lock after suspend/resume). `is_expired` uses `saturating_sub` so backward clock differences return false rather than panicking. **8 tests** including underflow-safety, monotonicity, and a `now_ms_is_after_2020` system-clock sanity check. |
| Settings parser | [`desktop/src-tauri/src/settings.rs`](../../desktop/src-tauri/src/settings.rs) | `Settings { auto_lock_timeout_ms: u64 }` pure value type + `parse_settings_field` (load path: lenient — clamps out-of-bounds with `AppWarning::SettingsClamped`) + `validate_save_value` (save path: strict — rejects out-of-bounds with `AppError::SettingsOutOfRange`, so silent clamping can't mask user intent) + `serialize_settings` (returns the `(record_type, field_name, value_text)` triple that Task 3's vault-save will package into a `BlockInput`). **12 tests** including a serialize↔parse round-trip and inclusive min/max bounds pinning. |
| Wiring in `main.rs` | [`desktop/src-tauri/src/main.rs`](../../desktop/src-tauri/src/main.rs) | Added `mod auto_lock; mod constants; mod errors; mod settings;` declarations. `fn main()` body unchanged from Task 1. |
| Cargo deps | [`desktop/src-tauri/Cargo.toml`](../../desktop/src-tauri/Cargo.toml) | Added: `secretary-ffi-bridge` (workspace path — for `FfiVaultError` typed mapping), `serde` + `serde_json` (IPC wire format), `thiserror` (derive `Error`), `tracing` (Rust-side detail logging), `sha2` + `hex` (deterministic UUID helper + frozen-hex tests). Versions track the workspace conventions used by `core/` and `ffi/secretary-ffi-bridge/`. The `tempfile = "=3.27.0"` exact-pin (for atomic writes) is NOT pulled here — it lands in Task 3 when the `device_uuid` persistence path is wired up. |
| Lockfile | [`Cargo.lock`](../../Cargo.lock) | Resolves the new transitive deps (serde 1.x, thiserror 2.x, tracing 0.1.x, sha2 0.10.x — all already in the workspace via other crates). |
| Handoff baton | This file ([`docs/handoffs/2026-05-27-d11-task-2-shipped.md`](.)) | Captures Task 2's delivery and frames Task 3. |
| Symlink retarget | [`NEXT_SESSION.md`](../../NEXT_SESSION.md) | Bumped from `2026-05-27-d11-task-1-shipped.md` to this file. |

**Commits on `feature/d11-task-2`** (5 original + 2 post-review fixups + a baton-sync amendment):

| SHA | Subject |
|---|---|
| `1330d24` | `feat(d11): constants module — auto-lock timings + settings schema names + deterministic UUID helper` |
| `07dd9e3` | `feat(d11): AppError + AppWarning + From<FfiVaultError> mapping` |
| `588f37e` | `feat(d11): IdleTracker pure module — now_ms + notify + is_expired (underflow-safe)` |
| `0a1281a` | `feat(d11): Settings parse/serialize pure module + Task 2 clippy hardening` |
| `de947dd` | `style(d11): cargo fmt fixup over Task 2 modules` |
| `ea30470` | `docs(d11): document u64 ms truncation bound in auto_lock::now_ms` |
| `31bb133` | `refactor(d11): split map_ffi_error pure helper from From<FfiVaultError>` |

Post-squash-merge SHA on `main` will differ.

### Gauntlet (live, performed)

```
PASSED: 993 FAILED: 0 IGNORED: 10        # baseline was 960 / 0 / 10
cargo clippy --release --workspace --tests -- -D warnings   → clean
cargo fmt --all -- --check                                  → clean
uv run core/tests/python/conformance.py                     → PASS
uv run core/tests/python/spec_test_name_freshness.py        → PASS
```

Plan predicted +27 tests (960 → 987). Actual delta is **+33** (960 → 993) — six extra tests beyond the plan's count, all defensible additions and called out per-module:

- `errors.rs`: +3 — `ffi_wrong_password_or_corrupt_collapses_to_wrong_password` (pins the anti-oracle collapse at the From<FfiVaultError> seam, not just at the serde shape) + `ffi_corrupt_vault_detail_is_logged_but_stripped_on_serialize` (pins the detail-stripping path end-to-end) + `map_ffi_error_is_pure_no_log_side_effect_required` (post-review-fixup: documents the API of the pure `map_ffi_error` helper that `From<FfiVaultError>` delegates to after logging).
- `auto_lock.rs`: +1 — `now_ms_is_after_2020` (sanity check: would catch an accidental "return seconds instead of milliseconds" regression).
- `settings.rs`: +2 — `parse_non_integer_errors` (the plan listed this in the test count but I had to verify) + `validate_save_accepts_min_and_max_inclusive` (the `..=` form is easy to off-by-one; pins the inclusivity).

Per the plan's note on prediction tracking: surplus tests are good news; Task 3's gauntlet baseline becomes **993 / 0 / 10** rather than **987 / 0 / 10**.

### Plan execution trace (for the reviewer)

- Plan Steps 1–17 followed verbatim with two minor adaptations (called out in §(3)).
- Step 18 (push + PR) executes at the end of this session.
- All four modules under the 500-line CLAUDE.md threshold: constants ≈ 140 LOC, errors ≈ 290 LOC, auto_lock ≈ 118 LOC, settings ≈ 270 LOC.
- Per-module TDD discipline: each module's tests written together with its implementation; each module committed in its own commit so the diff stays bisectable.

## (2) What's next — D.1.1 Task 3 (session + settings I/O facade)

Per the plan (Task 3 begins at plan line 1500 of `docs/superpowers/plans/2026-05-27-d11-tauri-walking-skeleton.md`), Task 3 wires the pure modules into a stateful session that owns the unlocked `OpenVaultManifest` + `UnlockedIdentity` and provides the actual vault I/O:

- `desktop/src-tauri/src/session.rs` — `VaultSession` / `UnlockedSession` types + `Drop` impl + `unlock` / `lock` / `notify_activity` / `with_open_vault` methods. ~300 LOC.
- `desktop/src-tauri/src/settings.rs` (extension) — `load_from_vault` + `save_to_vault` + `device_uuid` helpers (persist per-vault UUID at `dirs::data_dir()/secretary-desktop/devices/<vault_uuid_hex>.dev` for the vector-clock layer).
- `desktop/src-tauri/tests/session_integration.rs` — ~12 cargo tests against `core/tests/data/golden_vault_001/` + ephemeral vaults.

**Acceptance criteria for Task 3 (from the plan):**

- Gauntlet count goes from **993 → ~1005** (+12 integration tests).
- `desktop/src-tauri/Cargo.toml` gains `tempfile = "=3.27.0"` (exact pin per CLAUDE.md atomic-write discipline) + `dirs = "5"` + `rand` (for the per-vault device UUID generation).
- Settings round-trips through a real ephemeral vault: write via `save_block`, read back via `read_block`, parse via Task 2's `parse_settings_field`, assert equality.
- Drop-chain wipe pinned: drop the `UnlockedSession`, then memory-inspect that the `UnlockedIdentity`'s secret bytes are zeroed (the bridge crate's existing zeroize tests give a working pattern).
- Clippy + fmt + conformance + spec-freshness all stay green.

**Estimate:** ~75–90 min (Drop-chain test setup and `tempfile::TempDir`-driven ephemeral-vault fixtures take longer than pure-module work).

## (3) Open decisions and risks

### Plan adaptations (worth flagging to the reviewer)

1. **`From<FfiVaultError>` match adapted to the bridge's actual variants.** The plan's draft used variant names like `FfiVaultError::Unlock { .. }`, `FfiVaultError::WeakKdfParams { .. }`, `FfiVaultError::Io { detail }` that don't exist in the current bridge crate — the plan warned this might happen ("If `FfiVaultError` variants don't match the names used in the `From` impl, fix the match arms to use the real names"). The actual bridge surface (per [`ffi/secretary-ffi-bridge/src/error/vault/mod.rs`](../../ffi/secretary-ffi-bridge/src/error/vault/mod.rs)) is 13 variants including `WrongPasswordOrCorrupt`, `WrongMnemonicOrCorrupt`, `InvalidMnemonic { detail }`, `VaultMismatch`, `CorruptVault { detail }`, `FolderInvalid { detail }`, `BlockNotFound { uuid_hex }`, `SaveCryptoFailure { detail }`, `CardDecodeFailure { detail }`, plus four share/restore variants (`NotAuthor`, `RecipientAlreadyPresent`, `MissingRecipientCard`, `BlockUuidAlreadyLive`, `BlockNotInTrash`). All are now mapped explicitly in the `From` impl with rationale comments naming which `AppError` variant each one routes to and why. The `WeakKdfParams` → `KdfTooWeak` mapping has no producer because the bridge already collapses `WeakKdfParams` into `CorruptVault { detail }` upstream — `AppError::KdfTooWeak` survives as a typed variant (with a serde-shape test) for the future where the bridge exposes the parameter pair structurally, but no `From` arm constructs it today. This is documented in the module docstring.
2. **Clippy hardening rolled into Task 2 rather than deferred to Task 3.** The plan didn't anticipate clippy's `enum_variant_names` complaint about `AppWarning` (all three variants share the `Settings` prefix), `dead_code` complaints on the variants Task 4 will produce, or `assertions_on_constants` on tests like `assert!(AUTO_LOCK_MIN_MS < AUTO_LOCK_DEFAULT_MS)` (compile-time-known so it's not a runtime test). Resolved per CLAUDE.md "Clippy must stay clean" with: explicit `#[allow(clippy::enum_variant_names)]` + `#[allow(dead_code)]` allows with comments naming the future producer task and the IPC-contract reason for the shared prefix, and three compile-time-constant tests lifted to `const _: () = assert!(...)` (which upgrades the relationship check to a compile error if ever violated). All allows are scoped to specific items with documented justifications — no blanket file-level allows.

Neither adaptation changes the spec or the architectural decisions. Both are encounters with reality that the plan author couldn't have predicted without the live attempt.

### Post-review fixups (PR #137 review thread)

Two minor items from the PR #137 self-review landed as separate commits on top of the original five (`ea30470`, `31bb133`):

1. **Documented the `u64` ms truncation bound in `now_ms`.** `Duration::as_millis()` returns `u128`; the truncation to `u64` is safe well past any horizon this code will run, but worth one sentence in the docstring.
2. **Factored `map_ffi_error` out of `From<FfiVaultError>`.** The original `From` body embedded a `tracing::warn!` side effect; conventionally `From` is expected to be pure-value. The pure mapping now lives in `pub fn map_ffi_error(e) -> AppError`, and `impl From` logs + delegates. The side effect is visible at the call site rather than buried in the conversion. Adds one test (`map_ffi_error_is_pure_no_log_side_effect_required`) documenting the pure-helper API; existing 8 `From`-path tests unchanged.

Two further review items were deferred and filed as follow-up issues:

- **#139** — `AppError` lacks `Deserialize`; the wire-format contract is enforced one-way only at the Rust level. The `#[serde(skip_serializing)]` on `detail` fields makes a strict identity round-trip impossible without changing attribute semantics; defer to Task 6 (TS discriminated union) so the wire-format pin has a single canonical source.
- **#140** — `parse_settings_field`'s text-only invariant is documented but not type-enforced. Task 3 has the context (vault-load wiring + `RecordFieldValue` shape) to either enforce by signature or cover by acceptance test.

### Decisions settled

- **Anti-oracle conflation preserved at the IPC seam.** Both `FfiVaultError::WrongPasswordOrCorrupt` and `FfiVaultError::WrongMnemonicOrCorrupt` collapse to `AppError::WrongPassword`. This is now pinned by `ffi_wrong_password_or_corrupt_collapses_to_wrong_password` so a future refactor that tries to split the variants for "better UX" will fail a test rather than slip through.
- **`detail` field policy on the IPC seam is unconditional.** Every variant that carries diagnostic context strips it on the wire via `#[serde(skip_serializing)]`; the detail is logged via `tracing::warn!` on the Rust side before stripping. `ffi_corrupt_vault_detail_is_logged_but_stripped_on_serialize` and `vault_corrupt_detail_is_stripped` pin both halves of the property.
- **`FolderInvalid` maps to the generic `Io` bucket in `From<FfiVaultError>`.** Task 4's command handlers, which know the user-picked path, will construct `VaultPathNotFound` / `VaultPathNotAVault` directly at the boundary (where the path is in scope) rather than reverse-engineering from a detail string. The `Io` fallback exists so that any pre-Task-4 code path that exposes `FolderInvalid` surfaces something coherent.

### Risks carried forward

- **Plan's gauntlet-count predictions for Tasks 3–5 should be re-validated.** Task 2 came in at **993** rather than the predicted **987** (+6 surplus tests, including +1 from the post-review fixup). Task 3 was predicted at 999 (assuming 987 + 12); the actual baseline is now 993 + ~12 = ~1005. Task 4 at 1002 → ~1008; Task 5 at 1005 → ~1011. If actual counts diverge further, the plan should grow a one-line note rather than the implementations being padded/trimmed to hit predictions.
- **`AppError::KdfTooWeak` has no producer.** It survives as a typed variant for the future where the bridge surfaces the structured `WeakKdfParams` payload, but today every "weak KDF" failure folds through the bridge's `CorruptVault { detail }`. The serde-shape test `kdf_too_weak_carries_payload` keeps the wire format pinned, so when the bridge eventually exposes the structured payload the desktop side will already be ready. Document in `From<FfiVaultError>` docstring (done).
- **`AppError::AlreadyUnlocked` / `AppError::NotUnlocked` have no producer in Task 2.** These are session-state errors — Task 3's `VaultSession::unlock` and `VaultSession::with_open_vault` produce them. The `#[allow(dead_code)]` on `AppError` covers them; the producer comment in the source names Task 4 (which is when the actual command handlers wrap them).

### Issues currently open (carry-over + new from PR #137 review)

- #37, #117, #120, #122, #123 — none affected by Task 2.
- #38, #45, #75, #76, #78, #79, #81, #87, #88, #90, #95, #98 — none affected.
- **#139** — desktop: `AppError` lacks `Deserialize`; revisit alongside Task 6 TS discriminated union.
- **#140** — desktop: `parse_settings_field` text-only invariant; resolve in Task 3 (signature change or acceptance test).

### Housekeeping (stale worktrees on disk)

Carry-over from the prior baton (`feature/d11-task-1` is now also resolved after PR #131 merged, and the worktree was removed at the top of this session). Remaining stale worktrees that can be removed at any pause:

```bash
# From /Users/hherb/src/secretary, after the present PR merges:
git worktree remove .worktrees/c1-1b-sync-merge   && git branch -D feature/c1-1b-task-17
git worktree remove .worktrees/c2-task-1-spec     && git branch -D feature/c2-task-1-spec
for n in 1 2 3 4 5 6 7 8 9 10; do
  git worktree remove .worktrees/c2-task-$n       && git branch -D feature/c2-task-$n
done
git worktree remove .worktrees/d11-tauri-spec     && git branch -D feature/d11-tauri-spec
# Keep .worktrees/d11-task-2 until this PR merges; remove after.
```

## (4) Exact commands to resume (Task 3)

```bash
# After this Task 2 PR (feature/d11-task-2) merges:
cd /Users/hherb/src/secretary
git fetch --prune origin
git status --short              # expect: clean
git checkout main
git pull --ff-only origin main

# Re-baseline the gauntlet on fresh main (expect 993 / 0 / 10):
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "PASSED:", passed, "FAILED:", failed, "IGNORED:", ignored}'

# Set up the Task 3 worktree:
git worktree add .worktrees/d11-task-3 -b feature/d11-task-3 main
cd .worktrees/d11-task-3

# Open the plan and follow Task 3 step-by-step:
#   docs/superpowers/plans/2026-05-27-d11-tauri-walking-skeleton.md
# Search for "## Task 3:" (line ~1500). Each step block is self-contained.

# After all wiring + ephemeral-vault integration tests pass:
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "PASSED:", passed, "FAILED:", failed, "IGNORED:", ignored}'
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all -- --check
uv run core/tests/python/conformance.py
uv run core/tests/python/spec_test_name_freshness.py
```

## Closing inventory

- **Branch state on close:** `main` at `e329087` (D.1.1 Task 1 PR #131 merged earlier this session). `feature/d11-task-2` carries 5 commits on top (4 module commits + 1 fmt fixup).
- **Workspace tests on `feature/d11-task-2`:** **993 passed + 10 ignored** (+33 over the post-Task-1 baseline of 960; includes +1 from the post-review fixup).
- **README.md:** unchanged. Per-task status flips on a sub-project in early implementation phase would be noise (see prior baton; same logic applies).
- **ROADMAP.md:** unchanged. D.1 section's wording ("D.1.1 walking skeleton ... in design.") remains brief and inoffensive; the per-task implementation status doesn't belong in the cross-sub-project roadmap.
- **CLAUDE.md:** unchanged this session.
- **NEXT_SESSION.md:** symlink retargeted to this file.
- **`docs/adr/`:** unchanged.
- **`desktop/src-tauri/src/`:** four new pure modules (`constants.rs`, `errors.rs`, `auto_lock.rs`, `settings.rs`) plus the `mod` declarations in `main.rs`. The `desktop/src/` (Svelte) tree is untouched in Task 2.
- **Open issues:** see §(3) — none close with this PR.
- **Open PRs:** one to be opened at end of this session (D.1.1 Task 2 — backend pure modules).
- **Worktrees on disk:** stale worktrees listed in §(3) can be cleaned up at any pause; `feature/d11-task-2` stays until merge.
- **This file:** the live baton for the Task 2 close. The next slice opens with `docs/handoffs/<date>-d11-task-3-shipped.md`.
