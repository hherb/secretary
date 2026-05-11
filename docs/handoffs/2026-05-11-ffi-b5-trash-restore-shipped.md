# NEXT_SESSION.md

**Session date:** 2026-05-11 (B.5 implementation — full trash + restore lifecycle pair shipped end-to-end on `feat/ffi-b5-trash-restore-block`)
**Status:** B.5 complete across all 4 layers (core → bridge → PyO3 → uniffi) with Swift + Kotlin smoke runner additions. README + ROADMAP updated; ready to open PR.

## (1) What we shipped this session

Nine commits on `feat/ffi-b5-trash-restore-block`:

| Commit | Type | What landed |
|---|---|---|
| `e8c2103` | feat(ffi-b5) | Atomic addition of 3 new `core::vault::VaultError` variants (`BlockUuidAlreadyLive`, `BlockNotInTrash`, `RestoreVerificationFailed`) across all 4 layers. The plan's `format!("{block_uuid:?}")` rendering was corrected to `hex::encode(block_uuid)` mid-task because the original tests asserted `detail.contains("aa")` — the decimal Debug format does not satisfy that. +5 bridge pin tests, +4 uniffi pin tests, +2 pyo3 exception classes. Issue #40 tripwire fired as designed (compile errors at 3 mapper sites). |
| `eba7a1b` | feat(core-b5) | `core::vault::trash_block` orchestrator + §7 filename grammar tightening. Block file is moved `blocks/<uuid>.cbor.enc` → `trash/<uuid>.cbor.enc.<now_ms>` via `rename(2)`; `BlockEntry` is dropped, `TrashEntry` is appended, manifest is re-signed. Per-block vector clock is preserved (block content unchanged); only the manifest-level vector clock ticks. **Plan deviation: tests landed as integration tests in `core/tests/trash_restore.rs` rather than inline unit tests in `orchestrators.rs`** — the inline approach would have duplicated ~150 LOC of `make_fast_vault` machinery and `orchestrators.rs` is already well past the 500-LOC threshold. The deviation is documented in the file header. +4 integration tests. |
| `72e6f84` | feat(core-b5) | `core::vault::restore_block` orchestrator + §7.1 spec section. Reads the largest-timestamp file in `trash/`, full-decrypts and hybrid-verifies (defense in depth against forged trash files), resolves `recipient_fingerprint` → `contact_uuid` by scanning `contacts/*.card`, renames trash → blocks, purges older trashed copies best-effort, and re-signs the manifest. Block-level vector clock is preserved verbatim from the file header for sync correctness — restore is a continuation, not a fork. +7 integration tests, +1 proptest (16 cases). |
| `fcf9696` | feat(ffi-b5) | `bridge::trash_block` free-function entry point. Mirrors `bridge::share_block` pattern: snapshots manifest + identity under single locks, builds temporary `OpenVault`, calls `core::vault::trash_block`, writes back via `replace_manifest_and_file`. Failure leaves bridge handle byte-identical to pre-call. +4 unit mapper tests, +3 integration tests. |
| `ffa41f2` | feat(ffi-b5) | `bridge::restore_block` free-function entry point. Richer error mapper than trash: 2 typed FFI variants for the trash-side rejections (`BlockUuidAlreadyLive`, `BlockNotInTrash`), `RestoreVerificationFailed` folded to `CorruptVault`, `MissingRecipientCard` routed through. +5 unit mapper tests, +3 integration tests (round-trip, live-collision, tampered-file → `CorruptVault`). |
| `96ac296` | feat(ffi-b5) | PyO3 `trash_block` + `restore_block` pyfunctions. Two new `#[pyfunction]`s in `src/trash.rs` + `src/restore.rs` (each its own file to mirror `save.rs` / `share.rs` layout) wrapping the bridge entry points. UUID length validation surfaces `ValueError`; `FfiVaultError` routes through `ffi_vault_error_to_pyerr`. +11 pytest cases covering happy path, BlockNotFound, wrong-length UUID + device_uuid validation, BlockUuidAlreadyLive, BlockNotInTrash, CorruptVault on tampered file, fingerprint preservation, multi-copy purge, and persistence across reopen. |
| `f8e0e44` | feat(ffi-b5) | uniffi `trash_block` + `restore_block` namespace fns. Two new `[Throws=VaultError]` UDL declarations + Rust glue in `namespace.rs`. Length-validates `block_uuid` and `device_uuid` at the namespace boundary (wrong length surfaces as `VaultError::InvalidArgument`). uniffi-bindgen now produces Swift / Kotlin surface for the new `BlockUuidAlreadyLive` and `BlockNotInTrash` variants. |
| `46974e8` | test(ffi-b5) | Swift + Kotlin smoke runners cover trash + restore. +4 Swift asserts (30 → 34) and +4 Kotlin asserts (31 → 35) covering: trash + restore round-trip with record preservation, `BlockNotFound` for `trash_block(unknown_uuid)`, `BlockNotInTrash` for `restore_block(never-trashed)`, and `BlockUuidAlreadyLive` after re-saving at a previously-trashed UUID. |

### Verification at session close

| Check | Result |
|---|---|
| `cargo test --release --workspace --no-fail-fast` | **639 passed + 9 ignored, 0 failed** (was 603 baseline; +36 net). |
| `cargo clippy --release --workspace -- -D warnings` | clean. |
| `cargo fmt --all -- --check` | OK. |
| `uv run core/tests/python/conformance.py` | PASS. |
| `uv run core/tests/python/spec_test_name_freshness.py` | PASS. |
| `uv run --directory ffi/secretary-ffi-py pytest` | **68 passed** (was 57; +11). |
| `ffi/secretary-ffi-uniffi/tests/swift/run.sh` | **34/34 PASS** (was 30; +4). |
| `ffi/secretary-ffi-uniffi/tests/kotlin/run.sh` | **35/35 PASS** (was 31; +4). |

All plan §9 acceptance criteria met or exceeded (plan expected 630-635 cargo / 67 pytest; we have 639 / 68 — the deltas come from a couple of extra defensive mapper-pin tests added during execution).

## (2) What's next — open the B.5 PR + post-merge cleanups

### Immediate next step

**Open the PR for `feat/ffi-b5-trash-restore-block` → `main`.** Body should reference the spec + plan paths and call out the two plan deviations (no-inline-unit-tests; hex-encoded UUIDs in error mappers). Acceptance criteria are the test-count deltas above.

### Post-merge cleanup candidates (none blocking)

- **Issue #44 (`error/vault.rs` 500-line policy)** — the file grew another ~70 LOC in Task 1 (3 new `From` arms + 5 new pin tests + 2 new variants + their doc comments). Per the file-split memory and the B.4d posture, the per-variant explicit matching is intrinsic; splitting tests would over-deepen the directory. Worth a one-pass evaluation after B.5 lands.
- **Stale `signer_secret_keys()` accessor on `UnlockedIdentity`** (carried forward from PR #46) — still has `#[allow(dead_code)]`; no caller after PR #46's #42 fix. *No GitHub issue filed yet.*
- **Issue #38** — proptest case budget. B.5 adds a third 16-case proptest (`trash_restore_round_trip_preserves_block_fingerprint`); the umbrella fix (shared writable-vault fixture amortized across cases) waits for Sub-project C infrastructure.
- **`.claude/worktrees/` directory still untracked** — from a prior session's `chore+b4d-deferred-cleanup`. Safe to leave or `rm -rf`.

### Sub-project decisions left explicit (settled this session)

- **No-inline-unit-tests deviation** documented in `core/tests/trash_restore.rs` file header — the future expectation is that any new orchestrator-level tests follow the integration-test pattern, not the inline pattern.
- **Hex-encoded UUIDs** in the new `FfiVaultError::BlockUuidAlreadyLive` / `BlockNotInTrash` `detail` field — chosen for parity with the existing `BlockNotFound { uuid_hex }` rendering.
- **`RestoreVerificationFailed` folds to `CorruptVault`** at every layer that maps `core::VaultError → FfiVaultError`. This is the "data on disk doesn't match what we signed" contract.

## (3) Open decisions and risks

### Risks for the PR review

- **B.5 plan deviation:** the plan called for "+3 inline unit tests in `orchestrators.rs::tests` per sub-orchestrator" but I lowered that to "+0 inline; all coverage as integration tests" because `orchestrators.rs` is already past the 500-line threshold and the integration-test pattern (a la `tests/save_block.rs` / `tests/share_block.rs`) does the same job without file bloat. The deviation is called out in the commit message and the test-file header. Reviewer may push back; rationale is documented.
- **B.5 plan deviation:** the plan's `format!("{block_uuid:?}")` in the `From<core::VaultError>` mapper would have produced decimal-debug strings (`"[170, 170, ...]"`) that the plan's own tests asserted-against with `detail.contains("aa")`. Switched to `hex::encode(block_uuid)` to (a) match the existing `BlockNotFound { uuid_hex }` precedent and (b) satisfy the plan's tests as written. Documented in the Task 1 commit message.
- **restore_block's owner-as-sender assumption:** the decrypt call uses the owner card's public keys as the sender for hybrid-verify. In v1 the owner is always the block author, so this is correct. If `share_block` is ever extended to share-as-fork (lifting the author == owner precondition), `restore_block` needs the matching author-card lookup.

### Issues still open from prior sessions

- **Issue #37** — design discipline reminder for Sub-project C (preserve the manifest-only-read invariant for the sync layer).
- **Issue #38** — proptest case budget (shared writable-vault fixture).
- **Issue #44** — `error/vault.rs` 500-line policy threshold.
- **Issue #45** — three `pub(crate) #[allow(dead_code)]` accessors on `OpenVaultManifest` (forward-compat for Sub-project C).

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary
git checkout feat/ffi-b5-trash-restore-block
git status --short                                     # expect: clean (or just .claude/worktrees/ untracked)
git log --oneline -11
# Expect the 9 B.5 implementation commits + the 2 prior session commits:
#   46974e8 test(ffi-b5): Swift + Kotlin smoke runners cover trash + restore
#   f8e0e44 feat(ffi-b5): uniffi trash_block + restore_block namespace fns
#   96ac296 feat(ffi-b5): PyO3 trash_block + restore_block pyfunctions
#   ffa41f2 feat(ffi-b5): bridge::restore_block free-function entry point
#   fcf9696 feat(ffi-b5): bridge::trash_block free-function entry point
#   72e6f84 feat(core-b5): restore_block orchestrator + §7.1 spec section
#   eba7a1b feat(core-b5): trash_block orchestrator + §7 filename grammar tightening
#   e8c2103 feat(ffi-b5): atomic addition of trash/restore error variants across all 4 layers
#   2a38ffa docs(b5): NEXT_SESSION baton + handoff for design-and-plan session
#   4b828bf chore: salvage prior session's verification handoff onto B.5 branch
#   2278439 plan(ffi-b5): step-by-step implementation plan for trash_block / restore_block

# Verification gauntlet — should match this session's closing numbers exactly:
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | python3 -c "
import sys, re
p=f=i=0
for line in sys.stdin:
    m = re.search(r'(\d+) passed.*?(\d+) failed.*?(\d+) ignored', line)
    if m: p+=int(m.group(1)); f+=int(m.group(2)); i+=int(m.group(3))
print(f'TOTAL: {p} passed; {f} failed; {i} ignored')"
# Expect: TOTAL: 639 passed; 0 failed; 9 ignored

cargo clippy --release --workspace -- -D warnings      # Expect: clean
cargo fmt --all -- --check                              # Expect: OK
uv run core/tests/python/conformance.py                 # Expect: PASS
uv run core/tests/python/spec_test_name_freshness.py    # Expect: PASS

# PyO3 wheel + pytest:
(cd ffi/secretary-ffi-py && uv run maturin develop --release --uv && .venv/bin/python -m pytest)
# Expect: 68 passed

# Swift + Kotlin smoke runners:
ffi/secretary-ffi-uniffi/tests/swift/run.sh             # Expect: 34/34 PASS
ffi/secretary-ffi-uniffi/tests/kotlin/run.sh            # Expect: 35/35 PASS

# Open the PR:
gh pr create --base main --head feat/ffi-b5-trash-restore-block \
    --title "feat(b5): block trash + restore lifecycle pair across all 4 FFI layers" \
    --body "$(cat <<'EOF'
## Summary

Implements the full B.5 block-lifecycle pair — `trash_block` and `restore_block` — end-to-end through `secretary-core` (orchestrators + §7 / §7.1 spec), `secretary-ffi-bridge`, `secretary-ffi-py` (PyO3), and `secretary-ffi-uniffi` (Swift + Kotlin).

- 2 new core orchestrators: `core::vault::trash_block` and `core::vault::restore_block`. The restore side reads the largest-timestamp file in `trash/`, fully decrypts and hybrid-verifies it (defense in depth against forged trash files), resolves `recipient_fingerprint` → `contact_uuid` via `contacts/*.card` scan, renames trash → blocks, purges older copies best-effort, and re-signs the manifest. Block-level vector clock is preserved verbatim for sync correctness.
- `FfiVaultError` grows 13 → 15 variants: 2 typed restore-side variants (`BlockUuidAlreadyLive`, `BlockNotInTrash`). `RestoreVerificationFailed` folds to `CorruptVault` per the "data on disk doesn't match what we signed" contract.
- New `docs/vault-format.md` §7.1 normative sequence + §7 filename grammar tightening.

## Test plan

- [x] `cargo test --release --workspace --no-fail-fast` — 639 passed + 9 ignored (was 603; +36)
- [x] `cargo clippy --release --workspace -- -D warnings` — clean
- [x] `cargo fmt --all -- --check` — OK
- [x] `uv run core/tests/python/conformance.py` — PASS
- [x] `uv run core/tests/python/spec_test_name_freshness.py` — PASS
- [x] `uv run --directory ffi/secretary-ffi-py pytest` — 68 passed (was 57; +11)
- [x] `ffi/secretary-ffi-uniffi/tests/swift/run.sh` — 34/34 PASS (was 30; +4)
- [x] `ffi/secretary-ffi-uniffi/tests/kotlin/run.sh` — 35/35 PASS (was 31; +4)

Plan deviations called out in commit messages:
- Test layout: inline unit tests in `orchestrators.rs::tests` lowered to "all coverage as integration tests in `core/tests/trash_restore.rs`" to avoid file-bloat past the 500-LOC threshold.
- Mapper rendering: `format!("{block_uuid:?}")` corrected to `hex::encode(block_uuid)` for parity with `BlockNotFound { uuid_hex }`.

Spec: docs/superpowers/specs/2026-05-11-ffi-b5-trash-restore-block-design.md
Plan: docs/superpowers/plans/2026-05-11-ffi-b5-trash-restore-block.md

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Closing inventory

- **Branch:** `feat/ffi-b5-trash-restore-block` (11 commits ahead of main).
- **Total commits this session:** 9 (`e8c2103`, `eba7a1b`, `72e6f84`, `fcf9696`, `ffa41f2`, `96ac296`, `f8e0e44`, `46974e8`, and this NEXT_SESSION + handoff commit when it lands).
- **Workspace tests:** 639 cargo + 9 ignored (up from 603), 68 pytest (up from 57), Swift 34/34 (up from 30), Kotlin 35/35 (up from 31).
- **README:** updated (status line, B.5 row, test counts).
- **ROADMAP:** updated (status bar, B.5 entry with full narrative, test counts; old "B.5 — Conformance" placeholder moved to B.6).
- **Files modified:** [`README.md`](README.md), [`ROADMAP.md`](ROADMAP.md), [`NEXT_SESSION.md`](NEXT_SESSION.md) (this file), [`core/src/vault/mod.rs`](core/src/vault/mod.rs), [`core/src/vault/orchestrators.rs`](core/src/vault/orchestrators.rs), [`docs/vault-format.md`](docs/vault-format.md), [`ffi/secretary-ffi-bridge/src/error/vault.rs`](ffi/secretary-ffi-bridge/src/error/vault.rs), [`ffi/secretary-ffi-bridge/src/save/orchestration.rs`](ffi/secretary-ffi-bridge/src/save/orchestration.rs), [`ffi/secretary-ffi-bridge/src/share/orchestration.rs`](ffi/secretary-ffi-bridge/src/share/orchestration.rs), [`ffi/secretary-ffi-bridge/src/lib.rs`](ffi/secretary-ffi-bridge/src/lib.rs), [`ffi/secretary-ffi-uniffi/src/secretary.udl`](ffi/secretary-ffi-uniffi/src/secretary.udl), [`ffi/secretary-ffi-uniffi/src/errors.rs`](ffi/secretary-ffi-uniffi/src/errors.rs), [`ffi/secretary-ffi-uniffi/src/namespace.rs`](ffi/secretary-ffi-uniffi/src/namespace.rs), [`ffi/secretary-ffi-uniffi/src/lib.rs`](ffi/secretary-ffi-uniffi/src/lib.rs), [`ffi/secretary-ffi-uniffi/tests/swift/main.swift`](ffi/secretary-ffi-uniffi/tests/swift/main.swift), [`ffi/secretary-ffi-uniffi/tests/kotlin/Main.kt`](ffi/secretary-ffi-uniffi/tests/kotlin/Main.kt), [`ffi/secretary-ffi-py/src/lib.rs`](ffi/secretary-ffi-py/src/lib.rs), [`ffi/secretary-ffi-py/src/errors.rs`](ffi/secretary-ffi-py/src/errors.rs).
- **Files created:** [`core/tests/trash_restore.rs`](core/tests/trash_restore.rs), [`core/tests/trash_restore_proptest.rs`](core/tests/trash_restore_proptest.rs), [`ffi/secretary-ffi-bridge/src/trash/mod.rs`](ffi/secretary-ffi-bridge/src/trash/mod.rs), [`ffi/secretary-ffi-bridge/src/trash/orchestration.rs`](ffi/secretary-ffi-bridge/src/trash/orchestration.rs), [`ffi/secretary-ffi-bridge/src/restore/mod.rs`](ffi/secretary-ffi-bridge/src/restore/mod.rs), [`ffi/secretary-ffi-bridge/src/restore/orchestration.rs`](ffi/secretary-ffi-bridge/src/restore/orchestration.rs), [`ffi/secretary-ffi-bridge/tests/trash_block.rs`](ffi/secretary-ffi-bridge/tests/trash_block.rs), [`ffi/secretary-ffi-bridge/tests/restore_block.rs`](ffi/secretary-ffi-bridge/tests/restore_block.rs), [`ffi/secretary-ffi-py/src/trash.rs`](ffi/secretary-ffi-py/src/trash.rs), [`ffi/secretary-ffi-py/src/restore.rs`](ffi/secretary-ffi-py/src/restore.rs), [`ffi/secretary-ffi-py/tests/test_trash_restore.py`](ffi/secretary-ffi-py/tests/test_trash_restore.py), [`docs/handoffs/2026-05-11-ffi-b5-trash-restore-shipped.md`](docs/handoffs/2026-05-11-ffi-b5-trash-restore-shipped.md) (this file's frozen archive).
