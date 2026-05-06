# NEXT_SESSION.md

**Session date:** 2026-05-06 (Sub-project B.4a — folder-based open_vault through FFI)
**Status:** Sub-project B.4a complete; PR pending merge. The folder-in vault open path is now exposed across PyO3 (Python) and uniffi (Swift / Kotlin) via the existing shared `secretary-ffi-bridge` crate. The FFI surface now has 7 user-facing entry points: bytes-in `open_with_password` / `open_with_recovery` / `create_vault`, folder-in `open_vault_with_password` / `open_vault_with_recovery`, plus the `add` / `version` smokes. Two error types: `FfiUnlockError` (5-variant, bytes-in unchanged) and `FfiVaultError` (6-variant, folder-in NEW; mirrors 5 unlock-class variants byte-identically + 1 new FolderInvalid). Two opaque handles return from open paths: `UnlockedIdentity` (re-used unchanged) and `OpenVaultManifest` (NEW; holds IBK + manifest + envelope + verified owner card internally for B.4b/c/d to extend).

## (1) What we shipped this session

| Task | Commit(s) | What landed |
|---|---|---|
| 1 — bridge FfiVaultError | `57dc201` | New 6-variant flat `FfiVaultError` enum in `ffi/secretary-ffi-bridge/src/error.rs`. `From<core::VaultError>` delegates unlock-class variants through a private `From<FfiUnlockError>` arm so future FfiUnlockError renames propagate automatically. All 6 Display strings verified against spec. Spec-review fix-up `d745f91` added before Task 2 per "fix spec-review issues before quality review". |
| 1 fix-up | `d745f91` | Doc comment fixes on `FfiVaultError` and its variants per code-quality review; no behaviour change. |
| 2 — bridge vault.rs | `7c71b15`, `00e783d` | New `ffi/secretary-ffi-bridge/src/vault.rs` with `open_vault_with_password`, `open_vault_with_recovery`, `OpenVaultOutput`, `OpenVaultManifest`, `BlockSummary` + 9 unit tests (round-trip with password, round-trip with recovery, wrong-password error mapping, folder-invalid error mapping, `block_summaries` matches pinned KAT from golden vaults, `find_block` found / not-found, `wipe` semantics, accessor after wipe panics). Fix-up commit `00e783d` pinned `Cargo.toml` comment, improved drop-order doc, and pinned `recipient_uuids` in the test KAT. |
| 2 fix-up | `00e783d` | Style fix-up: Cargo.toml comment correction, drop-order doc improvement, recipient_uuids KAT pin. |
| 3 — bridge lib.rs | `dc4c25b` | Re-exports `FfiVaultError`, `OpenVaultOutput`, `OpenVaultManifest`, `BlockSummary`, `open_vault_with_password`, `open_vault_with_recovery`; crate-doc updated to reflect 7-entry-point surface. |
| 4 — PyO3 wrapper | `2196c0e`, `555c94c` | `#[pyfunction] open_vault_with_password` and `open_vault_with_recovery`; 3 new `#[pyclass]` (`OpenVaultOutput`, `OpenVaultManifest`, `BlockSummary`); 6 `create_exception!` calls for `VaultFolderInvalid`, `VaultWrongPasswordOrCorrupt`, `VaultWeakKdf`, `VaultIdentityExpired`, `VaultStorageError`, `VaultUnexpected`. Fix-up `555c94c` corrected `detail` field name consistency in `ffi_vault_error_to_pyerr`. |
| 4 fix-up | `555c94c` | Style fix-up: `detail` field name consistency in `ffi_vault_error_to_pyerr` mapping arms. |
| 5 — pytest | `f68bc01` | +7 tests: `test_open_vault_shape`, `test_open_vault_block_summaries`, `test_open_vault_find_block`, `test_open_vault_block_count`, `test_open_vault_wipe`, `test_open_vault_wrong_password_error`, `test_open_vault_folder_invalid_error`; module-scoped `opened_vault` fixture amortizes Argon2id cost. |
| 6 — UDL + uniffi glue | `63c555a` | UDL gains 2 `dictionary` types (`OpenVaultOutput`, `BlockSummary`) + 1 `interface` (`OpenVaultManifest`) + 1 `[Error]` enum (`VaultError`) + 2 namespace fns (`open_vault_with_password`, `open_vault_with_recovery`); uniffi-side wrapper structs with `Arc<Interface>`; +2 mapping/integration tests. |
| 7 — Swift + Kotlin smoke | `17ec4b9` | +3 asserts each (shape: vault_uuid + block_count non-empty, block_summaries round-trip, find_block found + not-found); unified into existing golden vault fixture. |
| 8 — READMEs + ROADMAP | `d2ac3ec` | Bridge / py / uniffi crate READMEs gain B.4a sections; top-level README progress bar advanced + status table B.4a row flipped ⏳ → ✅; ROADMAP B.4a entry flipped + status paragraph extended. |
| 9 — NEXT_SESSION + handoff | (this commit) | This file + `docs/handoffs/2026-05-06-b4a-open-vault.md`. |

### Verification at session close

| Check | Result |
|---|---|
| `cargo test --release --workspace` | **520 passed + 9 ignored, 0 failed** (was 498 + 9 at branch start; +22 from B.4a cumulative: +18 in the bridge crate, +2 in uniffi from Task 6, +2 in uniffi regression tests for the zeroize fix-up `cc8bcba`) |
| `cargo clippy --release --workspace -- -D warnings` | clean |
| `cargo fmt --all -- --check` | OK |
| `uv run --directory ffi/secretary-ffi-py pytest` | **29 passed** (was 22 — added 7 B.4a tests) |
| `uv run core/tests/python/conformance.py` | **PASS** |
| `uv run core/tests/python/spec_test_name_freshness.py` | **PASS** |
| `bash ffi/secretary-ffi-uniffi/tests/swift/run.sh` | **18/18 PASS** (was 15/15 — added 3 B.4a asserts) |
| `bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh` | **19 PASS lines** (was 16 PASS lines — added 3 B.4a asserts) |

### Per-crate breakdown of the 518-test workspace

- `secretary-core` — 448 (unchanged; +9 ignored)
- `secretary-ffi-bridge` — **54** (was 36; +18 net: +9 unit tests in new `vault.rs` + error and vault type coverage)
- `secretary-ffi-py` — 3 (unchanged Rust unit tests; the 29 pytest count is separate)
- `secretary-ffi-uniffi` — **13** (was 11; +2 mapping/integration tests from Task 6)

### Two-stage review caught real bugs (and confirmed real wins) — same shape as B.3a / B.3b

The subagent-driven-development workflow's two-stage review (spec compliance → code quality) drove fix-up commits across the implementation tasks. Concrete examples:

- **Task 1** (bridge FfiVaultError): Spec compliance review confirmed the `From<FfiUnlockError>` delegation arm correctly propagates all 5 unlock-class variant names without manual duplication; code quality review tightened doc comments in fix-up `d745f91`.
- **Task 2** (bridge vault.rs): Code quality review flagged the `Cargo.toml` comment wording and the drop-order doc accuracy; corrected in `00e783d`. The `recipient_uuids` KAT pin was also tightened to a concrete expected value rather than a length check.
- **Task 4** (PyO3 wrapper): Code quality review caught inconsistent `detail` field name in `ffi_vault_error_to_pyerr` mapping arms; corrected in `555c94c` before pytest was added.
- **Tasks 7** (Swift/Kotlin smoke): Plan's UDL type projections aligned without mismatches — the B.3b lessons about `Data` vs `[UInt8]` and `ULong` vs `Long` carried forward correctly.

The user's "fix every review issue before merging — no technical debt" preference held throughout. No issues filed for follow-up; everything in scope landed before the doc commit.

## (2) What's next

With B.4a done, the folder-based vault-open path is exposed at the FFI. The next step is B.4b — reading individual encrypted blocks from an open vault. Before writing a spec or plan for B.4b, a brainstorm session (via the `/brainstorm` skill) should resolve the following open design questions:

- **Record type FFI projection.** How do `Record` / `RecordField` / `RecordFieldValue` (which use `SecretString` / `SecretBytes` zeroize-typed wrappers in Rust) project to Python `dataclass` / Swift `struct` / Kotlin `data class` while preserving zeroize-discipline on the foreign-language side? The "bytes not strings" discipline established in B.2 applies but record types are structurally recursive.
- **Read-block API shape.** Does `read_block(block_uuid)` consume the `OpenVaultManifest` (one-shot access, simplest ownership) or take it by reference (allows multi-block sequential reads)? The `Mutex<Option<T>>` pattern enables both; the ergonomic tradeoff needs a decision before the UDL is written.
- **Error variant for block-not-found.** Should `FfiVaultError` gain a 7th variant `BlockNotFound { uuid }`, or is "block UUID not found" folded into `CorruptVault` (vault integrity failure) or kept as a distinct `BlockNotFound` without growing the error enum? The B.3b pattern was "5-variant, add a 6th only when the user action is genuinely different"; `BlockNotFound` is arguably a different user action (retry / re-sync vs. re-open).
- **Trash entries.** Still deferred to Sub-project C (sync) or surface in B.4b with a soft-delete flag on `BlockSummary`?

The deferred-items section in [docs/superpowers/specs/2026-05-06-ffi-b4a-open-vault-design.md](docs/superpowers/specs/2026-05-06-ffi-b4a-open-vault-design.md) "Non-goals (YAGNI)" carries the carry-over context — read it before requesting the brainstorming skill.

## (3) Open decisions and risks

### Decisions made and load-bearing for future sub-projects

These are the B.4a decisions that constrain subsequent FFI work (B.4b/c/d):

1. **Folder-IO ownership at the FFI established.** Rust core owns all reads and atomic writes through `secretary_core::vault`. Foreign callers pass a folder path string; the bridge translates to `PathBuf` and calls core. No foreign-side file I/O is ever expected.
2. **Two-handle output struct pattern.** `OpenVaultOutput { identity: UnlockedIdentity, manifest: OpenVaultManifest }` gives the caller two independently-lifetimed opaque handles. Identity handle follows the existing B.2/B.3a pattern; manifest handle is new for B.4a. B.4b will extend the manifest handle's accessor surface without changing the output struct shape.
3. **FfiVaultError 6-variant flat enum.** Mirrors `FfiUnlockError`'s 5 unlock-class variants byte-identically (same variant names + same Display strings) plus 1 new `FolderInvalid { detail }`. The private `From<FfiUnlockError>` delegation arm prevents unlock-class variant drift if `FfiUnlockError` is ever renamed. B.4b may grow this to 7 variants if `BlockNotFound` is approved in the design brainstorm.
4. **OpenVaultManifest holds IBK + manifest + envelope + owner card internally.** All four are stored in the `Mutex<Option<T>>` newtype so B.4b can call `read_block` without re-opening the vault. B.4b extends with `read_block`; B.4c with `save_block` (mutation question still open — does saving a block require a new `OpenVaultManifest` constructor or a `&mut self` method?); B.4d with `share_block` (ContactCard surface).
5. **`local_highest_clock` / rollback deferred to Sub-project C.** Both `open_vault_with_*` functions return `local_highest_clock: None` unconditionally. Sub-project C's sync orchestration layer will compute and act on the rollback signal; the FFI entry points should not change shape when that is implemented — only the `None` becomes `Some(u64)`.
6. **Owner contact card not exposed.** `OpenVaultManifest` holds the verified owner contact card internally (used during manifest authentication) but does not expose it through any accessor. Accessor exposure is deferred to B.4d (sharing primitives / ContactCard surface).

### Risks for future work

- **`BlockSummary.recipient_uuids` is the first multi-valued field in any FFI value type.** Swift projects it as `[String]`, Kotlin as `List<String>`. If B.4b adds block content, any field carrying `SecretBytes` will need the same careful bytes-vs-array treatment as mnemonic phrase bytes in B.3b.
- **`OpenVaultManifest` wipe-then-access panic semantics.** The `Mutex<Option<T>>` newtype panics on access after `wipe()`. This is intentional and documented, but B.4b tests must cover the after-wipe error path via Python `RuntimeError` / Swift/Kotlin exception — not a crash.
- **Maturin/uv cache stickiness** is well-documented in [`ffi/secretary-ffi-py/README.md`](ffi/secretary-ffi-py/README.md) and the project memory; expect to apply the documented nuclear fix after any branch-switch / squash-merge that touches PyO3 surface.

### Pre-existing technical debt

None outstanding from B.4a.

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary
git checkout main
git pull --ff-only

# Verify the post-merge state on main:
cargo test --release --workspace 2>&1 | grep -E "^test result:" | python3 -c "
import sys, re
p=f=i=0
for line in sys.stdin:
    m = re.search(r'(\d+) passed.*?(\d+) failed.*?(\d+) ignored', line)
    if m: p+=int(m.group(1)); f+=int(m.group(2)); i+=int(m.group(3))
print(f'TOTAL: {p} passed; {f} failed; {i} ignored')"
cargo clippy --release --workspace -- -D warnings && echo "clippy OK"
cargo fmt --all -- --check && echo "fmt OK"

# IMPORTANT: re-build the maturin dylib BEFORE pytest. Post-merge cache
# stickiness (documented in ffi/secretary-ffi-py/README.md) often
# manifests as `module 'secretary_ffi_py' has no attribute 'open_vault_with_password'`.
# If `maturin develop` alone doesn't pick up the new symbols, apply the
# nuclear fix:
#   rm -rf ffi/secretary-ffi-py/.venv
#   find ~/.cache/uv -name "*secretary*" -exec rm -rf {} +
#   uv sync --directory ffi/secretary-ffi-py
( cd ffi/secretary-ffi-py && uv run maturin develop --release --uv )

uv run --directory ffi/secretary-ffi-py pytest
uv run core/tests/python/conformance.py
uv run core/tests/python/spec_test_name_freshness.py
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh

# Expected: 520 passed + 9 ignored cargo; clippy clean; fmt OK; 29 pytest;
# PASS conformance + freshness; 18/18 Swift; 19 Kotlin PASS lines.

# Begin Sub-project B.4b:
# 1. Run the brainstorming skill first to resolve the 4 open design questions
#    listed in section (2) above (record type FFI projection, read-block API
#    shape, BlockNotFound error variant, trash entries).
# 2. After brainstorm resolves the questions, use the writing-plans skill to
#    produce docs/superpowers/specs/2026-05-XX-ffi-b4b-read-block-design.md.
# 3. Then use the writing-plans skill to produce the implementation plan.
```

---

## Closing inventory

- **Branch:** `feat/ffi-b4a-open-vault` (open PR; pending squash-merge to `main`)
- **Total commits since branching from `main@85c95b4`:** 11 on the feature branch (8 task implementations + 2 review/style fix-ups + 1 doc/handoff). PR to be squash-merged.
- **Workspace tests:** 520 + 9 ignored
- **Pytest:** 29 (22 from B.1 + B.2 + B.3a + B.3b + 7 B.4a)
- **Swift smoke:** 18/18 (15 from prior + 3 B.4a)
- **Kotlin smoke:** 19 PASS lines (16 from prior + 3 B.4a)
- **Bridge crate:** 54 unit tests (was 36; +18 net)
- **uniffi crate:** 15 unit tests (was 11; +2 net from Task 6 + 2 regression tests added in `cc8bcba` for the zeroize-on-invalid-UTF-8-folder-path fix)
- **PR:** [#28](https://github.com/hherb/secretary/pull/28) — open, pending squash-merge to `main`.
