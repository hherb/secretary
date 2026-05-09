# NEXT_SESSION.md

**Session date:** 2026-05-09 (Sub-project B.4b — design spec)
**Status:** B.4b design approved + committed to `main`. Implementation plan + code pending. The spec resolves all four open design questions from the post-B.4a baton (record-type FFI projection, read-block API shape, BlockNotFound error variant, trash entries) and adds one defense-in-depth fuzz-target item that's in scope for the implementation. Workspace state on `main` is unchanged from B.4a's post-merge baseline (522 + 9 cargo, 30 pytest, 18/18 Swift, 19 Kotlin).

## (1) What we shipped this session

| Task | Commit(s) | What landed |
|---|---|---|
| Brainstorm + design (B.4b spec) | `3093782` | New `docs/superpowers/specs/2026-05-09-ffi-b4b-read-block-design.md` (623 lines). Resolves the four NEXT_SESSION-baton open questions: (1) Hybrid Record projection — value-type metadata + opaque `FieldHandle` for secret payloads with explicit `expose_text()` / `expose_bytes()` boundary; (2) Free-function `bridge::read_block(&identity, &manifest, &[u8; 16])` shape (matches "free functions in reusable modules" preference); (3) 7-variant `FfiVaultError` with new `BlockNotFound { uuid_hex }`; decrypt + file-missing fold into `CorruptVault`; (4) Trash deferred to Sub-project C — `block_summaries()` filters trashed; `read_block(trashed_uuid)` returns `BlockNotFound`. Plus settled follow-ups: `OpenVaultManifestInner` gains `vault_folder: PathBuf` (bridge-internal, no B.4a public surface change); wrong-length-UUID raises `ValueError` / `IllegalArgumentException` (anti-conflation); `Record.unknown` / `RecordField.unknown` not surfaced; `Record.tombstone: bool` IS surfaced, `tombstoned_at_ms` is NOT; single-author-only block reading (multi-author deferred to B.4d). One in-scope hardening: extend `core/fuzz/fuzz_targets/record.rs` with a defense-in-depth Text-field UTF-8-validity assertion (rejects the alternative of surfacing a yet-another error variant on `expose_text`). |
| ROADMAP refresh | `fc7e35d` | B.4b roadmap entry rewritten from the placeholder "main open design question" framing to a concrete summary of the resolved spec; added spec link. README unchanged (no test count / status changes). |
| NEXT_SESSION + handoff | (this commit) | This file + `docs/handoffs/2026-05-09-b4b-spec.md`. |

### Verification at session close (no code changes; baseline check only)

| Check | Result |
|---|---|
| `cargo test --release --workspace` | **522 passed + 9 ignored, 0 failed** (unchanged from B.4a post-merge) |
| `cargo clippy --release --workspace -- -D warnings` | clean |
| `cargo fmt --all -- --check` | OK |
| `uv run --directory ffi/secretary-ffi-py pytest` | **30 passed** (after applying the documented nuclear cache fix at session start) |
| `uv run core/tests/python/conformance.py` | PASS |
| `uv run core/tests/python/spec_test_name_freshness.py` | PASS |
| Swift smoke | 18/18 PASS |
| Kotlin smoke | 19 PASS lines |

(Per `feedback_python_uv` + the documented maturin/uv cache stickiness, the post-merge `pytest` invocation needs `rm -rf ffi/secretary-ffi-py/.venv && find ~/.cache/uv -name "*secretary*" -exec rm -rf {} + && uv sync --directory ffi/secretary-ffi-py && (cd ffi/secretary-ffi-py && uv run maturin develop --release --uv)` before pytest sees the new symbols. Already applied this session.)

## (2) What's next

The B.4b spec is approved. The next step is to **write the implementation plan** with the `superpowers:writing-plans` skill, then execute the plan with the `superpowers:subagent-driven-development` skill (same workflow as B.4a).

### Concrete acceptance criteria for B.4b implementation

| Gate | Target |
|---|---|
| `cargo test --release --workspace` | **535+ passed + 9 ignored** (was 522 + 9; +12-14 new bridge-crate unit tests in `record.rs`) |
| `cargo clippy --release --workspace -- -D warnings` | clean |
| `cargo fmt --all -- --check` | OK |
| `uv run --directory ffi/secretary-ffi-py pytest` | **40 passed** (was 30; +10 B.4b tests) |
| Swift smoke | **22/22 PASS** (was 18/18; +4 B.4b asserts) |
| Kotlin smoke | **23 PASS lines** (was 19; +4 B.4b asserts) |
| `uv run core/tests/python/conformance.py` | PASS unchanged |
| `uv run core/tests/python/spec_test_name_freshness.py` | PASS unchanged |
| `cargo fuzz run record -- -runs=10000` (nightly; from `core/fuzz/`) | clean — no UTF-8-validity assertion failures |

### Implementation task breakdown (rough — the writing-plans pass will refine)

1. Bridge crate: extend `OpenVaultManifestInner` with `vault_folder: PathBuf`; thread it through `open_vault_with_password` / `open_vault_with_recovery` constructors. No public accessor change.
2. Bridge crate: add 7th `FfiVaultError::BlockNotFound { uuid_hex }`; extend `From<core::VaultError>` mapping (file-missing → `CorruptVault`; decrypt failures → `CorruptVault`); add tripwire test for new variant's Display string.
3. Bridge crate: NEW `ffi/secretary-ffi-bridge/src/record.rs` — `read_block` free fn + `BlockReadOutput` + `Record` + `FieldHandle` + 12-14 unit tests pinned against `golden_vault_001_inputs.json::block_plaintext`.
4. Bridge crate: `lib.rs` re-exports + crate-doc update (7 → 8 entry points).
5. Fuzz harness: extend `core/fuzz/fuzz_targets/record.rs` with the defense-in-depth UTF-8 assertion on `RecordFieldValue::Text` after successful decode; smoke-run with `-runs=10000` on nightly.
6. PyO3 wrapper: `#[pyfunction] read_block`; 3 `#[pyclass]` (`BlockReadOutput`, `Record`, `FieldHandle`) with `__enter__`/`__exit__`; `create_exception!(VaultBlockNotFound)`; 7th arm in `ffi_vault_error_to_pyerr`.
7. pytest: +10 tests covering shape, metadata, text-payload, bytes/text discrimination, BlockNotFound, ValueError on wrong-length UUID, context-manager wipe, Arc-clone wipe sharing.
8. uniffi UDL + bridge crate impl: 1 namespace fn (`read_block`); 3 interfaces (`BlockReadOutput`, `Record`, `FieldHandle`); 1 new `[Error]` enum variant; uniffi 0.31 codegen renames documented in project memory still apply (`wipe → close` on Kotlin; `AutoCloseable` auto-generated).
9. Swift smoke + Kotlin smoke: +4 asserts each.
10. README + ROADMAP refresh; NEXT_SESSION + handoff.

The two-stage review pattern from B.3a/B.3b/B.4a (spec compliance review → code quality review per task) carries forward.

## (3) Open decisions and risks

### Decisions made and load-bearing for B.4c+

These B.4b spec decisions constrain subsequent FFI work:

1. **`OpenVaultManifestInner.vault_folder: PathBuf` is the canonical "where this vault lives" handle** for B.4c (`save_block`) and B.4d (`share_block`). Both will reuse this for atomic-write paths. No need to re-thread the folder through future bridge entry points.
2. **Hybrid Record projection is the canonical pattern for any future secret-payload-bearing value type.** Non-secret metadata is value-type; secret payload is opaque-handle with explicit `expose_*()` boundary. ContactCard's public-key accessors (B.4d) will follow the same shape — public keys are non-secret so projected as plain bytes.
3. **`Record` / `FieldHandle` use `Arc<Mutex<Option<T>>>` not just `Mutex<Option<T>>`.** Because accessors return clones the foreign caller can store. `BlockReadOutput`, `OpenVaultManifest`, `UnlockedIdentity` keep the simpler `Mutex<Option<T>>` (no shared-clone access pattern).
4. **Single-author block reading only in B.4b.** The bridge assumes `manifest.owner_card` is the sender card. B.4d's `share_block` flow will add `contacts/<author_uuid>.card` discovery and the multi-author read path.
5. **Wrong-length UUID = `ValueError` / `IllegalArgumentException`, not `BlockNotFound`.** The same anti-conflation discipline applies to any future `&[u8; N]` parameter — wrong length is a programmer bug, not a data error.
6. **Trash entries stay invisible at the FFI through B.4d.** Restore-from-trash is a Sub-project C / sync-orchestrator concern that needs vector-clock context. If a viewer UI needs "show deleted" before C ships, this decision is revisited.

### Risks for the B.4b implementation

- **Record/FieldHandle wipe ordering corner case.** `BlockReadOutput::wipe()` walks `records: Vec<Record>` and calls `wipe()` on each; each `Record::wipe()` walks `fields: Vec<FieldHandle>` similarly. If a foreign caller holds a clone of an inner `FieldHandle` and calls `wipe()` on it, then later calls `wipe()` on the parent `Record`, the second wipe should be idempotent (the inner Option is already None). Tests should cover both orderings.
- **uniffi 0.31 + 3 new interfaces.** B.4a had 1 new interface (OpenVaultManifest) + 2 dictionaries; B.4b has 3 new interfaces (BlockReadOutput, Record, FieldHandle). The codegen-rename quirks may surface differently — particularly if Kotlin's `AutoCloseable` interaction with multiple wipe-able interfaces nests in unexpected ways. Mitigation: implement Task 8 before Task 9 and let the codegen run before writing smoke tests.
- **Maturin / uv cache stickiness on PyO3 surface change.** Documented in project memory (`project_secretary_maturin_uv_cache`); B.4b adds substantial new symbols (`read_block` + `BlockReadOutput` + `Record` + `FieldHandle` + `VaultBlockNotFound`), so apply the nuclear fix proactively after Task 6 (PyO3 wrapper) before running pytest in Task 7.

### Pre-existing technical debt

None outstanding from B.4a. The B.4b spec inherits zero open items from B.4a beyond the standard "deferred to later sub-project" non-goals.

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary
git checkout main
git pull --ff-only

# Verify the post-session state on main:
cargo test --release --workspace 2>&1 | grep -E "^test result:" | python3 -c "
import sys, re
p=f=i=0
for line in sys.stdin:
    m = re.search(r'(\d+) passed.*?(\d+) failed.*?(\d+) ignored', line)
    if m: p+=int(m.group(1)); f+=int(m.group(2)); i+=int(m.group(3))
print(f'TOTAL: {p} passed; {f} failed; {i} ignored')"
cargo clippy --release --workspace -- -D warnings && echo "clippy OK"
cargo fmt --all -- --check && echo "fmt OK"

# IMPORTANT: re-build the maturin dylib BEFORE pytest. Cache stickiness
# (documented in ffi/secretary-ffi-py/README.md) often manifests as
# `module 'secretary_ffi_py' has no attribute 'open_vault_with_password'`
# or similar after a branch switch. Apply nuclear fix:
#   rm -rf ffi/secretary-ffi-py/.venv
#   find ~/.cache/uv -name "*secretary*" -exec rm -rf {} +
#   uv sync --directory ffi/secretary-ffi-py
( cd ffi/secretary-ffi-py && uv run maturin develop --release --uv )

uv run --directory ffi/secretary-ffi-py pytest
uv run core/tests/python/conformance.py
uv run core/tests/python/spec_test_name_freshness.py
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh

# Expected baseline: 522 passed + 9 ignored cargo; clippy clean; fmt OK; 30 pytest;
# PASS conformance + freshness; 18/18 Swift; 19 Kotlin PASS lines.

# Begin Sub-project B.4b implementation:
# 1. Read the approved spec:
#      docs/superpowers/specs/2026-05-09-ffi-b4b-read-block-design.md
# 2. Create a feature branch:
#      git checkout -b feat/ffi-b4b-read-block
# 3. Use the writing-plans skill to produce:
#      docs/superpowers/plans/2026-05-XX-ffi-b4b-read-block-plan.md
# 4. Use the subagent-driven-development skill to execute the plan task by task,
#    with the two-stage review pattern (spec compliance → code quality) per task,
#    landing each task as its own commit (no batched mega-commits — same shape as B.4a).
# 5. Per project memory `feedback_next_session_in_pr`: update + commit NEXT_SESSION.md
#    on the FEATURE BRANCH before pushing the PR (not after merge).
```

---

## Closing inventory

- **Branch:** `main` (no feature branch this session — design-only work landed directly to `main` per the project's pattern of committing approved specs ahead of implementation).
- **Total commits this session:** 3 on `main` (`3093782` spec + `fc7e35d` ROADMAP refresh + this commit's NEXT_SESSION + handoff).
- **Workspace tests:** 522 + 9 ignored (unchanged).
- **Pytest:** 30 (unchanged).
- **Swift smoke:** 18/18 (unchanged).
- **Kotlin smoke:** 19 PASS lines (unchanged).
- **Bridge crate:** 56 unit tests (unchanged).
- **uniffi crate:** 15 unit tests (unchanged).
- **Spec doc:** [docs/superpowers/specs/2026-05-09-ffi-b4b-read-block-design.md](docs/superpowers/specs/2026-05-09-ffi-b4b-read-block-design.md) (623 lines; 9-decision log + in-scope fuzz hardening + deferred-items list).
- **Handoff:** [docs/handoffs/2026-05-09-b4b-spec.md](docs/handoffs/2026-05-09-b4b-spec.md).
