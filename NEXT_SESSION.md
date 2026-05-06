# NEXT_SESSION.md

**Session date:** 2026-05-05 (Sub-project B.3b — vault creation through FFI)
**Status:** Sub-project B.3b complete and merged. PR [#27](https://github.com/hherb/secretary/pull/27) squash-merged to `main` as `a8d1b14`. The vault creation path is now exposed across PyO3 (Python) and uniffi (Swift / Kotlin) via the existing shared `secretary-ffi-bridge` crate. With B.3b done, the FFI surface contains every `secretary_core::unlock` v1 entry point: `open_with_password`, `open_with_recovery`, and `create_vault`. The deferred-from-B.2 "how does `Sensitive<T>` materialize on the foreign side?" question is answered with a one-shot opaque `MnemonicOutput` handle pattern. Subsequent FFI work addresses different concerns (vault operations on records, sharing primitives, public-key accessors).

## (1) What we shipped this session

| Task | Commit(s) | What landed |
|---|---|---|
| 1 — bridge error.rs Display tweak | `de37939` | `CorruptVault` Display string changed from `"vault is corrupt or unreadable: {detail}"` (read-path-only) to `"vault data integrity failure: {detail}"` (path-neutral) so the variant reads correctly on both create and open paths; +1 tripwire test. |
| 1b — uniffi UnlockError mirror | `c0b203f` | Symmetric Display tweak to the uniffi crate's mirrored `UnlockError::CorruptVault` so Swift/Kotlin error messages stay in sync with the bridge/Python sides. Plan-gap caught during Task 1 spec review and folded in immediately per "no technical debt"; +1 tripwire test. |
| 2 — bridge create.rs | `c9df6fd`, `6b4f268` | New file with `create_vault`, `CreateVaultOutput`, `MnemonicOutput` + 5 tests (3 fast on `MnemonicOutput` contract, 2 slow round-trip through real V1_DEFAULT Argon2id). Bridge instantiates `OsRng` + `V1_DEFAULT` internally; foreign callers cannot tune either. Added `rand_core = "0.6"` as a runtime dep (matches core's pin). Style fix-up trimmed a duplicate field doc per code-quality review. |
| 3 — bridge lib.rs | `81bd503` | Re-exports `create_vault`, `CreateVaultOutput`, `MnemonicOutput`; crate-doc updated for the 7-item surface. Two pre-existing latent rustdoc warnings in create.rs surfaced by Task 3's `cargo doc` gate were folded in (intra-doc link path corrections). |
| 4 — PyO3 wrapper | `763b08f` | `#[pyfunction] create_vault`; 2 new `#[pyclass]` (`CreateVaultOutput` with take-once getters, `MnemonicOutput` with `__enter__`/`__exit__`); wrapper-side `Vec<u8>` password zeroize before `?`-propagation. |
| 5 — pytest | `f2cf1f8`, `123f19e` | +6 tests (shape, immediately-live identity, 24-word mnemonic, one-shot take, round-trip × 2); module-scoped `created_vault` fixture amortizes one Argon2id cost. Style fix-up narrowed a docstring to match assertion scope. |
| 6 — UDL + uniffi glue | `d2c37f4` | UDL gains 1 `dictionary` (`CreateVaultOutput`) + 1 `interface` (`MnemonicOutput`) + 1 namespace fn (`create_vault`); uniffi-side wrapper structs with `Arc<Interface>` for dictionary fields; +2 mapping/integration tests; bridge gains `#[doc(hidden)] pub fn new_for_test` so uniffi tests can synthesize a `MnemonicOutput` without paying Argon2id cost; `rand_chacha = "0.3"` added as dev-dep. |
| 7 — Swift + Kotlin smoke | `0b7a2ea`, `f78afca` | +3 asserts each (shape, round-trip-with-password, round-trip-with-recovery); plan vs uniffi 0.31 codegen type mismatches corrected (Swift `bytes` → `Data` not `[UInt8]`; Swift `sequence<u8>?` → `[UInt8]?` then `Data(...)` to convert; Kotlin `u64` → `ULong` not `Long`; Kotlin `sequence<u8>?` → `List<UByte>?` element-wise to `ByteArray`). Style fix-up tightened Swift assertion 15 cleanup symmetry (`defer { mnemonic.wipe() }` instead of trailing eager wipe). |
| 8 — READMEs + ROADMAP | `a0aa63d` | Bridge / py / uniffi crate READMEs gain B.3b sections; top-level README progress bar advanced + status table B.3b row flipped ⏳ → ✅; ROADMAP B.3b entry flipped + long status paragraph extended. |
| 9 — NEXT_SESSION + handoff | (this commit) | This file + `docs/handoffs/2026-05-05-b3b-create-vault.md`. |

### Verification at session close

| Check | Result |
|---|---|
| `cargo test --release --workspace` | **498 passed + 9 ignored, 0 failed** (was 489 + 9 at branch start; +9 from B.3b cumulative across the bridge + uniffi crates) |
| `cargo clippy --release --workspace -- -D warnings` | clean |
| `cargo fmt --all -- --check` | OK |
| `uv run --directory ffi/secretary-ffi-py pytest` | **22 passed** (was 16 — added 6 B.3b tests) |
| `uv run core/tests/python/conformance.py` | **PASS** |
| `uv run core/tests/python/spec_test_name_freshness.py` | **PASS** |
| `bash ffi/secretary-ffi-uniffi/tests/swift/run.sh` | **15/15 PASS** (was 12/12 — added 3 B.3b asserts) |
| `bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh` | **15 asserts all PASS** (was 12/12 — added 3 B.3b asserts; runner emits 16 PASS lines because assertion 15 has both a `phrase != null` guard and an inner round-trip check) |

### Per-crate breakdown of the 498-test workspace

- `secretary-core` — 448 (unchanged)
- `secretary-ffi-bridge` — **36** (was 30; +6 net: +1 tripwire in `error.rs`, +5 in new `create.rs`)
- `secretary-ffi-py` — 3 (unchanged Rust unit tests; the 22 pytest count is separate)
- `secretary-ffi-uniffi` — **11** (was 8; +1 tripwire in lib.rs from Task 1b; +2 in mod tests from Task 6)

### Two-stage review caught real bugs (and confirmed real wins) — same shape as B.3a

The subagent-driven-development workflow's two-stage review (spec compliance → code quality) drove fix-up commits across the implementation tasks. Concrete examples:

- **Task 1** (bridge error.rs): Spec compliance review caught a plan gap — the uniffi crate's mirrored `UnlockError::CorruptVault` Display text wasn't updated by the plan, which would have left Swift/Kotlin error messages out of sync with bridge/Python. Fix-up commit `c0b203f` (Task 1b) addressed it before any other work touched the unified error surface.
- **Task 2** (bridge create.rs): Code quality review flagged a `MnemonicOutput::inner` field doc as duplicating module-level docs; trimmed in `6b4f268`.
- **Task 3** (bridge lib.rs): Controller spotted two pre-existing rustdoc warnings while running Task 3's `cargo doc --no-deps` gate (which Task 2's gate didn't run); folded into Task 3's commit per "incidental issues — fix or file, never just mention".
- **Task 5** (pytest): Code quality review noted the shape-test docstring overstated the assertion scope; narrowed in `123f19e`.
- **Task 7** (Swift/Kotlin smoke): The implementer surfaced 5 plan-vs-uniffi-codegen type mismatches during implementation (Swift `bytes` vs `[UInt8]`, Swift `sequence<u8>?` mnemonic conversion, Kotlin `u64` vs `Long`, Kotlin `List<UByte>?` element-wise to `ByteArray`, Kotlin assertion-15 dual-PASS structure). All corrected appropriately. Code quality review flagged a Swift cleanup-symmetry inconsistency; tightened in `f78afca`.

The user's "fix every review issue before merging — no technical debt" preference held throughout. No issues filed for follow-up; everything in scope landed before the doc commit.

## (2) What's next

With B.3b done, the v1 unlock-and-create FFI surface is complete. Subsequent sub-projects address different concerns; brainstorm needed for whichever is selected next:

- **B.4: Record operations.** Expose vault read/write of `Record` types through the FFI. Brings in CRDT merge semantics, record-level encryption, and the user's actual secret-storage workflows.
- **B.5: Sharing primitives.** Public-key accessors + cross-vault encryption operations. Re-opens the deferred public-key-accessors non-goal from B.2 / B.3a / B.3b.
- **C: Sync orchestration.** Beyond client-only operations; involves the as-yet-undesigned sync layer.
- **D: Platform UIs.** Swift/Kotlin/Python desktop apps consuming the now-stable FFI.

The deferred-items section in [docs/superpowers/specs/2026-05-05-ffi-b3b-create-vault-design.md](docs/superpowers/specs/2026-05-05-ffi-b3b-create-vault-design.md) "Non-goals (YAGNI)" carries the carry-over context — read it before requesting the brainstorming skill.

## (3) Open decisions and risks

### Decisions made and load-bearing for future sub-projects

These are the B.3b decisions that constrain subsequent FFI work:

1. **Bridge crate stays the single source of FFI code truth.** Any new entry point lives there first; PyO3 and uniffi project from it.
2. **5-variant thinned error preserves §13 anti-oracle conflation.** B.3b kept the cardinality unchanged structurally; only the Display text on `CorruptVault` was tweaked to be path-neutral. New entry points fold into one of the existing five OR add a 6th distinct user-actionable category — never an inner-cause sub-variant.
3. **Bytes-not-string at the FFI boundary for secret inputs and outputs.** B.3b extended this to outputs via `MnemonicOutput.take_phrase() -> Option<Vec<u8>>`. The caller-zeroize discipline is documented at every layer.
4. **Explicit close + RAII safety net stays in place.** Python `with`, Swift `defer`, Kotlin `.use {}`. Both `UnlockedIdentity` and `MnemonicOutput` follow this pattern; both are AutoCloseable in Kotlin via uniffi 0.31's auto-codegen.
5. **OsRng + V1_DEFAULT hardcoded for create paths.** No foreign-side knobs. Future entry points that need RNG or KDF tuning may revisit; current discipline is "production-safe-only at the FFI".
6. **One-shot `Sensitive<T>`-output pattern (`MnemonicOutput`).** The pattern works: `Mutex<Option<T>>` newtype + crate-private constructor + `take` accessor that copies bytes out before drop + idempotent `wipe`. Reusable for future output-direction secrets if any arise.
7. **`#[doc(hidden)] pub fn new_for_test` escape hatch.** When sibling crates need to construct an opaque-handle directly (without paying expensive setup costs), a hidden test-only constructor on the bridge is the right pattern — doc-hidden, minimum-visibility (`pub` because cross-crate, not `pub(crate)`).

### Risks for future work

- **B.3b made `WeakKdfParams` structurally unreachable through the FFI.** If a future sub-project re-introduces foreign-side `Argon2idParams` control, the existing defensive fold-into-`CorruptVault` mapping should be revisited (either promote `WeakKdfParams` to its own variant or keep folded with documented rationale).
- **Maturin/uv cache stickiness** is well-documented in [`ffi/secretary-ffi-py/README.md`](ffi/secretary-ffi-py/README.md) and the project memory; expect to apply the documented nuclear fix after any branch-switch / squash-merge that touches PyO3 surface.

### Pre-existing technical debt

None outstanding from B.3b.

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
# manifests as `module 'secretary_ffi_py' has no attribute 'create_vault'`.
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

# Expected: 498 passed + 9 ignored cargo; clippy clean; fmt OK; 22 pytest;
# PASS conformance + freshness; 15/15 Swift; 15/15 Kotlin (16 PASS lines
# because assertion 15 has both a guard and an inner check).
```

---

## Closing inventory

- **Branch:** `feat/ffi-b3b-create-vault` (squash-merged + deletable; current work happens on `main`)
- **Total commits since branching from `main@e6f97e6`:** 12 on the feature branch (8 task implementations + 1 inserted task 1b + 4 review/style fix-ups + 1 doc/handoff). Squash-merged to `main` as `a8d1b14`.
- **Workspace tests:** 498 + 9 ignored
- **Pytest:** 22 (16 from B.1 + B.2 + B.3a + 6 B.3b)
- **Swift smoke:** 15/15 (12 from prior + 3 B.3b)
- **Kotlin smoke:** 15/15 (12 from prior + 3 B.3b; 16 PASS lines emitted because assertion 15 has a guard)
- **Bridge crate:** 36 unit tests (was 30; +6 net)
- **uniffi crate:** 11 unit tests (was 8; +3 net including Task 1b's tripwire)
- **PR:** [#27](https://github.com/hherb/secretary/pull/27) squash-merged as `a8d1b14`.
