# NEXT_SESSION.md

**Session date:** 2026-05-04 (Sub-project B.2 — FFI vault unlock; **MID-EXECUTION**)
**Status:** B.2 implementation in progress on branch `feat/ffi-b2-vault-unlock` in worktree `.worktrees/feat-ffi-b2-vault-unlock/`. Tasks 0–6 of 12 complete (bridge crate fully built). Tasks 7–12 remain (PyO3 + uniffi projections + docs + handoff + PR).

> **IMPORTANT — how to resume.** This file lives on the **feature branch**, NOT on main. Run `/nextsession` from inside the worktree:
>
> ```bash
> cd /Users/hherb/src/secretary/.worktrees/feat-ffi-b2-vault-unlock
> /nextsession
> ```
>
> If you run `/nextsession` from `/Users/hherb/src/secretary/` (main worktree), you'll get main's older NEXT_SESSION.md which is the pre-B.2 baton — wrong baton. The feature branch's NEXT_SESSION.md (this file) is the in-progress baton.

---

## (1) What we shipped this session

Sub-project B.2 began with brainstorm + spec + plan, then mid-implementation. Spec and plan committed to `main` BEFORE the worktree was created so they're inherited cleanly:

| SHA | Commit | Branch |
|---|---|---|
| `36850ec` | docs(next-session): record squash-merge SHA 96cfc4b for PR #22 | `main` |
| `86c4521` | docs(spec): add B.2 FFI vault unlock design (PR-pending) | `main` |
| `959c6ed` | docs(plan): add B.2 FFI vault unlock implementation plan | `main` |

Then the worktree forked off `main@959c6ed` for implementation. Tasks 0–6 landed as 10 commits on `feat/ffi-b2-vault-unlock`:

| Task | SHA(s) | What landed |
|---|---|---|
| 0 — Worktree | (controller) | `.worktrees/feat-ffi-b2-vault-unlock/` on branch `feat/ffi-b2-vault-unlock` |
| 1 — Generator refactor | `7caffa3, c3249c9` | Extracted `core/tests/common/fixture_builder.rs` from monolithic `golden_vault_001.rs`; pinned bytes unchanged. Fix-up restored `#![allow(dead_code)]` placement + cross-reference comment + import hygiene. |
| 2 — golden_vault_002 | `4cd039f, 5a79663, a7b2c5a` | Sibling fixture: distinct vault_uuid `aabbccdd-...`, distinct created_at_ms `2000000001000`, distinct password `"correct horse battery staple two"`, identity seeds 0xB0/0xB1/0xB2, KDF salt all-0x02. Fix-ups removed dead `_verify_path_helpers` (the implementer fabricated removing it while actually adding it — caught by spec review) and polished review comments. |
| 3 — Bridge crate skeleton | `27591ed` | New `ffi/secretary-ffi-bridge/` workspace member; pure-safe Rust; **zeroize pinned to exact `=1.8.2`** with security comment (improvement over plan's caret range). |
| 4 — error.rs | `fdb7542, e7db659` | Thinned 3-variant `FfiUnlockError` + `From<core::UnlockError>` (no-wildcard match) + 10 unit tests covering all 7 reachable + 2 defensive forward-compat variants + Display-stability pinning. Fix-up added rationale comments to defensive tests + display-stability anchor for foreign-side tests. |
| 5 — identity.rs | `22aef50` | `UnlockedIdentity` opaque wrapper with `Mutex<Option<core::UnlockedIdentity>>` for idempotent close + thread-safe accessors + use-after-close non-throwing semantics. 6 unit tests including thread-safety smoke. Added `rand_chacha = "0.3"` as dev-dep. |
| 6 — unlock.rs | `81bbfff` | `open_with_password` free function + 4 integration tests using `include_bytes!`-embedded golden_vault_001 + golden_vault_002 fixtures (success / wrong-password → `WrongPasswordOrCorrupt` / cross-vault file-pair → `VaultMismatch` / truncated TOML → `CorruptVault`). Plus a redacted `Debug` impl on `UnlockedIdentity` (test infrastructure required it; matches project's redacting-Debug pattern). |

### Verification at session pause

| Check | Result |
|---|---|
| `cargo test --release --workspace` | **474 passed + 9 ignored, 0 failed** (was 451 + 6 on main) |
| `cargo clippy --release --workspace -- -D warnings` | clean |
| `git diff core/tests/data/golden_vault_001/` (vs `main`) | empty (vault_001 untouched) |
| `uv run core/tests/python/conformance.py` | **PASS** |
| `uv run core/tests/python/spec_test_name_freshness.py` | **PASS** |
| Bridge crate self-test (`cargo test -p secretary-ffi-bridge`) | 20 tests pass |

### Two-stage review caught real issues

The subagent-driven-development workflow's two-stage review (spec compliance → code quality) caught issues across multiple tasks:

- **Task 1**: implementer moved `#![allow(dead_code)]` from doc-first to pre-doc placement (regression); full-path `Sensitive::new` import inconsistency.
- **Task 2**: implementer **fabricated** a "removed `_verify_path_helpers`" claim — spec reviewer caught that the function was actually *added* by the same implementer to suppress an unused-import warning. Removed in fix-up.
- **Task 4**: missing rationale comments on defensive-mapping tests; missing anchor comment on display-stability test that foreign smoke runners (Tasks 8/10) will assert against.

The user's "fix every review issue before merging — no technical debt" preference held: every flagged issue got a fix-up commit before moving to the next task.

### Deviations from plan accepted (with rationale)

- Task 2: extra `golden_vault_002_cross_vault_mismatch` test (Rust-core layer; complementary to Task 6's bridge-crate test, different layers). Spec reviewer accepted as scope-aligned.
- Task 3: zeroize pinned to exact `=1.8.2` with security comment (better than plan's `"1.8"` caret; matches `core/Cargo.toml`'s exact-pin discipline for security-critical deps per CLAUDE.md).
- Task 4: variant-name corrections where plan's literal text didn't match real core API (`VaultTomlError::MissingField` arg type, `BundleFileError::TruncatedHeader` → `Truncated { offset }`, `BundleError::MalformedCbor` → `CborError`, `KdfError::OutputLengthOutOfRange` → `ParamsBelowV1Floor`). Each correction commented inline.
- Task 6: redacted `Debug` impl on `UnlockedIdentity` (test infrastructure required `T: Debug` for `unwrap_err()`; impl exposes only `closed: bool`, no secret material — matches `core::UnlockedIdentity`'s own redacting Debug policy).

---

## (2) What's next, with concrete acceptance criteria

### Resume from Task 7

Tasks 7–12 of the plan at [docs/superpowers/plans/2026-05-04-ffi-b2-vault-unlock.md](docs/superpowers/plans/2026-05-04-ffi-b2-vault-unlock.md):

| Task | What it does | Files | Estimated dispatches |
|---|---|---|---|
| 7 — PyO3 wrapper + exception classes | Newtype `#[pyclass] UnlockedIdentity` around `bridge::UnlockedIdentity` + 3 `create_exception!` classes + `From<FfiUnlockError> for PyErr` + `#[pyfunction] open_with_password` + `__enter__` / `__exit__` for context-manager protocol | `ffi/secretary-ffi-py/Cargo.toml`, `ffi/secretary-ffi-py/src/lib.rs` | ~3 (impl + spec + code-quality reviews) |
| 8 — Python pytest tests | 7 new tests using `Path(__file__).resolve().parents[3]` for golden_vault path resolution; `with secretary_ffi_py.open_with_password(...) as identity:` idiom; pytest-raises for the 3 error classes; close-idempotence + use-after-close + bytearray caller-zeroize doc | `ffi/secretary-ffi-py/tests/test_smoke.py` | ~3 |
| 9 — uniffi UDL + Rust glue | UDL adds `interface UnlockedIdentity`, `[Error] interface UnlockError { ...; CorruptVault(string message) }` (complex error form), namespace function `[Throws=UnlockError] open_with_password(bytes, bytes, bytes)`. Rust-side: pub struct newtype + method forwarders + `From<FfiUnlockError>`. | `ffi/secretary-ffi-uniffi/Cargo.toml`, `ffi/secretary-ffi-uniffi/src/secretary.udl`, `ffi/secretary-ffi-uniffi/src/lib.rs` | ~3 |
| 10 — Swift + Kotlin smoke runners | `SECRETARY_GOLDEN_VAULT_DIR` env var via `run.sh` for both languages. Swift: `defer { close() }` idiom. Kotlin: `.use { }` extension function in 5-line `UnlockedIdentityExt.kt` (until uniffi natively supports `AutoCloseable`). 4 new asserts each language: success / wrong password / vault mismatch / corrupt vault. | `tests/swift/{main.swift, run.sh}`, `tests/kotlin/{Main.kt, UnlockedIdentityExt.kt, run.sh}` | ~4 |
| 11 — READMEs + ROADMAP + top-level docs | New `secretary-ffi-bridge/README.md`. Edit `secretary-ffi-py/README.md` + `secretary-ffi-uniffi/README.md` to add "Vault unlock (B.2)" sections with idiomatic-usage code, exception-handling, password-input discipline (caller-zeroize convention). Edit top-level `README.md` (FFI status table → ✅ B.2; ASCII progress bar). Edit `ROADMAP.md` (§ "Sub-project B" → B.2 ✅). | 5 README/ROADMAP files | ~2 (lower-stakes, mechanical) |
| 12 — NEXT_SESSION + handoff archive + PR | Replace this file's contents with the post-B.2 retrospective + B.3 forward-look. Create `docs/handoffs/2026-MM-DD-b2-vault-unlock.md` timestamped archive. Push branch + open PR. | `NEXT_SESSION.md`, `docs/handoffs/`, `gh pr create` | ~1 |

### Acceptance gates at session close (after Task 12)

- `cargo test --release --workspace` — ~474+ passed, 0 failed (no Rust unit tests added in Tasks 7–10; the foreign-language tests live in pytest / Swift / Kotlin)
- `cargo clippy --release --workspace -- -D warnings` — clean
- `uv run --directory ffi/secretary-ffi-py pytest` — 10 passed (was 3; +7 unlock tests)
- `uv run core/tests/python/conformance.py` — PASS unchanged
- `uv run core/tests/python/spec_test_name_freshness.py` — PASS
- `bash ffi/secretary-ffi-uniffi/tests/swift/run.sh` — 7/7 PASS (was 3/3; +4 unlock asserts)
- `bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh` — 7/7 PASS (was 3/3; +4 unlock asserts)

---

## (3) Open decisions and risks

### Decisions made (recorded for context)

The brainstorm settled these and they're load-bearing for Tasks 7–10:

1. **Q1(b)**: scope is `open_with_password` + non-secret accessors only. NO `create_vault`, NO `open_with_recovery`, NO genuinely-secret accessors. Deferred to B.3+.
2. **Q2(γ)**: `WeakKdfParams` is unreachable through `open_with_password` (only `create_vault` enforces the v1 floor on write); B.2 surfaces only what `open_with_password` actually returns. Defensive forward-compat mapping is in place.
3. **Q3(II)**: 3-variant thinned error type expressing user-actionable intent (`WrongPasswordOrCorrupt` / `VaultMismatch` / `CorruptVault { message }`). The conflation of wrong-password + corruption preserves the §13 anti-oracle property — **MUST NOT** be split on the foreign side.
4. **Q4(B)**: explicit close + RAII. Python `with`, Kotlin `.use`, Swift `defer`. Hand-written Kotlin `.use` extension at `tests/kotlin/UnlockedIdentityExt.kt` (Task 10) until uniffi natively supports `AutoCloseable`; tracked by routine `trig_018gYtGpiycgLXqUsDpV2NZD` (weekly Mondays 09:00 Australia/Perth).
5. **Q5(ii)**: passwords are bytes (not String) at the FFI boundary; first-party clients enforce caller-side zeroize via mutable buffers.
6. **Q7(α)**: free functions parallel to Rust core's procedural shape; convenience wrappers (if needed) live on the Rust side.
7. **Q8(b)**: shared `secretary-ffi-bridge` crate as the single source of code truth — done in Tasks 3–6.
8. **Q9(2)**: `SECRETARY_GOLDEN_VAULT_DIR` env var via `run.sh` for Swift/Kotlin; `Path(__file__).resolve().parents[3]` for pytest.

### Risks for Tasks 9 / 10 specifically

- **uniffi `[Error] interface UnlockError { ... CorruptVault(string message); }` complex-error syntax** may or may not be supported in the workspace's pinned uniffi version. If unsupported, fallback per spec Risk register: flat `[Error] enum` + lose the `message` field on Swift/Kotlin (mitigated by baking the inner Display into `UnlockError`'s `Display::fmt` so `Throwable.message` / `Error.localizedDescription` still carries it). **Verify before committing Task 9** by running a `cargo build --release -p secretary-ffi-uniffi` after the UDL change and checking for parser errors.
- **PyO3 `#[pyclass]` newtype + `__enter__` / `__exit__`**: the `__exit__` signature varies across PyO3 versions. The plan's signature uses `Bound<'_, PyAny>` for the exc_type / exc_value / traceback args. Verify this matches the repo's PyO3 version (`grep '^pyo3' ffi/secretary-ffi-py/Cargo.toml`).
- **maturin develop + uv editable cache trap** (per user memory): after Rust changes in `secretary-ffi-py`, nuke `ffi/secretary-ffi-py/.venv` + `uv cache clean` before running pytest. The cache-stickiness bug means stale `.so` files survive `maturin develop` invocations.
- **JNA jar download in Kotlin run.sh**: the SHA-256-verified fetch from Maven Central runs on every invocation (cached locally after first run). If offline / proxied, `JNA_VERSION` and `JNA_SHA256` constants in the script are the change point.

### Subagent-driven-development observations from Tasks 1–6

- The two-stage review (spec compliance → code quality) IS catching real bugs. Don't skip it for Tasks 7–12.
- Implementer reports describe what they *intended* to do, not always what they *did*. The `_verify_path_helpers` fabrication in Task 2 was caught by the spec reviewer reading the actual diff — without that step it would have shipped.
- Mechanical scaffolding tasks (like Task 3, the bridge skeleton) can skip the formal two-stage review — direct verification by the controller (read the diff + run gates) is sufficient. Tasks with logic (4, 5, 6) needed both review stages.
- Variant-name corrections are common when plans pre-cite enum variants. Implementers should verify against actual core API before pasting the plan's literal test code.

---

## (4) Exact commands to resume

```bash
# 1. cd into the worktree (NOT main)
cd /Users/hherb/src/secretary/.worktrees/feat-ffi-b2-vault-unlock
git status
git log --oneline -3   # confirm HEAD is 81bbfff or later

# 2. Re-baseline tests (everything should still pass)
cargo test --release --workspace 2>&1 | grep -E "^test result:"
cargo clippy --release --workspace -- -D warnings && echo "clippy OK"
cargo test --release -p secretary-ffi-bridge 2>&1 | tail -3   # bridge crate self-test

# Expected: cargo workspace 474 passed + 9 ignored, clippy clean,
# bridge crate 20 tests pass.

# 3. Run /nextsession FROM THE WORKTREE — that gets THIS file as the baton.
#    Then follow the resume instructions to invoke
#    superpowers:subagent-driven-development with the plan at
#    docs/superpowers/plans/2026-05-04-ffi-b2-vault-unlock.md, starting
#    from Task 7.

# 4. After Task 7 (or any subsequent task) commits, this file's
#    "What we shipped" table grows. After Task 12, replace this file
#    with the post-B.2 retrospective + B.3 forward-look (see plan
#    Task 12 for the template).
```

### Custom prompt for the next session

If you don't want to use `/nextsession`, here's a self-contained prompt that does the same thing:

```
Resume B.2 FFI vault unlock implementation. We're mid-execution in
.worktrees/feat-ffi-b2-vault-unlock/ on branch feat/ffi-b2-vault-unlock.
Tasks 0-6 complete (bridge crate fully built); Tasks 7-12 remaining.

Read NEXT_SESSION.md (in this worktree, NOT in the main worktree) for
full context. Then invoke superpowers:subagent-driven-development to
continue with Task 7 of the plan at
docs/superpowers/plans/2026-05-04-ffi-b2-vault-unlock.md.

The two-stage review (spec compliance → code quality) per the
subagent-driven-development skill IS catching real bugs in this branch's
prior tasks — keep using it for tasks 7-10 (which involve logic).
Mechanical doc-only tasks (11, 12) can skip the formal two-stage review
and use direct controller verification.
```

Either prompt works. `/nextsession` is shorter and matches your habit; the long-form prompt is self-contained if you want to spawn it from a place where `/nextsession` isn't convenient.

---

## Closing inventory

- **Branch:** `feat/ffi-b2-vault-unlock` (10 implementation commits since branching from `main@959c6ed`)
- **Worktree:** `.worktrees/feat-ffi-b2-vault-unlock/`
- **Tests:** 474 + 9 ignored (cargo); 20 in bridge crate alone; 3 + 3 + 3 in existing pytest/Swift/Kotlin (unchanged so far)
- **Clippy:** clean with `-D warnings`
- **Bridge crate:** complete. `secretary-ffi-bridge` workspace member with `error.rs`, `identity.rs`, `unlock.rs` filled in.
- **PyO3 / uniffi crates:** B.1 / B.1.1 / B.1.1.1 surface unchanged; B.2 projection layers (Tasks 7 / 9) not yet written.
- **Foreign smoke runners:** existing 3 asserts each (Python pytest / Swift / Kotlin) unchanged; Tasks 8 / 10 add 4 new asserts each.
- **Documentation:** spec at `docs/superpowers/specs/2026-05-04-ffi-b2-vault-unlock-design.md` (on main, inherited); plan at `docs/superpowers/plans/2026-05-04-ffi-b2-vault-unlock.md` (on main, inherited); per-crate READMEs not yet edited (Task 11).
- **Companion routine:** `trig_018gYtGpiycgLXqUsDpV2NZD` (weekly uniffi Closeable-trait watch) is active and will fire its first run on Mon 2026-05-11 09:06 Australia/Perth.
- **PR status:** not yet opened. Will open after Task 12 with cumulative test plan.
