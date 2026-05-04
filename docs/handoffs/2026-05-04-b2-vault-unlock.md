# NEXT_SESSION.md

**Session date:** 2026-05-04 (Sub-project B.2 — vault unlock through FFI)
**Status:** Sub-project B.2 complete and merged. PR [#24](https://github.com/hherb/secretary/pull/24) squash-merged to `main` as `4d0fffc`; post-merge `cedaccc` closed issue #23 (`cargo fmt --all` repo-wide drift). The first fallible, secret-bearing FFI operation is now exposed across PyO3 (Python) and uniffi (Swift / Kotlin) via the new shared `secretary-ffi-bridge` crate. With B.2 done, the FFI surface includes its first vault crypto operation; B.3 expands it with `open_with_recovery` and (deferred-design) `create_vault`.

## (1) What we shipped this session

| Phase | Task | Commit(s) | What landed |
|---|---|---|---|
| 7.4 | 7 — PyO3 wrapper | `4b2b05e`, `d73ca02`, `99878fe` | UnlockedIdentity #[pyclass] newtype, 3 exception classes (WrongPasswordOrCorrupt / VaultMismatch / CorruptVault), context-manager protocol; review fix-ups for stale doc + Cargo.toml description; password param widened to Vec<u8> for bytearray support. |
| 7.4 | 8 — pytest tests | `284a0e6`, `f24fa4e` | 7 new pytests (success path + wrong password + cross-vault mismatch + corrupt vault + idempotent close + use-after-close + bytearray caller-zeroize); review fix-ups: PEP 8 import consolidation, _TRUNCATION_SUFFIX_BYTES named constant, `-> None` annotations, password Vec<u8> wrapper-side zeroize. |
| 7.5 | 9 — uniffi UDL + glue | `29e3e1c` | UDL surface adds `[Throws=UnlockError] open_with_password`, `interface UnlockedIdentity`, `[Error] interface UnlockError`; Rust glue: 3-variant error enum + `From<FfiUnlockError>` + opaque-handle newtype + Vec<u8> password zeroize. Three uniffi-codegen-driven deviations from plan: `CorruptVault.message → detail` (Kotlin Throwable.message collision), `UnlockedIdentity::close → wipe` (Kotlin AutoCloseable.close auto-generation), `Result<Arc<UnlockedIdentity>, _>` return type (uniffi interface marshalling). |
| 7.5 | 10 — Swift + Kotlin smoke | `7cda192`, `fcd56aa` | 4 new Swift asserts + 4 new Kotlin asserts (success / wrong password / cross-vault mismatch / truncated TOML), driven via SECRETARY_GOLDEN_VAULT_DIR env var in run.sh. Kotlin uses stdlib `.use { }` directly via uniffi 0.31's auto-AutoCloseable — hand-rolled UnlockedIdentityExt.kt skipped. Review fix-ups: Kotlin fixture-read try/catch parity with Swift, named TRUNCATION_SUFFIX_BYTES constant. |
| Final | 11 — READMEs + ROADMAP | `959ef1b` | New ffi/secretary-ffi-bridge/README.md; B.2 sections appended to ffi/secretary-ffi-py/README.md and ffi/secretary-ffi-uniffi/README.md (Python uses original `close`, uniffi uses renamed `wipe` / `.detail`). Top-level README + ROADMAP advanced: B.2 ✅, ASCII progress bar 14→21 chars, "Where we are" date 2026-05-03 → 2026-05-04, test count 451+6 → 477+9 with per-crate breakdown. |
| Final | 12 — handoff + PR | `959ef1b` (then squash-merged as `4d0fffc`) | Post-B.2 NEXT_SESSION + docs/handoffs/ archive + GitHub issue #23 filed for repo-wide cargo fmt drift + branch pushed + PR opened. |
| Post-merge | Issue #23 cleanup | `cedaccc` | `cargo fmt --all` (workspace + `core/fuzz/`) — pure rustfmt cosmetics, zero logic changes; verified all gates green. Closes #23. |
| Post-merge | SHA-record fix-up | (this commit) | Records squash-merge SHA `4d0fffc` in NEXT_SESSION.md + this handoff archive copy; corrects bridge-crate test count (20 → 22 — was rounded down at session close); disables companion routine `trig_018gYtGpiycgLXqUsDpV2NZD` via RemoteTrigger (`enabled: false`); fresh handoff copy at `docs/handoffs/2026-05-04-post-pr24-cleanup.md`. Same shape as `36850ec` did for PR #22. |

### Verification at session close

| Check | Result |
|---|---|
| `cargo test --release --workspace` | **479 passed + 9 ignored, 0 failed** (was 451 + 6 at branch start; the 477 cited at session close undercounted the bridge crate's 22 unit tests as 20) |
| `cargo clippy --release --workspace -- -D warnings` | clean |
| `uv run --directory ffi/secretary-ffi-py pytest` | **10 passed** (was 3 — added 7 B.2 tests) |
| `uv run core/tests/python/conformance.py` | **PASS** |
| `uv run core/tests/python/spec_test_name_freshness.py` | **PASS** |
| `bash ffi/secretary-ffi-uniffi/tests/swift/run.sh` | **7/7 PASS** (was 3/3 — added 4 B.2 asserts) |
| `bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh` | **7/7 PASS** (was 3/3 — added 4 B.2 asserts) |

### Two-stage review caught real bugs (and confirmed real wins)

The subagent-driven-development workflow's two-stage review (spec compliance → code quality) caught issues across multiple tasks:

- **Task 7**: spec review said ✅; code quality flagged 3 Important + 2 Minor (stale `From<>` doctring, transient `# NEW` comment, B.1-era Cargo.toml description, missing crate-level B.2 signpost). Fix-up commit `d73ca02` addressed all four.
- **Task 8**: implementer found a Task 7 bug while writing tests — `password: &[u8]` rejected `bytearray`. Filed as a separate Task 7 follow-up commit (`99878fe`) before committing the tests. Also fixed M1-M4 from code-quality review (PEP 8 imports, magic 50, `-> None` annotations, wrapper-side zeroize) in `f24fa4e`.
- **Task 9**: caught zero issues in code-quality review; implementation was clean. The deviations (close → wipe, message → detail, Arc<>) were uniffi 0.31 codegen constraints discovered DURING implementation, properly documented in commit body.
- **Task 10**: spec review said ✅; code quality flagged 1 Important (Kotlin missing the same fixture-read try/catch as Swift) + 1 Minor (magic 50 in Swift/Kotlin matches pytest discipline). Fix-up `fcd56aa` addressed both.
- **Task 11**: docs-only; controller verified directly without dispatching review subagents. Clean.

The user's "fix every review issue before merging — no technical debt" preference held: every flagged issue got a fix-up commit before moving to the next task. `cargo fmt --all` repo-wide drift (pre-existing, predates this branch) filed as a separate GitHub issue rather than folded into a feature commit; see issue #23.

## (2) What's next, with concrete acceptance criteria

### Sub-project B.3 — second + third unlock paths

Brainstorm + spec needed before code. Open design questions to settle in the brainstorm:

1. **How does the 24-word BIP-39 mnemonic cross the FFI boundary?** Options: bytes (zero-pad to 33-byte payload), List[str] (preserved word boundaries), single space-separated string (caller-zeroize ergonomics). Trade-offs around foreign-side word-list validation, normalization, and password-input parity (B.2 chose bytes).
2. **Does `create_vault` expose `WeakKdfParams`?** (B.2 chose to elide this variant because `open_with_password` only reads stored params; `create_vault` writes them and triggers the v1 floor enforcement, so the variant becomes reachable.)
3. **Is `create_vault`'s recovery-mnemonic-output value zeroized through the FFI?** Currently the bridge crate would need to extend `UnlockedIdentity` (or add a new opaque handle) to hold the mnemonic plus identity together, so the foreign-side caller can `display_name()` AND `take_recovery_mnemonic_once()` (one-shot accessor that consumes the inner Sensitive<Mnemonic>).
4. **Do we keep the 3-variant thinned error or expand?** If `open_with_recovery` and `create_vault` together surface a 4th distinct user-actionable category, the thinned-3 may need to grow. The §13 anti-oracle conflation must hold.

Acceptance criteria for B.3 (to be refined during brainstorm):
- [ ] `open_with_recovery(vault.toml bytes, identity.bundle.enc bytes, mnemonic <type>)` exposed across PyO3 + uniffi via the bridge crate.
- [ ] `create_vault(password, kdf_params?, recovery? )` exposed across both — with whatever shape the brainstorm settles for the recovery-mnemonic-output one-shot accessor.
- [ ] Test count grows: cargo workspace + 10 expected (3 bridge crate + 4 pytest + 2 Swift + 2 Kotlin or similar).
- [ ] All gates green at session close (cargo, clippy, pytest, conformance, freshness, both smoke runners).
- [ ] `secretary-ffi-bridge`'s 3-variant error preserves §13 anti-oracle conflation OR is explicitly extended with documented rationale.
- [ ] Spec at `docs/superpowers/specs/2026-MM-DD-ffi-b3-recovery-and-create.md` lands first; plan follows.

The deferred-items section at [docs/superpowers/specs/2026-05-04-ffi-b2-vault-unlock-design.md](docs/superpowers/specs/2026-05-04-ffi-b2-vault-unlock-design.md) "Non-goals (YAGNI)" carries the original carry-over context — read it before requesting the brainstorming skill.

## (3) Open decisions and risks

### Decisions made and load-bearing for B.3

These are the B.2 decisions that will constrain B.3's brainstorm:

1. **Bridge crate stays the single source of FFI code truth**. New B.3 surface (`open_with_recovery`, `create_vault`) must live there first; PyO3 and uniffi project from it. Renames driven by foreign-language codegen (like B.2's `close → wipe`) stay projection-only — bridge crate's API doesn't change to accommodate.
2. **3-variant thinned error preserves §13 anti-oracle conflation**. `WrongPasswordOrCorrupt` does NOT split. `VaultMismatch` and `CorruptVault { message }` are the structural extension points. New B.3 errors fold into one of the three or are added as a 4th distinct user-actionable category — never as an inner-cause sub-variant.
3. **Bytes-not-string at the FFI boundary for secret inputs**. Caller-side zeroize discipline is the documented contract; wrapper-side `Vec<u8>` is zeroized after the bridge call; bridge wraps into `SecretBytes` for the durable copy. B.3 must follow this pattern for the mnemonic input + the password input.
4. **Explicit close + RAII safety net**. Python `with`, Swift `defer { wipe() }`, Kotlin `.use { }` (auto-AutoCloseable). For `create_vault`'s recovery-mnemonic output: the foreign-side caller reads it once, then it auto-zeroizes on handle close.

### Risks for B.3 specifically

- **Mnemonic input shape** is the highest-uncertainty design point. Strings have caller-zeroize tradeoffs in Python (`str` is immutable, no zeroize); `bytearray(b" ".join(words))` shape moves the locus of complexity foreign-side. List[str] in Python forces uniffi-side `Vec<String>` which has its own zeroize gaps.
- **`create_vault`'s recovery-mnemonic output across uniffi** may need a new error variant for "mnemonic generation failed" or ride existing `CorruptVault { message }` for entropy-source failures.
- **Test fixture extension**: B.2 added `golden_vault_002/` for cross-vault mismatch. B.3 may need a 3rd fixture for `open_with_recovery` if the recovery KEK path needs a distinct vault to avoid contaminating golden_vault_001's invariants. Decision deferred until needed.

### Pre-existing technical debt (filed, not folded into this PR)

- ~~**Issue #23 — Repo-wide cargo fmt drift** in unrelated files (predates B.2 branch). To be addressed in a single follow-up commit on `main`.~~ **Closed by `cedaccc`** on `main` post-merge — pure rustfmt cosmetics, zero logic changes, all gates re-verified green.

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

# IMPORTANT: re-build the maturin dylib BEFORE running pytest.
# Without this, .venv carries the pre-merge .so and the new B.2 symbols
# (`open_with_password`, `WrongPasswordOrCorrupt`, etc.) are missing —
# pytest fails with `AttributeError: module 'secretary_ffi_py' has no attribute …`.
( cd ffi/secretary-ffi-py && uv run maturin develop --release --uv )

uv run --directory ffi/secretary-ffi-py pytest
uv run core/tests/python/conformance.py
uv run core/tests/python/spec_test_name_freshness.py
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh

# Expected: 479 passed + 9 ignored cargo; clippy clean; fmt OK; 10 pytest;
# PASS conformance + freshness; 7/7 Swift; 7/7 Kotlin.

# Begin Sub-project B.3 with brainstorm. Read the deferred-items section
# of docs/superpowers/specs/2026-05-04-ffi-b2-vault-unlock-design.md first.
# Then: /brainstorm
```

---

## Closing inventory

- **Branch:** `feat/ffi-b2-vault-unlock` (squash-merged + deletable; current work happens on `main`)
- **Total commits since branching from `main@959c6ed`:** ~19 on the feature branch (10 implementation + 5 review fix-ups + 1 mid-execution baton + 3 doc/handoff). Squash-merged to `main` as `4d0fffc`.
- **Workspace tests:** 479 + 9 ignored
- **Pytest:** 10 (3 B.1 + 7 B.2)
- **Swift smoke:** 7 (3 B.1.1 + 4 B.2)
- **Kotlin smoke:** 7 (3 B.1.1.1 + 4 B.2)
- **Bridge crate:** 22 unit tests (11 in `error.rs` + 7 in `identity.rs` + 4 in `unlock.rs`); pure-safe Rust; exact-pinned `zeroize = "=1.8.2"`.
- **PR:** [#24](https://github.com/hherb/secretary/pull/24) squash-merged as `4d0fffc`.
- **Issue:** [#23](https://github.com/hherb/secretary/issues/23) closed as completed by `cedaccc`.
- **Companion routine** `trig_018gYtGpiycgLXqUsDpV2NZD` (weekly uniffi Closeable-trait watch) is **disabled** (`enabled: false` via RemoteTrigger) — uniffi 0.31's auto-AutoCloseable was confirmed during Task 9, so the watch is satisfied. To delete fully (rather than disable): https://claude.ai/code/routines/trig_018gYtGpiycgLXqUsDpV2NZD. A new watch can be set up later if the next major uniffi version changes that behavior.
