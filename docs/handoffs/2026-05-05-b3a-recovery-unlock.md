# NEXT_SESSION.md

**Session date:** 2026-05-05 (Sub-project B.3a — recovery-phrase unlock through FFI)
**Status:** Sub-project B.3a complete; PR pending merge. The recovery-phrase unlock path is now exposed across PyO3 (Python) and uniffi (Swift / Kotlin) via the existing shared `secretary-ffi-bridge` crate. `FfiUnlockError` grew from 3 → 5 variants. With B.3a done, the FFI surface includes both unlock entry points; B.3b expands it with `create_vault` (the output-direction mnemonic case + the deferred "how does `Sensitive<T>` materialize on the foreign side?" question).

## (1) What we shipped this session

| Task | Commit(s) | What landed |
|---|---|---|
| 1 — JSON pin + drift assert | `e01b3cf`, `ae82363` | `recovery_mnemonic_phrase` pinned in `golden_vault_{001,002}_inputs.json`; `bip39::Mnemonic::from_entropy(entropy).to_string() == pinned_phrase` drift-detection assertion in `core/tests/common/fixture_builder.rs`. Vault bytes unchanged. Review fix-up: mirrored JSON field order in the `Inputs` struct for readability. |
| 2 — bridge `error.rs` | `7923280`, `3a3bf95` | `FfiUnlockError` grew 3 → 5 variants (`WrongMnemonicOrCorrupt`, `InvalidMnemonic { detail }`); `CorruptVault.message` renamed to `.detail` for naming uniformity; B.2's defensive `From<>` arms for the recovery-only variants promoted to active mappings; +3 net unit tests. Review fix-up: rustfmt + clarified the `CorruptVault.detail` field rustdoc with the rename rationale. |
| 3 — bridge `unlock.rs` | `d25b085`, `5acb634` | `pub fn open_with_recovery(&[u8], &[u8], &[u8])` added with UTF-8-validation seam; +5 integration tests pinning all error paths against `golden_vault_{001,002}/`. Review fix-up: dropped a dead `VAULT_002_TOML` constant and synced the unlock.rs module-doc against the new shape. |
| 4 — bridge `lib.rs` | `6b64530`, `cbc8897` | Re-exports `open_with_recovery`; crate-doc updated to mention 5-variant error and the bytes-in mnemonic contract. Incidental fix-up: cleared two pre-existing rustdoc warnings in the bridge crate. |
| 5 — PyO3 wrapper | `ff3a0e3`, `0c0e58a` | `#[pyfunction] open_with_recovery`; 2 new `create_exception!` macros (`WrongMnemonicOrCorrupt`, `InvalidMnemonic`); `From<FfiUnlockError> for PyErr` extended for the 5-variant shape and the renamed `detail` field; wrapper-side `Vec<u8>` zeroize for the mnemonic input. Review fix-up: promoted `use zeroize::Zeroize` to crate-level. |
| 6 — pytest | `29d5787` | +6 tests; `_golden_vault_phrase(n)` helper reads `recovery_mnemonic_phrase` from inputs JSON; `bytearray` caller-zeroize parity with B.2's password-path coverage. |
| 7 — UDL + uniffi glue | `a624a90`, `c68833e` | UDL gains 2 `[Error]` variants + 1 namespace function; uniffi `UnlockError` mirrors the bridge's 5-variant shape; +2 mapping tests; `CorruptVault` test renamed for the `detail` field. Review fix-up: updated stale 3-variant references in uniffi crate doc / rustdoc to 5-variant. |
| 8 — Swift + Kotlin smoke | `f8284e0`, `2aea215` | +4 asserts each (success / wrong mnemonic / invalid length / vault mismatch); phrases loaded from inputs JSON via `SECRETARY_GOLDEN_VAULT_DIR` — no hardcoded 24-word strings. Review fix-up: replaced a regex-based JSON parser in the Kotlin runner with a tiny tokenizer for robustness. |
| 9 — READMEs + ROADMAP | `2fd61ca` | Bridge README updated in place (3 → 5 variant surface) plus appended B.3a delta section; PyO3 + uniffi crate READMEs gain B.3a usage sections (Python `bytearray` + zeroize discipline; Swift `defer { wipe() }`; Kotlin `.use { }`); top-level README + ROADMAP advanced (date, test counts, progress bar, B.3a entry flipped ✅). |
| 10 — NEXT_SESSION + handoff | (this commit) | This file + `docs/handoffs/2026-05-05-b3a-recovery-unlock.md`. |

### Verification at session close

| Check | Result |
|---|---|
| `cargo test --release --workspace` | **489 passed + 9 ignored, 0 failed** (was 479 + 9 at branch start; +10 from B.3a — +8 in `secretary-ffi-bridge`, +2 in `secretary-ffi-uniffi`) |
| `cargo clippy --release --workspace -- -D warnings` | clean |
| `cargo fmt --all -- --check` | OK |
| `uv run --directory ffi/secretary-ffi-py pytest` | **16 passed** (was 10 — added 6 B.3a tests) |
| `uv run core/tests/python/conformance.py` | **PASS** |
| `uv run core/tests/python/spec_test_name_freshness.py` | **PASS** (96 resolved, 0 unresolved, 2 suppressed by allowlist) |
| `bash ffi/secretary-ffi-uniffi/tests/swift/run.sh` | **12/12 PASS** (was 8/8 — added 4 B.3a asserts) |
| `bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh` | **12/12 PASS** (was 8/8 — added 4 B.3a asserts) |

### Per-crate breakdown of the 489-test workspace

- `secretary-core` — 448 (unchanged)
- `secretary-ffi-bridge` — **30** (was 22; +8 net: +3 in `error.rs` after B.2's defensive `From` arms got promoted to active mappings + the `InvalidMnemonic` triplet was expanded out of the single defensive test + the `CorruptVault.message → detail` regression pin; +5 in `unlock.rs` for the recovery-path success / wrong-mnemonic / wrong-length / invalid-UTF-8 / vault-mismatch integration tests)
- `secretary-ffi-py` — 3 (unchanged Rust unit tests; the 16 pytest count is separate)
- `secretary-ffi-uniffi` — **8** (was 6; +2 mapping tests for the new error variants)

### Two-stage review caught real bugs (and confirmed real wins) — same shape as B.2

The subagent-driven-development workflow's two-stage review (spec compliance → code quality) drove fix-up commits across the implementation tasks; every flagged issue was addressed with a separate fix-up commit before moving on. Concrete examples:

- **Task 2** (bridge error.rs): code quality flagged unclear rustdoc on the renamed `detail` field — `3a3bf95` clarified the rename rationale inline so future readers don't need to consult the spec doc.
- **Task 3** (bridge unlock.rs): code quality found a dead `VAULT_002_TOML` constant (B.2 leftover) and stale module-doc text. `5acb634` cleared both.
- **Task 4** (bridge lib.rs): controller spotted two pre-existing rustdoc warnings (predates B.3a) while reviewing the lib.rs delta; filed-as-fixed inline per the user's "fix every issue" preference rather than deferring (`cbc8897`).
- **Task 5** (PyO3): code quality flagged the `use zeroize::Zeroize` import being inside a function body. `0c0e58a` promoted it to crate-level.
- **Task 7** (uniffi): code quality found stale `3-variant` references in the uniffi crate's rustdoc that B.3a's edits hadn't touched. `c68833e` swept them to `5-variant`.
- **Task 8** (Swift + Kotlin smoke): code quality flagged a regex-based JSON parse in the Kotlin runner as fragile (would break on whitespace variations); `2aea215` replaced it with a tiny tokenizer that mirrors the Swift runner's robustness.

The user's "fix every review issue before merging — no technical debt" preference held throughout. No issues filed for follow-up; everything in scope landed before the doc commit.

## (2) What's next, with concrete acceptance criteria

### Sub-project B.3b — `create_vault` through the FFI

Brainstorm + spec needed before code. Open design questions to settle:

1. **Output-direction `Sensitive<T>` materialization on the foreign side.** `create_vault` returns a freshly-generated 24-word BIP-39 mnemonic that must cross the FFI back to the caller. How do Python `bytes`/`bytearray`, Swift `Data`, and Kotlin `ByteArray` handle "this came from a `Sensitive<T>`" — what zeroize discipline is documented? Options: one-shot accessor that consumes the inner Sensitive (zeroize on read); copy-into-foreign-allocated-buffer; new opaque handle type holding both the identity and the mnemonic with a `take_recovery_mnemonic_once()` accessor. (Same question deferred from B.2's "no genuinely-secret bytes crossing back" non-goal and from B.3a's `recovery_phrase()`-accessor non-goal.)
2. **RNG seam.** Does `create_vault` accept a foreign-side RNG, or is the OS CSPRNG always used? First-party clients always want OS CSPRNG; tests want deterministic seeded RNG; uniffi's marshalling of "function pointer to a foreign RNG" is non-trivial.
3. **KDF params ergonomics.** Per current Rust core, `create_vault` enforces the §1.2 v1 floor (`memory_kib >= 65536`). Does the FFI expose params as a struct, or always use the default? The default is fine for production; tests need sub-floor for speed (`create_vault_unchecked`). FFI should NOT expose `unchecked` — first-party clients should hit the safe path.
4. **`WeakKdfParams` reachability.** B.3a left this defensively folded into `CorruptVault { detail }`. With B.3b's `create_vault` reachable, does it become its own variant (distinct user remedy: "your params are too weak") or stay folded (the safe entry point won't return it)? Decision belongs to B.3b's design pass.
5. **Error surface cardinality.** B.3a's 5-variant shape may grow to 6 if mnemonic-generation failure or weak-KDF-params surface as their own user-actionable categories. The §13 anti-oracle conflation must continue to hold.

Acceptance criteria for B.3b (refined during brainstorm):
- [ ] `create_vault(password, kdf_params?, recovery_output: ?)` exposed across PyO3 + uniffi via the bridge crate.
- [ ] One-shot recovery-mnemonic accessor that consumes `Sensitive<Mnemonic>` on read.
- [ ] Test count grows: cargo workspace +~10, pytest +~5, Swift +~3, Kotlin +~3.
- [ ] All gates green at session close (cargo, clippy, fmt, pytest, conformance, freshness, both smoke runners).
- [ ] §13 anti-oracle conflation continues to hold OR is explicitly extended with documented rationale.
- [ ] Spec at `docs/superpowers/specs/<date>-ffi-b3b-create-vault-design.md` lands first; plan follows.

The deferred-items section in [docs/superpowers/specs/2026-05-04-ffi-b3a-recovery-unlock-design.md](docs/superpowers/specs/2026-05-04-ffi-b3a-recovery-unlock-design.md) "Non-goals (YAGNI)" carries the original carry-over context — read it before requesting the brainstorming skill.

## (3) Open decisions and risks

### Decisions made and load-bearing for B.3b

These are the B.3a decisions that constrain B.3b's brainstorm:

1. **Bridge crate stays the single source of FFI code truth.** New B.3b surface (`create_vault`) must live there first; PyO3 and uniffi project from it. Renames driven by foreign-language codegen stay projection-only — bridge crate's API doesn't change to accommodate.
2. **5-variant thinned error preserves §13 anti-oracle conflation across both unlock paths.** New B.3b errors fold into one of the existing five OR are added as a 6th distinct user-actionable category — never as an inner-cause sub-variant. `create_vault` is not a decryption path so doesn't add another anti-oracle variant; mnemonic-generation failure (if it surfaces at all) and weak-KDF-params are the two candidate-new-variants for the design discussion.
3. **Bytes-not-string at the FFI boundary for secret inputs.** B.3a's mnemonic-input pattern matches B.2's password-input pattern: `Vec<u8>` with caller-zeroize discipline; bridge wraps into `SecretBytes` for the durable copy; wrapper-side zeroize after the bridge call. B.3b's password input must follow the same pattern.
4. **`CorruptVault.detail` field naming uniform across all layers.** B.3a propagated the name from the uniffi-side projection-only rename (B.2-era) into the bridge crate field itself. The only remaining uniffi-side rename is `close → wipe`.
5. **Explicit close + RAII safety net stays in place.** Python `with`, Swift `defer { wipe() }`, Kotlin `.use { }` (auto-AutoCloseable). For B.3b's `create_vault` with mnemonic output: the foreign-side caller reads the mnemonic once, then it auto-zeroizes on handle close (or on the dedicated `take_recovery_mnemonic_once()` accessor returning).

### Risks for B.3b specifically

- **Output-direction `Sensitive<T>` marshalling** is the highest-uncertainty design point. Each foreign language has different memory ownership semantics; the "right" answer might be a different one per language (e.g. Python `bytes` immutable vs. Swift `Data` value-type vs. Kotlin `ByteArray` reference-type all have distinct lifetime and zeroize stories). The brainstorm should explicitly enumerate the per-language story before settling on a uniform shape.
- **Test fixture extension.** B.3b's `create_vault` produces fresh randomness, so it can't pin against the existing `golden_vault_{001,002}/` byte-fixtures. Tests likely build synthetic vaults at runtime via seeded RNG; round-trip assertions (create-then-open-with-password / create-then-open-with-recovery) become the primary contract pin. No new on-disk fixtures expected.
- **Weak KDF params reachability.** Currently `WeakKdfParams` is defensively folded into `CorruptVault { detail }`. If B.3b chooses to surface it as its own variant, that's a 6th variant (preserving the §13 property) and a renamed exception class on Python; if it stays folded, the foreign caller has no way to distinguish "your KDF params are too weak" from "the vault file is malformed" — a UI affordance loss that may matter for the create-vault flow specifically (where the user is choosing params, not reading them).

### Pre-existing technical debt

None outstanding from B.3a. The two pre-existing rustdoc warnings cleared in `cbc8897` (Task 4) were the only incidental items found and they were folded inline rather than filed as a separate issue.

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
# Without this, .venv carries the pre-merge .so and the new B.3a symbols
# (`open_with_recovery`, `WrongMnemonicOrCorrupt`, `InvalidMnemonic`) are
# missing — pytest fails with `AttributeError: module 'secretary_ffi_py'
# has no attribute …`.
( cd ffi/secretary-ffi-py && uv run maturin develop --release --uv )

uv run --directory ffi/secretary-ffi-py pytest
uv run core/tests/python/conformance.py
uv run core/tests/python/spec_test_name_freshness.py
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh

# Expected: 489 passed + 9 ignored cargo; clippy clean; fmt OK; 16 pytest;
# PASS conformance + freshness; 12/12 Swift; 12/12 Kotlin.

# Begin Sub-project B.3b with brainstorm. Read the deferred-items section
# of docs/superpowers/specs/2026-05-04-ffi-b3a-recovery-unlock-design.md first.
# Then: /brainstorm
```

---

## Closing inventory

- **Branch:** `feat/ffi-b3a-recovery-unlock` (PR-pending; squash-merge target is `main`)
- **Total commits since branching from `main@ea5d530`:** 17 on the feature branch (8 task-implementation + 7 review-or-incidental fix-ups + 2 doc/handoff). Will squash to 1 in the PR.
- **Workspace tests:** 489 + 9 ignored
- **Pytest:** 16 (10 from B.1 + B.2 + 6 B.3a)
- **Swift smoke:** 12/12 (3 B.1.1 + 5 B.2 + 4 B.3a)
- **Kotlin smoke:** 12/12 (3 B.1.1.1 + 5 B.2 + 4 B.3a)
- **Bridge crate:** 30 unit tests (14 in `error.rs` + 7 in `identity.rs` + 9 in `unlock.rs`); pure-safe Rust; exact-pinned `zeroize = "=1.8.2"`.
- **PR:** [#NN](https://github.com/hherb/secretary/pull/NN) (URL recorded after `gh pr create` returns)
