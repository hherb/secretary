# NEXT_SESSION.md

**Session date:** 2026-05-03 (Sub-project B.1.1 — Swift via uniffi)
**Session-specific handoff** for the B.1.1 session. The remaining half
of the FFI binding boilerplate (uniffi UDL + macOS-host Swift smoke
runner) ships in this branch / PR; Kotlin smoke runner is deferred to
B.1.1.1 per the start-of-session decision.

For the comprehensive rolling-baton (full carry-over context, deferred-
with-reasons items, external-review track, etc.), continue to read
[`secretary_next_session.md`](secretary_next_session.md) — that file is
the multi-session entry point and remains authoritative; this file is
just the single-session delta.

---

## (1) What we shipped this session

Five logical commits on branch `feat/ffi-b1-1-uniffi-boilerplate`,
each one verifiable independently and ordered so an early step can be
reverted without unwinding later ones. The squash-merge SHA on `main`
will be recorded in a post-merge follow-up commit (matching the
post-PR-20 pattern at `ca936c6`).

| SHA | Commit | What changed |
|---|---|---|
| `5d770d3` | feat(ffi-uniffi): B.1.1 step 1 — pure-Rust contract for add + version | Rust unit tests pinning `add(2, 3) == 5`, the `wrapping_add` overflow contract, and `version() == FORMAT_VERSION` — independent of the uniffi pipeline so a later UDL/bindgen regression can't silently weaken the underlying behavior. |
| `57aecae` | feat(ffi-uniffi): B.1.1 step 2 — wire uniffi UDL → cdylib pipeline | Adds `uniffi = "0.31"` (semver range, both `[dependencies]` with `cli` feature and `[build-dependencies]` with `build` feature); `build.rs` calling `uniffi::generate_scaffolding`; in-crate `[[bin]] uniffi-bindgen` target so bindgen version is locked to crate's `uniffi` dep; `src/secretary.udl` namespace; `lib.rs` `include_scaffolding!()` macro + `#![allow(unsafe_code)]` carve-out (mirrors `secretary-ffi-py`'s `forbid → deny` pattern). |
| `dcb722c` | feat(ffi-uniffi): B.1.1 step 3 — macOS-host Swift smoke runner | `tests/swift/main.swift` with three pinned-value asserts (mirrors the Rust unit tests) using a named `EXPECTED_FORMAT_VERSION` constant; `tests/swift/run.sh` orchestration script (cargo build → uniffi-bindgen Swift → swiftc → run with `DYLD_LIBRARY_PATH`); `.gitignore` excludes for `bindings/` and the compiled smoke binary + `.dSYM`. |
| `fc0341e` | docs(ffi-uniffi): B.1.1 step 4 — README + sibling-crate cross-references | New `ffi/secretary-ffi-uniffi/README.md` parallel in structure to the Python crate's README. Refreshed three stale lines in `secretary-ffi-py/README.md` (cache-stickiness scope, Swift/Kotlin status, lint-discipline cross-reference). |
| `cd73b4b` | docs: refresh README.md + ROADMAP.md for B.1.1 (Swift uniffi binding) | Top-level status table flipped uniffi entry to ✅ Swift / B.1.1.1 Kotlin pending; test totals 448 → 451; `forbid(unsafe_code)` claim corrected (now `core/` only; both FFI crates carry `deny` carve-out); Sub-project B section in ROADMAP gained a B.1.1.1 phase entry; ASCII progress bar advanced 8 → 12 chars. |

### Verification at session close

All gates green:

| Check | Result |
|---|---|
| `cargo test --release --workspace` | **451 passed + 6 ignored, 0 failed** (was 448 + 6 pre-B.1.1; +3 new uniffi unit tests) |
| `cargo clippy --release --workspace -- -D warnings` | **clean**, exit 0 |
| `uv run --directory ffi/secretary-ffi-py pytest` | **3 passed** (no regression from B.1) |
| `uv run core/tests/python/conformance.py` | **all 5 sections PASS** |
| `uv run core/tests/python/spec_test_name_freshness.py` | **96 resolved + 0 unresolved + 2 allowlisted**, PASS |
| `ffi/secretary-ffi-uniffi/tests/swift/run.sh` | **all 3 Swift assertions PASS** end-to-end through cdylib + C ABI bridge |

### Decisions made at start of session

1. **uniffi version pin → semver range.** `uniffi = "0.31"` (resolved
   `0.31.1` at session close) in both `[dependencies]` and
   `[build-dependencies]`. uniffi is pre-1.0 but off the crypto path,
   so the `tempfile = "=3.27.0"` exact-pin discipline doesn't apply.
   Mirrors `pyo3 = "0.28"` in the sibling crate.
2. **uniffi UDL location → single UDL inside the crate.** One UDL at
   `ffi/secretary-ffi-uniffi/src/secretary.udl`; namespace `secretary`
   matches the `include_scaffolding!()` argument and the build.rs
   path. Trivial answer for a single-binding-crate project; called
   out so a future contributor doesn't have to re-derive.
3. **Kotlin smoke runner → defer to B.1.1.1.** Confirmed by user:
   "one language at a time, regardless of what is already installed."
   bindgen already emits Kotlin via `--language kotlin`; only the
   JVM/JNI runner harness is missing.

### How uniffi-bindgen is installed (no global install required)

Per Mozilla's recommended pattern for uniffi 0.30+: an in-crate
`[[bin]] uniffi-bindgen` target ships with the crate, with a one-line
`fn main() { uniffi::uniffi_bindgen_main() }`. Locks the bindgen
version to the crate's `uniffi` dep; no `cargo install
uniffi-bindgen-cli` step. Net win in determinism — the cost is one-time
compilation of the bindgen binary on each contributor's machine.

---

## (2) What's next, with concrete acceptance criteria

### A. Sub-project B.1.1.1 — Kotlin smoke runner (small, bounded)

The remaining shard of B.1.1. uniffi-bindgen already emits Kotlin
bindings (`--language kotlin`); only the runner harness is missing.

**Acceptance criteria:**

1. `ffi/secretary-ffi-uniffi/tests/kotlin/Main.kt` with the same three
   pinned-value asserts as `tests/swift/main.swift`:
   - `add(2u, 3u) == 5u`
   - `add(UInt.MAX_VALUE, 1u) == 0u` (wrapping contract)
   - `version().toInt() == 1` (FORMAT_VERSION)
2. `ffi/secretary-ffi-uniffi/tests/kotlin/run.sh` orchestration script,
   parallel in shape to `tests/swift/run.sh`:
   - cargo build the cdylib
   - cargo run --bin uniffi-bindgen -- generate --language kotlin
   - kotlinc compile + JVM run
   - exit 0 only if every assertion passes
3. JVM-only path (no Android emulator). The `jna` JAR (uniffi's Kotlin
   bindings depend on `net.java.dev.jna:jna`) needs to land on the
   classpath; document the script's bootstrap (download via Gradle
   wrapper, vendor a minimal JAR, or document a one-time `brew install
   kotlin` + manual JNA install).
4. Bindings dir (`ffi/secretary-ffi-uniffi/bindings/kotlin/`) is
   already covered by the existing `bindings/` gitignore stanza added
   in B.1.1; no .gitignore changes needed.
5. README updated: replace "What B.1.1 deliberately does NOT do →
   Kotlin smoke runner" entry with a Kotlin-layer build & test section
   parallel to the Swift one.
6. ROADMAP.md flipped: B.1.1.1 ⏳ → ✅; Sub-project B status line
   updated; ASCII progress bar advanced again.

**Estimate:** ~1.5–2 hours focused. The hardest single sub-question is
the JNA classpath bootstrap (uniffi's Kotlin output requires `jna` at
runtime; how it lands on the classpath is the only non-mechanical
choice).

### B. Sub-project B.2 (after B.1.1.1) — first vault crypto exposed

Vault unlock + open exposed across all three languages. First fallible
operations means `PyResult` / Swift `throws` / Kotlin `@Throws` error
marshalling becomes first-class, and first secret-bearing types across
the FFI boundary need a deliberate design pass on zeroize discipline
through Python's GC, Swift's ARC, and the JVM's GC.

**This warrants its own brainstorming + spec + plan cycle**, not an
in-session pass. The spec needs to answer:

- How do `Sensitive<T>` / `SecretString` cross the FFI boundary?
  Borrowed-only, copy-only, or move-with-zeroize-on-foreign-drop?
- How does `UnlockError::WeakKdfParams` get marshaled to a foreign
  exception type? B.2's `open_with_password` wrapper must NOT silently
  downgrade — should be a first-class exception in every binding.
- Does `open_with_password` return a context manager so the unlocked
  identity is zeroized at scope exit (Python `__exit__`, Swift `defer`,
  Kotlin `use`)?
- `RecordFieldValue::{Text(SecretString), Bytes(SecretBytes)}` — how
  do they materialise into each foreign language? Python `bytes`
  (copies, defeats the zeroize), `bytearray` (mutable, can be wiped),
  or a custom `SecretBytes` type with a context-manager API?

---

## (3) Open decisions and risks

### Decisions to make at the start of B.1.1.1

1. **JNA distribution path.** Options:
   - (a) Vendor a minimal `jna.jar` under `ffi/secretary-ffi-uniffi/tests/kotlin/lib/`
     and gitignore it (fetch in `run.sh`).
   - (b) Use a Gradle wrapper at `ffi/secretary-ffi-uniffi/tests/kotlin/`
     with one resolved dep — heavier but standard.
   - (c) Document a one-time `brew install kotlin` + manual JNA install
     and have run.sh check for both — lightest.
   - Recommend (a) for parity with the swift runner's "self-contained
     `run.sh`" property.
2. **Kotlin compile target.** Latest stable Kotlin (2.0+) on the JVM,
   targeting `--release 21` (matches the Android Gradle Plugin's
   floor). No need for KMP / multiplatform here — JVM target only.
3. **Naming convention for the Kotlin entry-point.** `Main.kt` with a
   top-level `main()` function vs. `MainKt.kt` with a class. Recommend
   `Main.kt` + top-level `main()` (idiomatic; matches how Kotlin
   compiles to a `MainKt.class` automatically).

### Risks (mostly upstream-managed; flagging for awareness)

- **`hkdf` 0.13.0 carry-over.** Released 2026-03-30; does NOT add
  zeroize to internal HMAC state and DOES rename `Hkdf` →
  `GenericHkdf` (with source-compat aliases). Watch is recurring
  (Mondays 09:00 Australia/Perth). Flagged in
  [`core/src/crypto/kdf.rs:216-223`](core/src/crypto/kdf.rs#L216-L223).
  No action needed this session; carry-over remains.
- **External paid review** is gated on calendar / availability of a
  reviewer with FIPS 203 / 204 implementer experience. B.1.1.1 work
  proceeds in parallel — FFI doesn't touch `core/src/`, so any spec
  clarification the external reviewer surfaces can land alongside FFI
  work without conflict.
- **Squash-merged worktree cleanup.** Once the PR for
  `feat/ffi-b1-1-uniffi-boilerplate` squash-merges, prune the worktree
  (`git worktree remove .worktrees/feat-ffi-b1-1-uniffi-boilerplate`)
  and delete the local branch (`git branch -D
  feat/ffi-b1-1-uniffi-boilerplate`). Remote branch on origin can be
  deleted via the GitHub UI or `git push origin --delete
  feat/ffi-b1-1-uniffi-boilerplate` if not already auto-deleted.

---

## (4) Exact commands to resume

```bash
# 1. Start from a clean main (after PR for B.1.1 has merged)
cd /Users/hherb/src/secretary
git checkout main
git pull --ff-only

# 2. Re-baseline tests (everything should still pass)
cargo test --release --workspace
cargo clippy --release --workspace -- -D warnings
uv run --directory ffi/secretary-ffi-py pytest
uv run core/tests/python/conformance.py
uv run core/tests/python/spec_test_name_freshness.py
ffi/secretary-ffi-uniffi/tests/swift/run.sh

# Expected: 451 passed + 6 ignored, clippy clean, pytest 3 passed,
#   conformance PASS, spec freshness 96 / 0 / 2, Swift smoke runner
#   3/3 PASS.

# 3. Create the B.1.1.1 worktree (project-local convention; see
#    feedback_worktree_location memory)
git worktree add .worktrees/feat-ffi-b1-1-1-kotlin-smoke-runner \
  -b feat/ffi-b1-1-1-kotlin-smoke-runner
cd .worktrees/feat-ffi-b1-1-1-kotlin-smoke-runner

# 4. Read the design anchor and the rolling-baton:
#    /Users/hherb/.claude/plans/we-are-starting-with-logical-newt.md
#    /Users/hherb/src/secretary/secretary_next_session.md
#    (the latter has the full B.1.1.1 plan-of-attack)
```

---

## Closing inventory

- **Tests:** 451 + 6 ignored (cargo); 3 passed (Python pytest); 5
  conformance sections PASS; spec freshness 96 / 0 / 2; Swift smoke
  runner 3/3 PASS.
- **Clippy:** clean with `-D warnings`.
- **Sub-project A:** feature-complete; Phase A.7 internal track ✅,
  external (paid) track pending.
- **Sub-project B:** B.1 (Python) ✅; B.1.1 (Swift via uniffi) ✅;
  B.1.1.1 (Kotlin smoke runner) is the recommended next concrete unit
  of work; B.2 (vault crypto exposure) needs its own brainstorm/spec/
  plan cycle.
- **Sub-project C / D:** not started.
- **`docs/TODO_FINAL_POLISHING.md`:** 2 conditionally-deferred
  sections remaining (no actionable trigger today; file deletes itself
  when both close).
- **PR for B.1.1 status:** open at session close. Five commits on
  `feat/ffi-b1-1-uniffi-boilerplate`. Squash-merge SHA to be recorded
  in a post-merge follow-up commit.
