# NEXT_SESSION.md

**Session date:** 2026-05-03 (Sub-project B.1.1.1 — Kotlin smoke runner)
**Session-specific handoff** for the B.1.1.1 session. The Kotlin
foreign-language layer of the uniffi binding pair shipped — same UDL,
JVM-host runner driven through JNA, asserting the same three pinned
values as the Swift and Rust layers. With B.1, B.1.1, and B.1.1.1 done,
**all three FFI binding boilerplates are operational**; B.2 is the
next unit of work (vault crypto exposure across all three languages).

For the comprehensive rolling-baton (full carry-over context, deferred-
with-reasons items, external-review track, etc.), continue to read
[`secretary_next_session.md`](secretary_next_session.md) — that file is
the multi-session entry point and remains authoritative; this file is
just the single-session delta.

---

## (1) What we shipped this session

Three logical commits on branch `feat/ffi-b1-1-1-kotlin-smoke-runner`,
each one verifiable independently and ordered so an early step can be
reverted without unwinding later ones. The squash-merge SHA on `main`
will be recorded in a post-merge follow-up commit (matching the
post-PR-21 pattern at `ca936c6`).

| SHA | Commit | What changed |
|---|---|---|
| `f6370bf` | feat(ffi-uniffi): B.1.1.1 — JVM-host Kotlin smoke runner | New `tests/kotlin/Main.kt` with three pinned-value asserts (`add(2u, 3u) == 5u`, `add(UInt.MAX_VALUE, 1u) == 0u`, `version() == 1u`) using a named `EXPECTED_FORMAT_VERSION` constant; new `tests/kotlin/run.sh` orchestration script (cargo build → uniffi-bindgen Kotlin → SHA-256-verified `jna-5.14.0.jar` fetch from Maven Central → kotlinc `-include-runtime` fat-jar → `java -Djna.library.path=… MainKt`); `.gitignore` excludes for `tests/kotlin/lib/` (cached JNA) and `tests/kotlin/secretary_smoke.jar` (compiled fat-jar). Mirrors the structure of the Swift smoke runner. |
| `805b575` | docs(ffi-uniffi): B.1.1.1 — README cross-language section for Kotlin | `ffi/secretary-ffi-uniffi/README.md` updated: opening line now mentions the B.1.1 / B.1.1.1 split; "Build & test" intro switches from "two test layers" to "three test layers" (Rust + Swift + Kotlin); new "Kotlin layer (JVM host)" section parallel to the Swift one (5-step pipeline, JNA pin rationale, `kotlinc` / `java` prerequisites with brew + SDKMAN install hints); "Where the build products live" gains Kotlin entries; scope table now shows both Swift and Kotlin signatures side-by-side; "What B.1.1 deliberately does NOT do" rewritten as "What B.1.1 / B.1.1.1 deliberately do NOT do" (drops the "no Kotlin smoke runner" bullet, gains an Android-emulator deferral bullet). |
| _(this commit; SHA recorded post-merge in a follow-up — self-referential SHAs cannot be filled in the same commit they refer to)_ | docs: refresh README.md + ROADMAP.md + NEXT_SESSION.md for B.1.1.1 | Top-level status table flipped uniffi entry to ✅ B.1.1 + B.1.1.1 (was "Kotlin smoke runner deferred to B.1.1.1"); test-count narrative clarified that B.1.1.1's contribution is JVM-side (no new Rust tests); ROADMAP.md ASCII progress bar advanced 12 → 14 chars; ROADMAP § "Sub-project B" header updated; B.1.1.1 entry flipped ⏳ → ✅ with full pipeline description; NEXT_SESSION.md updated to record this session and recommend B.2 as next unit; timestamped handoff copy added to `docs/handoffs/2026-05-03-b1-1-1-ffi-uniffi-kotlin.md`. |

### Verification at session close

All gates green:

| Check | Result |
|---|---|
| `cargo test --release --workspace` | **451 passed + 6 ignored, 0 failed** (no new Rust tests; B.1.1.1's contribution is JVM-side) |
| `cargo clippy --release --workspace -- -D warnings` | **clean**, exit 0 |
| `uv run --directory ffi/secretary-ffi-py pytest` | **3 passed** (no regression from B.1) |
| `uv run core/tests/python/conformance.py` | **all 5 sections PASS** |
| `uv run core/tests/python/spec_test_name_freshness.py` | **96 resolved + 0 unresolved + 2 allowlisted**, PASS |
| `ffi/secretary-ffi-uniffi/tests/swift/run.sh` | **all 3 Swift assertions PASS** end-to-end through cdylib + C ABI bridge |
| `ffi/secretary-ffi-uniffi/tests/kotlin/run.sh` | **all 3 Kotlin assertions PASS** end-to-end through cdylib + JNA bridge |

### Decisions made at start of session

1. **JNA distribution path → option (a): vendor + auto-fetch.**
   `tests/kotlin/lib/` is gitignored; `run.sh` fetches `jna-5.14.0.jar`
   from Maven Central on first run with **SHA-256 verification** on
   every invocation (cached or not). Mirrors the Swift runner's
   "self-contained run.sh" property without committing a binary jar.
   `JNA_VERSION` and `JNA_SHA256` live as named constants near the top
   of `run.sh` so a future bump is one obvious edit.
2. **Kotlin compile target → kotlinc 2.x on JVM (JDK 17+).** Verified
   end-to-end with kotlinc 2.3.21 + OpenJDK 21.0.8 on this host.
   `kotlinc` install via `brew install kotlin` (macOS) or `sdk install
   kotlin` (Linux SDKMAN). Sanity check in `run.sh` emits an actionable
   error message if kotlinc or java is missing.
3. **Naming convention for entry-point → `Main.kt` + top-level
   `main()`.** Compiles to the implicit `MainKt` class (idiomatic
   Kotlin). `java … MainKt` is the launch command.

### How JNA library loading works

uniffi's Kotlin output uses `Native.register(UniffiLib::class.java,
findLibraryName(componentName = "secretary"))` where `findLibraryName`
returns the literal string `"secretary_ffi_uniffi"`. JNA resolves that
name against `-Djna.library.path` first, then the platform default
search path. The runner sets `-Djna.library.path=$TARGET_DIR` so
`libsecretary_ffi_uniffi.dylib` (Linux: `.so`; Windows: `.dll`) is
found alongside the cdylib at runtime. No `LD_LIBRARY_PATH` /
`DYLD_LIBRARY_PATH` env-var fiddling needed — JNA prefers its own
`-D` system property.

### Benign warning observed

uniffi-bindgen tries to auto-format the generated Kotlin with `ktlint`
and emits a non-fatal warning if `ktlint` isn't installed:

```
Warning: Unable to auto-format secretary.kt using ktlint:
  Os { code: 2, kind: NotFound, message: "No such file or directory" }
```

The warning is cosmetic — formatting only — and the unformatted
generated file compiles fine (verified end-to-end). Installing ktlint
(`brew install ktlint`) silences it. Not worth blocking on; flagged
here so future contributors don't waste time chasing it.

---

## (2) What's next, with concrete acceptance criteria

### Sub-project B.2 — first vault crypto exposed

With B.1 (Python), B.1.1 (Swift), and B.1.1.1 (Kotlin) all done, the
boilerplate-pipelines triad is complete. The next unit of work is
exposing the first **fallible, secret-bearing** API across all three
languages: vault unlock + open. This is qualitatively different from
B.1 / B.1.1 / B.1.1.1, which only proved the binding pipeline with
infallible `add` / `version`. B.2 surfaces:

- First fallible operations means **error-marshalling design** becomes
  load-bearing: `PyResult[T]` ergonomics in PyO3, Swift `throws`,
  Kotlin `@Throws` / sealed-class error types in uniffi.
- First secret-bearing types crossing the FFI boundary means
  **zeroize-discipline design** must answer how `Sensitive<T>` /
  `SecretString` / `SecretBytes` materialize (or don't) into Python
  `bytes` / `bytearray`, Swift `Data`, and Kotlin `ByteArray`.
- `UnlockError::WeakKdfParams` (the typed v1 KDF floor at
  `Argon2idParams::V1_MIN_MEMORY_KIB`) must NOT silently downgrade in
  any binding — it has to surface as a first-class exception with the
  same actionable message in every foreign language.

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

**Acceptance criteria for "B.2 ready to start":**

1. Brainstorming session ⇒ design doc covering the three questions
   above + the error-marshalling design.
2. Spec drafted for the foreign-language API: function signatures
   in each of Python, Swift, Kotlin; error types named; ownership /
   lifetime of secret-bearing types named.
3. Plan-of-attack with bite-sized steps (probably one step per
   language, or one step per surface area — TBD by the spec).

**Estimate:** brainstorm + spec is ~1–2 sessions before a single line
of B.2 code is written.

### Smaller pickup items (if delaying B.2)

If a session has less than ~2 hours of focused time and the B.2
brainstorm-cycle feels too large, pickup options carried over from
prior sessions live in the rolling-baton at
[`secretary_next_session.md`](secretary_next_session.md) § "Smaller
pickup items".

---

## (3) Open decisions and risks

### Decisions to make at the start of B.2

The full list of B.2 brainstorm questions is in §(2) above. The two
most consequential, called out here so they're not lost in the prose:

1. **Secret-bearing-type marshalling discipline.** Borrow-only,
   copy-with-foreign-zeroize-on-drop, or copy-with-best-effort-only?
   This shapes the entire B.2 API surface. Bias: borrow-only where
   possible (e.g. `with vault.unlock(...) as identity:` context-
   manager pattern) to keep the lifetime explicit and the
   foreign-side surface area small.
2. **Error-marshalling shape.** Single uniffi `[Throws] Error` with a
   sealed enum of variants vs. per-function-typed errors. Bias:
   single sealed enum for parity with the Rust `ErrorKind` shape, but
   needs a brainstorm pass to confirm the foreign-side ergonomics.

### Risks (mostly upstream-managed; flagging for awareness)

- **`hkdf` 0.13.0 carry-over.** Released 2026-03-30; does NOT add
  zeroize to internal HMAC state and DOES rename `Hkdf` →
  `GenericHkdf` (with source-compat aliases). Watch is recurring
  (Mondays 09:00 Australia/Perth). Flagged in
  [`core/src/crypto/kdf.rs:216-223`](core/src/crypto/kdf.rs#L216-L223).
  No action needed this session; carry-over remains.
- **External paid review** is gated on calendar / availability of a
  reviewer with FIPS 203 / 204 implementer experience. B.2 work
  proceeds in parallel — FFI doesn't touch `core/src/`, so any spec
  clarification the external reviewer surfaces can land alongside FFI
  work without conflict.
- **Squash-merged worktree cleanup.** Two worktrees from now-merged
  branches accumulate at session close:
  `.worktrees/feat-ffi-b1-1-uniffi-boilerplate` (PR #21, merged as
  `21023ea`) — safe to prune now. The current
  `.worktrees/feat-ffi-b1-1-1-kotlin-smoke-runner` will be stale once
  this PR squash-merges.
- **JNA pin currency.** `JNA_VERSION = "5.14.0"` in
  `tests/kotlin/run.sh` is well off the crypto path (smoke-runner
  only; never linked into the cdylib). Bumping it is a single-line
  edit to `JNA_VERSION` + `JNA_SHA256`; bump only when there's a
  reason (e.g. uniffi 0.32+ requires a newer JNA, or a security
  advisory lands against 5.14.0).

---

## (4) Exact commands to resume

```bash
# 1. Start from a clean main (after PR for B.1.1.1 has merged)
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
ffi/secretary-ffi-uniffi/tests/kotlin/run.sh

# Expected: 451 passed + 6 ignored, clippy clean, pytest 3 passed,
#   conformance PASS, spec freshness 96 / 0 / 2, Swift smoke runner
#   3/3 PASS, Kotlin smoke runner 3/3 PASS.

# 3. Prune the (now-merged) worktrees:
git worktree remove .worktrees/feat-ffi-b1-1-uniffi-boilerplate
git branch -D feat/ffi-b1-1-uniffi-boilerplate
git worktree remove .worktrees/feat-ffi-b1-1-1-kotlin-smoke-runner
git branch -D feat/ffi-b1-1-1-kotlin-smoke-runner

# 4. B.2 starts with a brainstorm session — NOT a worktree + code dive.
#    Read the design anchor and the rolling-baton:
#    /Users/hherb/.claude/plans/we-are-starting-with-logical-newt.md
#    /Users/hherb/src/secretary/secretary_next_session.md
#    Then explicitly request the brainstorming skill before drafting
#    a B.2 spec.
```

---

## Closing inventory

- **Tests:** 451 + 6 ignored (cargo); 3 passed (Python pytest); 5
  conformance sections PASS; spec freshness 96 / 0 / 2; Swift smoke
  runner 3/3 PASS; Kotlin smoke runner 3/3 PASS.
- **Clippy:** clean with `-D warnings`.
- **Sub-project A:** feature-complete; Phase A.7 internal track ✅,
  external (paid) track pending.
- **Sub-project B:** B.1 (Python) ✅; B.1.1 (Swift via uniffi) ✅;
  B.1.1.1 (Kotlin smoke runner) ✅. The full FFI boilerplate triad is
  complete; the next concrete unit of work is **B.2 (vault crypto
  exposure)** which needs its own brainstorm/spec/plan cycle.
- **Sub-project C / D:** not started.
- **`docs/TODO_FINAL_POLISHING.md`:** 2 conditionally-deferred
  sections remaining (no actionable trigger today; file deletes itself
  when both close).
- **PR for B.1.1.1 status:** open at session close. Three commits on
  `feat/ffi-b1-1-1-kotlin-smoke-runner`. Squash-merge SHA to be
  recorded in a post-merge follow-up commit.
