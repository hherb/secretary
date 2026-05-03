# NEXT_SESSION.md

**Session date:** 2026-05-03 (consolidation pass after PR #20 merge)
**Session-specific handoff** for the short consolidation session that
realigned the rolling-baton (`secretary_next_session.md`) and the
single-session delta with the post-merge state of `main`. No new
feature work this session — just a stale-doc cleanup so the next
session can start cleanly on B.1.1 (uniffi UDL + Swift smoke runner).

For the comprehensive rolling-baton (full carry-over context, deferred-
with-reasons items, external-review track, etc.), continue to read
[`secretary_next_session.md`](secretary_next_session.md) — that file is
the multi-session entry point and remains authoritative; this file is
just the single-session delta.

---

## (1) What we shipped this session

A docs-only consolidation. The B.1 work itself (PyO3 + maturin Python
bindings boilerplate) had already shipped earlier the same day in
[PR #20](https://github.com/hherb/secretary/pull/20) at squash-merge
`a2f76b8`; this session's job was to update the rolling-baton entry
point and the single-session NEXT_SESSION.md to reflect that, since
the PR-#20 session had left both stale (still recommending "begin
Sub-project B.1" as next work).

### Commits (this consolidation session)

- `be36f5d` — `docs(next-session): consolidate post-PR-20 state — B.1 done, B.1.1 next`

### What changed

- **[`secretary_next_session.md`](secretary_next_session.md)** —
  - Recommended next concrete unit of work flipped from "Begin
    Sub-project B.1 — FFI bindings boilerplate" to "Begin
    Sub-project B.1.1 — uniffi UDL + Swift/Kotlin smoke runners",
    with the corresponding decision list and acceptance-criteria
    rewrite.
  - "Smaller pickup items (if delaying Sub-project B)" → "...
    delaying Sub-project B.1.1)".
  - Current-state at-a-glance: "Sub-project B (FFI): stubs only" →
    "B.1 Python complete (PR #20 / `a2f76b8`); `secretary-ffi-uniffi`
    remains a stub; B.1.1 next".
  - Rolled-up summary section gained a new entry for PR #20 with the
    four mid-stream code-review corrections (extension-module
    deprecation, maturin in dev deps, pytest testpaths, broken
    CLAUDE.md link).
- **[`NEXT_SESSION.md`](NEXT_SESSION.md)** — rewritten as this file
  (consolidation handoff; previous content was the PR-#20 single-
  session delta which is now in the docs/handoffs/ archive).

No code changed. No tests added or modified.

### Verification at session close

- `cargo test --release --workspace` → **448 passed + 6 ignored,
  0 failed** (matches post-PR-20 baseline).
- `cargo clippy --release --workspace -- -D warnings` → **clean**,
  exit 0.
- `uv run --directory ffi/secretary-ffi-py pytest` → **3 passed**.
- `uv run core/tests/python/conformance.py` → **all 5 sections PASS**.
- `uv run core/tests/python/spec_test_name_freshness.py` → **96
  resolved + 0 unresolved + 2 allowlisted**, PASS.

---

## (2) What's next, with concrete acceptance criteria

### A. Sub-project B.1.1 — uniffi UDL + Swift smoke runner (recommended next work)

The remaining half of B.1. Same shape as B.1 Python but on the
[`ffi/secretary-ffi-uniffi/`](ffi/secretary-ffi-uniffi/) crate, which
is still a stub. The full plan-of-attack lives in the rolling-baton
at [`secretary_next_session.md`](secretary_next_session.md) §
"Recommended next concrete unit of work".

**Acceptance criteria:**

1. `ffi/secretary-ffi-uniffi/Cargo.toml` adds `uniffi = "0.x"`
   (current stable, semver range — uniffi isn't on the crypto path).
   Lint table mirrors `secretary-ffi-py/` (localized
   `unsafe_code = "deny"` per CLAUDE.md's "FFI as isolated reviewed
   boundary" principle).
2. A single uniffi UDL in
   `ffi/secretary-ffi-uniffi/src/secretary.udl` describing one tiny
   round-trip function `fn add(a: u32, b: u32) -> u32`, wired
   through to both Swift and Kotlin bindings via `uniffi-bindgen`.
3. **Round-trip tests:**
   - Rust unit test in the uniffi crate that calls `add` directly.
   - macOS-host Swift smoke runner (`tests/swift/main.swift` + the
     generated bindings, `swiftc -L ... main.swift`, no iOS simulator
     required) that loads the bindings and asserts `add(2, 3) == 5`.
   - Kotlin smoke runner if feasible without an Android emulator —
     **probably defer to a B.1.1.1 follow-up commit** so B.1.1 ships
     as Rust + Swift only.
4. Build flow ("where do the Swift / Kotlin build products live")
   documented in
   [`ffi/secretary-ffi-uniffi/README.md`](ffi/secretary-ffi-uniffi/README.md),
   parallel to the Python README's structure.
5. No vault crypto exposed yet — B.1.1 mirrors B.1's "prove the
   binding pipeline" scope.

**Estimate:** ~2–3 hours focused. The hardest single sub-question
is the Kotlin smoke-runner cost vs. value (recommend defer).

### B. Sub-project B.2 (after B.1.1) — first vault crypto exposed

Vault unlock + open exposed across all three languages. First fallible
operations means `PyResult` / equivalent error marshalling becomes
first-class, and first secret-bearing types across the FFI boundary
need a deliberate design pass on zeroize discipline through Python's GC.

**This warrants its own brainstorming + spec + plan cycle**, not an
in-session pass. The spec needs to answer:

- How do `Sensitive<T>` / `SecretString` cross the FFI boundary?
  Borrowed-only, copy-only, or move-with-zeroize-on-Python-drop?
- How does `UnlockError::WeakKdfParams` get marshaled to a Python
  exception type? B.2's `open_with_password` Python wrapper must NOT
  silently downgrade — should be a first-class Python exception.
- Does `open_with_password` return a Python context manager so the
  unlocked identity is zeroized at `__exit__` time?
- `RecordFieldValue::Text(SecretString)` and
  `RecordFieldValue::Bytes(SecretBytes)` — how do they materialise
  into Python? `bytes` (copies, defeats the zeroize), `bytearray`
  (mutable, can be wiped), or a custom `SecretBytes` type with a
  context-manager API?

---

## (3) Open decisions and risks

### Decisions to make at the start of B.1.1

1. **uniffi version pin.** Recommend a semver range
   (`uniffi = "0.x"` → resolves to current stable), not an exact pin.
   uniffi is still pre-1.0 but isn't on the crypto path, so the
   `tempfile = "=3.27.0"` exact-pin discipline doesn't apply here.
2. **uniffi UDL location.** With one binding crate today, the trivial
   answer is "one UDL inside `ffi/secretary-ffi-uniffi/`". Worth
   saying out loud so it's deliberate.
3. **Kotlin smoke runner.** macOS-host Swift loader is essentially
   free (`swiftc main.swift -L bindings/swift ...`). Kotlin requires
   either an emulator or a JVM-only stub harness — defer if no
   emulator is available.

### Risks (mostly upstream-managed; flagging for awareness)

- **`hkdf` 0.13.0 carry-over.** Released 2026-03-30; does NOT add
  zeroize to internal HMAC state and DOES rename `Hkdf` →
  `GenericHkdf` (with source-compat aliases). Watch is recurring
  (Mondays 09:00 Australia/Perth). Flagged in
  [`core/src/crypto/kdf.rs:216-223`](core/src/crypto/kdf.rs#L216-L223).
  No action needed this session; carry-over remains.
- **External paid review** is gated on calendar / availability of a
  reviewer with FIPS 203 / 204 implementer experience. B.1.1 work
  proceeds in parallel — FFI doesn't touch `core/src/`, so any spec
  clarification the external reviewer surfaces can land alongside
  FFI work without conflict.
- **Squash-merged worktree cleanup.** The
  `.worktrees/feat-ffi-b1-py-bindings-boilerplate/` worktree was
  pruned at the end of this consolidation session and the local
  `feat/ffi-b1-py-bindings-boilerplate` branch deleted. Remote
  branch on origin can be deleted via the GitHub UI or
  `git push origin --delete feat/ffi-b1-py-bindings-boilerplate`
  if not already auto-deleted.

---

## (4) Exact commands to resume

```bash
# 1. Start from a clean main
cd /Users/hherb/src/secretary
git checkout main
git pull --ff-only

# 2. Re-baseline tests (everything should still pass)
cargo test --release --workspace
cargo clippy --release --workspace -- -D warnings
uv run --directory ffi/secretary-ffi-py pytest
uv run core/tests/python/conformance.py
uv run core/tests/python/spec_test_name_freshness.py

# Expected: 448 passed + 6 ignored, clippy clean, pytest 3 passed,
#   conformance PASS, spec freshness 96 resolved + 0 unresolved + 2 allowlisted.

# 3. Create the B.1.1 worktree (project-local convention; see
#    feedback_worktree_location memory)
git worktree add .worktrees/feat-ffi-b1-1-uniffi-boilerplate \
  -b feat/ffi-b1-1-uniffi-boilerplate
cd .worktrees/feat-ffi-b1-1-uniffi-boilerplate

# 4. Read the design anchor and the rolling-baton:
#    /Users/hherb/.claude/plans/we-are-starting-with-logical-newt.md
#    /Users/hherb/src/secretary/secretary_next_session.md
#    (the latter has the full B.1.1 plan-of-attack)
```

---

## Closing inventory

- **Tests:** 448 + 6 ignored (cargo); 3 passed (Python pytest); 5
  conformance sections PASS; spec freshness 96 / 0 / 2.
- **Clippy:** clean with `-D warnings`.
- **Sub-project A:** feature-complete; Phase A.7 internal track ✅,
  external (paid) track pending.
- **Sub-project B:** B.1 (Python) ✅; B.1.1 (uniffi Swift/Kotlin) is
  the recommended next concrete unit of work.
- **Sub-project C / D:** not started.
- **`docs/TODO_FINAL_POLISHING.md`:** 2 conditionally-deferred
  sections remaining (no actionable trigger today; file deletes itself
  when both close).
- **PR #20 status:** merged at `a2f76b8`. Worktree pruned.
