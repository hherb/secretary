# NEXT_SESSION.md

**Session date:** 2026-05-03
**Session-specific handoff** for the session that closed pickup items #3 and #4.

For the comprehensive rolling-baton (full carry-over context, deferred-with-
reasons items, external-review track, etc.), continue to read
[`secretary_next_session.md`](secretary_next_session.md) — that file is the
multi-session entry point and remains authoritative; this file is just the
single-session delta.

---

## (1) What we shipped this session

Two commits on PR [#19](https://github.com/hherb/secretary/pull/19) (`pickup/items-3-and-4` → `main`):

- **`8280a21`** — `refactor(conformance): replace type-ignore in py_merge_unknown_map with explicit assert`
  - Replaced `# type: ignore[arg-type]` in the fall-through branch of
    `py_merge_unknown_map` with an explicit `assert r_hex is not None`.
  - Dropped Section 1 of [`docs/TODO_FINAL_POLISHING.md`](docs/TODO_FINAL_POLISHING.md)
    per its "drop the section in the same commit" rule.
  - Refreshed stale line-number anchors in the two surviving sections of
    `TODO_FINAL_POLISHING.md` (function moved from 921-956 to 1914-1949;
    Section 5 from 1116-1176 to 2381-2441).
  - Closes pickup item #3 (sub-item 1).

- **`56021fd`** — `docs(contributors): add index.md for the Phase A.7 reviewer-handoff package`
  - New [`docs/manual/contributors/index.md`](docs/manual/contributors/index.md)
    as the entry-point for the three internal-audit memos
    (differential-replay protocol, side-channel audit, memory-hygiene audit).
  - Documents per-memo scope and "when to read this" guidance keyed off
    the kind of code change a contributor is making.
  - Calls out the relationship to the planned external paid review:
    these memos are the principal handoff package, complementary to the
    normative specs in [`docs/`](docs/).
  - Documents the maintenance discipline (preserve scope/methodology
    when extending; new findings outside an existing scope go into a
    new memo).
  - Closes pickup item #4.

**Verification at session close:**

- `cargo test --release --workspace` → 445 passed + 6 ignored (matches
  pre-session baseline).
- `cargo clippy --release --workspace -- -D warnings` → clean.
- `uv run core/tests/python/conformance.py` → all 5 sections PASS.
- `uv run core/tests/python/spec_test_name_freshness.py` → 96 resolved
  + 0 unresolved + 2 allowlisted (now scans 14 docs, was 13;
  the new `index.md` is covered without false positives).

PR #19 is open and awaits review/merge.

---

## (2) What's next, with concrete acceptance criteria

Two doors, depending on whether you want a focused-short or a longer push:

### A. Sub-project B.1 — FFI bindings boilerplate (the big one)

The recommended next concrete unit of work per
[`secretary_next_session.md`](secretary_next_session.md). Sub-project A is
feature-complete; B.1 unblocks Sub-project C (sync orchestration) and
Sub-project D (platform UIs).

**Acceptance criteria for B.1:**

1. Both FFI crates ([`ffi/secretary-ffi-py/`](ffi/secretary-ffi-py/) and
   [`ffi/secretary-ffi-uniffi/`](ffi/secretary-ffi-uniffi/)) build under
   `cargo build --release --workspace` (verify they currently do — the
   current state is "stub").
2. A single uniffi UDL describing one tiny round-trip function (e.g.
   `fn sum(a: u32, b: u32) -> u32`) wired through to both Swift and
   Kotlin bindings via uniffi-bindgen.
3. The PyO3 crate exposes the equivalent `#[pyfunction]` and produces a
   `secretary_ffi_py.so` (or `.dylib`) Python extension importable as
   `import secretary_ffi_py`.
4. **Round-trip tests:**
   - Rust unit test that calls the function directly.
   - Python `pytest` (run via `uv run pytest`) that imports the built
     `.so` and asserts the same return value.
   - Swift / Kotlin smoke runner if feasible in-session — otherwise
     defer to a follow-up commit.
5. The "where does the Python build product live so that `uv run` can
   import it" question is answered explicitly — pick `maturin`-built
   wheel installed into the project's `uv` env, or built `.so`
   discovered via `PYTHONPATH`, and document the choice in the FFI
   crate's `README.md`.
6. No vault crypto exposed yet — just prove the binding pipeline works
   end-to-end. Crypto surface comes in B.2+.

**Estimate:** ~2–4 hours focused. The hardest single sub-question is
the Python build-product layout (criterion 5).

### B. Smaller pickup items (if delaying B.1)

The remaining smaller items in
[`secretary_next_session.md`](secretary_next_session.md) after this session:

- Sub-items 2 and 3 of pickup item #3 — both **conditionally deferred**
  (`hex_lex_compare` helper extraction needs a second hex-bearing KAT
  field; `_record_pass_fail` needs a Section 6 with 5+ sub-tests). Not
  unconditional pickup work.
- Carry-over dribbles section in `secretary_next_session.md` — none
  candidates for an in-session pass.

In other words: there are no smaller actionable items remaining after this
session. Next session should commit to B.1 unless a new issue surfaces.

---

## (3) Open decisions and risks

### Decisions to make at the start of B.1

1. **Python build-product layout.** Two reasonable shapes:
   - `maturin develop` builds and installs the wheel directly into the
     `uv` venv (`uv sync` then `uv run maturin develop --manifest-path
     ffi/secretary-ffi-py/Cargo.toml`). Clean import path; standard
     PyO3 workflow.
   - Cargo builds `cdylib`, copy to a known location, set `PYTHONPATH`.
     Faster iteration but more bespoke.

   Recommend `maturin develop`. Decide before writing the first
   `pyproject.toml`.

2. **uniffi UDL location.** One UDL per crate or one shared UDL referenced
   from the uniffi crate? With one binding crate today, the trivial
   answer is "one UDL inside `ffi/secretary-ffi-uniffi/`". Worth saying
   out loud so it's deliberate.

3. **Smoke-test runners for Swift / Kotlin.** Running these from a Mac
   without an iOS simulator / Android emulator is painful. Options:
   - In-session: a tiny Swift `main.swift` that loads the bindings on
     macOS-host (cheapest, doesn't exercise the iOS-specific path).
   - Defer Swift / Kotlin smoke tests to a follow-up B.1.1 commit and
     ship B.1 as Rust + Python only.

   Recommend the latter; B.1 is about the pipeline, not platform
   coverage.

### Risks (mostly upstream-managed; flagging for awareness)

- **`hkdf` 0.13.0 carry-over.** Released 2026-03-30; does NOT add zeroize
  to internal HMAC state and DOES rename `Hkdf` → `GenericHkdf` (with
  source-compat aliases). Watch is recurring (Mondays 09:00
  Australia/Perth). Flagged in
  [`core/src/crypto/kdf.rs:216-223`](core/src/crypto/kdf.rs#L216-L223).
  No action needed this session; carry-over remains.

- **External paid review** is gated on calendar / availability of a
  reviewer with FIPS 203 / 204 implementer experience. B.1 work proceeds
  in parallel — FFI doesn't touch `core/src/`, so any spec clarification
  the external reviewer surfaces can land alongside FFI work without
  conflict.

- **PR #19 is open and unmerged at session close.** If next session
  starts before the PR is reviewed/merged, **rebase first** (or branch
  off PR #19's tip) to avoid touching the same `TODO_FINAL_POLISHING.md`
  and `docs/manual/contributors/` files.

---

## (4) Exact commands to resume

```bash
# 1. Get back to the repo and confirm clean main
cd /Users/hherb/src/secretary
git checkout main
git pull --ff-only

# 2. If PR #19 has been merged, you're already up to date.
#    If PR #19 is still open and you want to start B.1 anyway, base
#    the new branch off main (FFI work doesn't conflict):
git checkout -b feat/ffi-b1-bindings-boilerplate

# 3. Re-baseline tests before touching anything:
cargo test --release --workspace
cargo clippy --release --workspace -- -D warnings
uv run core/tests/python/conformance.py
uv run core/tests/python/spec_test_name_freshness.py

# Expected: 445 passed + 6 ignored, clippy clean, conformance PASS,
#   spec freshness 96 resolved + 0 unresolved + 2 allowlisted.

# 4. Read the design anchor and the next-session entry point:
#    /Users/hherb/.claude/plans/we-are-starting-with-logical-newt.md
#    /Users/hherb/src/secretary/secretary_next_session.md
#    (the latter has the full B.1 plan-of-attack)
```

If picking up `pickup/items-3-and-4` because PR #19 needs revisions:

```bash
cd /Users/hherb/src/secretary
git fetch origin
git checkout pickup/items-3-and-4
git pull --ff-only
```

---

## Closing inventory

- **Tests:** 445 passed + 6 ignored (cargo); 5 Python conformance
  sections PASS; spec freshness 96 / 0 / 2.
- **Clippy:** clean with `-D warnings`.
- **`docs/TODO_FINAL_POLISHING.md`:** down from 3 sections to 2 (both
  conditionally deferred). When the file becomes empty, delete it per
  its own footer.
- **PR #19 status:** open, awaiting review.
- **Branch:** `pickup/items-3-and-4` pushed and tracking `origin/`.
