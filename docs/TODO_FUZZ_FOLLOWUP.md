# Fuzz infrastructure follow-up

**Created:** 2026-05-01 as a follow-up to PR #9 (vault: defensive death-clock
clamp + tag canonicalisation + Python unknown-merge KAT).

A future session should pick this up. The task is small (fix a `.gitignore`
gap, then triage four real fuzz findings into regression tests). Estimated
1–2 hours depending on whether any of the findings turn out to be deep bugs
vs. trivial input-size issues.

When this work is complete, **delete this file in the same commit** that
ships the last regression test.

---

## Context

`core/fuzz/` was running locally during PR #9 work and accumulated:

* Build artifacts in `core/fuzz/target/` — not gitignored, polluting
  `git status`.
* Auto-grown corpus directories in `core/fuzz/corpus/<target>/` — not
  gitignored.
* Real fuzz findings in `core/fuzz/artifacts/<target>/` — `oom-*` and
  `slow-unit-*` files. These are bugs the fuzzer caught that have not been
  triaged.

PR #9 deliberately did not bundle any of this — it was scope creep for a
merge-logic PR. This doc captures what to do next.

---

## Step 1: Close the `.gitignore` gap

Current state: the existing `.gitignore` has `/target/` (root-anchored), so
`core/fuzz/target/` is NOT matched. The fuzz `corpus/` and `artifacts/`
directories are also not matched by anything.

Add to `.gitignore`:

```gitignore
# cargo-fuzz outputs (build artifacts, auto-grown corpus, crash findings).
# Real fuzz findings worth keeping should be promoted to regression tests
# under core/tests/, not committed as raw artifacts.
core/fuzz/target/
core/fuzz/corpus/
core/fuzz/artifacts/
```

(Do **not** change the existing `/target/` rule — it correctly anchors the
top-level Rust workspace `target/`. The fuzz crate is a sub-Cargo project
with its own `target/`, and being explicit is clearer than relaxing the
anchor.)

After landing, `git status` should be clean on a freshly-fuzzed working tree.

---

## Step 2: Triage the four fuzz findings

Each finding lives at the path shown. The `oom-*` and `slow-unit-*` filenames
are libfuzzer's convention: the suffix is the SHA-1 of the input. Reproduce
each by feeding the file back into the fuzz target:

```bash
cd core/fuzz
cargo +nightly fuzz run <target_name> artifacts/<target_name>/<filename>
```

(Or `cargo fuzz run` if the project has migrated off nightly — check the
fuzz crate's `rust-toolchain.toml` first.)

### Finding 1 — `contact_card` OOM

* **Path:** `core/fuzz/artifacts/contact_card/oom-031e9f63c25e22eeff434c0ffb290bbbcffae7d0`
* **Symptom:** parser exhausts memory on this input.
* **Fix shape:** likely a missing length cap in the contact-card decoder.
  Find the parser entry point, locate the unbounded `Vec` / `String` /
  `BTreeMap` allocation, and add a hard cap consistent with the rest of the
  vault format's bounded fields.
* **Regression test:** copy the input bytes into
  `core/tests/contact_card_regression.rs` (or similar) as a `const &[u8]` and
  assert the parser returns a typed error rather than panicking or OOMing.

### Finding 2 — `record` OOM

* **Path:** `core/fuzz/artifacts/record/oom-df5366aa6da002c3176f3f8fa4aa157fa58d0424`
* **Symptom:** record decoder exhausts memory.
* **Fix shape:** same as Finding 1 — find and cap the unbounded allocation.
  The likely culprits are `fields` map size, individual field value sizes,
  `tags` vec length, or `unknown` map size.
* **Regression test:** as above, in the appropriate test file under
  `core/tests/`.

### Findings 3 & 4 — `vault_toml` slow-unit (×2)

* **Paths:**
  * `core/fuzz/artifacts/vault_toml/slow-unit-bca8ee9d63ee08277327777d4849aa0b1f4db8f7`
  * `core/fuzz/artifacts/vault_toml/slow-unit-fa13b6d1cac31081c62d8eda5f5d68f48542dc1f`
* **Symptom:** parser exceeds libfuzzer's per-execution time threshold
  (default 1 second). May indicate quadratic or worse complexity on a
  particular input shape.
* **Triage:**
  1. Reproduce both inputs against the current parser. They may be the same
     pathology shrunk to two minimal cases.
  2. Profile with `cargo flamegraph` or `perf` to identify the hot path.
  3. If the pathology is in the upstream `toml` crate, file an upstream
     issue and add an input-size cap as a workaround. If it's in our parser,
     fix the algorithm.
* **Regression test:** time-bound assertion (`Duration::from_millis(...)`)
  on each minimised input. Don't pin a wall-clock value — assert "completes
  within 100ms" with a margin.

---

## What NOT to do

* **Do not commit the raw `artifacts/` or `corpus/` directories.** The
  `.gitignore` change in Step 1 prevents this. Promoting findings into
  named regression tests under `core/tests/` is the right pattern; the raw
  fuzzer outputs are noisy and not human-meaningful filenames.
* **Do not delete the `core/fuzz/` directory itself.** It contains the fuzz
  crate's `Cargo.toml` and `fuzz_targets/` (which ARE tracked, or should be
  — verify before this work starts). Only the three subdirectories listed
  in Step 1 should be ignored.
* **Do not paper over OOM findings with `#[cfg(fuzzing)]` size limits.** The
  cap should apply to the production decoder too — a hostile sync peer can
  ship the same malformed input to a real client. Fuzz-only caps would
  leave the production parser exposed.

---

## Verification

Before marking this done:

* `git status` is clean after a `cargo fuzz run` cycle on each target.
* `cargo test --release --workspace` passes the new regression tests.
* For each finding, the regression test input fails the *pre-fix* parser
  (verify by stashing the fix, running the test, observing the failure,
  un-stashing) — proving the test actually exercises the bug.
* This file is deleted in the same commit that ships the last regression
  test.
