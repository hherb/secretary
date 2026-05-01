# Fuzz infrastructure follow-up

**Created:** 2026-05-01 as a follow-up to PR #9 (vault: defensive death-clock
clamp + tag canonicalisation + Python unknown-merge KAT) for Steps 1–2,
extended 2026-05-01 with Step 3 (PR #8 monitor scaffold gaps surfaced
during first real-campaign use).

Three independent tracks, all post-PR-#8/9:

1. **`.gitignore` gap** — small, mechanical (Step 1).
2. **Triage four real fuzz findings** — 1–2 hours depending on whether
   the findings are deep bugs vs. trivial input-size issues (Step 2).
3. **Surface live telemetry in the NiceGUI monitor** — PR #8 shipped
   the dashboard as a deliberate static scaffold; running it against
   real campaigns immediately exposes that a healthy and a wedged
   campaign look identical because the existing pulse stream isn't
   plumbed to the UI (Step 3).

When **all three tracks** are done, **delete this file in the same
commit** that ships the last regression test (or the last UI patch,
whichever lands later).

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

## Step 3: Surface live telemetry in the NiceGUI monitor

PR #8 shipped the monitor as a deliberate scaffold (`fbef11b feat(monitor):
static six-card UI scaffold`); the PR title flagged the bug-bash as deferred.
The result is a dashboard where a healthy running campaign and a silently-
wedged one look identical: the only reactive bind is `crash_label` on a 1 Hz
timer ([core/fuzz/monitor.py:408](core/fuzz/monitor.py#L408)); `status_label`
only flips on Start / Stop button presses
([core/fuzz/monitor.py:423](core/fuzz/monitor.py#L423),
[core/fuzz/monitor.py:427](core/fuzz/monitor.py#L427)) and never reflects
the `Status` enum's plateau / cap-reached / crashed transitions, even though
the stderr reader already drives those state changes on `RunState.status`.

The data the cards need is already on `RunState`
([core/fuzz/monitor.py:177-194](core/fuzz/monitor.py#L177-L194)): the most
recent `Pulse` is `pulses[-1]`, the `Status` enum carries the lifecycle,
`started_at` gives elapsed time, `runs_cap` is the cap, `crash_path` is the
finding. Everything below is a presentation-layer fix — no parser,
state-machine, or subprocess changes.

### 3.1 — Reactive status badge

* **Where:** [core/fuzz/monitor.py:397](core/fuzz/monitor.py#L397) and the
  per-card timer at [:408](core/fuzz/monitor.py#L408).
* **What:** `status_label` is currently set imperatively in `on_start` /
  `on_stop`. Make it reactive instead — drive it from the same per-card
  timer that owns `update_crash_label`, reading `RunState.status` and
  rendering the enum name (`IDLE` / `RUNNING` / `PLATEAU` / `CAP_REACHED` /
  `CRASHED` / `STOPPED`).
* **Bonus polish:** colour the badge by status (Quasar `text-positive` /
  `text-warning` / `text-negative` etc.) so a glance across six cards reads
  like a traffic-lights view.

### 3.2 — Live pulse readout per card

* **Where:** add to the card body in
  [`_render_card`](core/fuzz/monitor.py#L388) alongside the existing labels.
* **What:** a single line per card showing `cov / ft / corp / exec/s / rss`
  from `pulses[-1]`. Refresh on the same per-card timer as status. When
  `pulses` is empty (idle, or just spawned and pre-INITED), show `—` rather
  than zeros — distinguishes "no data yet" from "telemetry says zero".
* **Why:** this is the single most useful piece of information the scaffold
  is hiding. Without it the user cannot distinguish "RUNNING and making
  progress" from "RUNNING and silently stuck", which makes the dashboard
  worse than running `cargo fuzz run` in a terminal.

### 3.3 — Elapsed time + cap progress

* **Where:** same per-card timer as 3.2.
* **What:**
  * `elapsed = time.monotonic() - rs.started_at` rendered as `mm:ss` while
    `rs.status == RUNNING`, frozen on terminal status.
  * `exec_count / runs_cap` (e.g. `"1.2M / 5M"`) when `runs_cap` is not
    `None`; just `exec_count` when running open-ended.
  * Optional: a small `ui.linear_progress` widget when `runs_cap` is set,
    so cap-reaching campaigns have a visual ETA.

### 3.4 — Global findings counter

* **Where:** above the grid, in
  [`MonitorApp.render`](core/fuzz/monitor.py#L241).
* **What:** scan `core/fuzz/artifacts/<target>/` once per second (cheap;
  small dirs) and surface a single-line tally — e.g.
  `Findings: 2 OOMs, 2 slow-units across 4 targets`. Optionally expand to
  a per-target breakdown in a `ui.expansion`.
* **Why:** when a campaign produces a finding, the user currently has no
  in-UI signal until they Stop and look at the filesystem. The per-card
  `crash_label` only fires for `Status.CRASHED` — `oom-*` and `slow-unit-*`
  artifacts are already in `artifacts/<target>/` and never surfaced.

### 3.5 — Runs-cap input clipping

* **Where:** [core/fuzz/monitor.py:393-396](core/fuzz/monitor.py#L393-L396).
* **What:** the label `"runs cap (blank = open-ended)"` is wider than the
  card column at the current grid width and renders as
  `"runs cap (blank = open…"`. Either shorten the label
  (`"runs cap (blank = ∞)"` works) or widen the card — current width is
  `w-96` ([:389](core/fuzz/monitor.py#L389)); `w-full` inside a 3-column
  grid would let the input breathe.
* **Cosmetic only**, but visible on first launch so worth fixing alongside
  the rest.

### Verification (Step 3)

* Spawn three campaigns at once (e.g. `vault_toml`, `record`, `contact_card`
  on `asan`). The dashboard now shows:
  * cov / ft / corp / exec/s / rss updating once per second per running
    card,
  * elapsed time advancing,
  * status badge transitioning RUNNING → PLATEAU when the plateau detector
    fires (verify by setting `plateau_k` low in `.monitor-state.json` to
    force a plateau quickly),
  * the global findings counter reflecting any pre-existing artifacts in
    `core/fuzz/artifacts/`.
* Stop a running campaign mid-flight; the readout freezes at the last pulse
  and the badge flips to STOPPED.
* Eyeball the runs-cap input — no ellipsis truncation.

These items are presentation-layer only. They do not block Steps 1 and 2
(gitignore + finding triage); pick them up in either order.

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
