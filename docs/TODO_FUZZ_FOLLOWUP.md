# Fuzz infrastructure follow-up

**Created:** 2026-05-01 as a follow-up to PR #9 (vault: defensive death-clock
clamp + tag canonicalisation + Python unknown-merge KAT) for Steps 1–2,
extended 2026-05-01 with Step 3 (PR #8 monitor scaffold gaps surfaced
during first real-campaign use).

## Status

* **Step 1 — `.gitignore` gap:** ✅ already in place. `core/fuzz/.gitignore`
  ignores `target/`, `corpus/`, `artifacts/`, and `.monitor-state.json`
  via per-crate scoping; the doc author missed the per-crate file.
  Verified by `git check-ignore` against a freshly-fuzzed tree.
* **Step 2 — Triage the four fuzz findings:** ✅ done in PR-A
  (`fix/fuzz-findings-triage`). Six artifacts (the four named below plus
  two more that appeared after the doc was written) were investigated and
  found to be libfuzzer false positives — see "Step 2 (done): triage outcome"
  below for the full investigation. Inputs were promoted as committed
  regression tests anyway, and a real DoS surface found while reading the
  contact-card decoder (`display_name` was unbounded variable-length CBOR
  text on a peer-supplied path) was capped at 4 KiB on parse.
* **Step 3 — Surface live telemetry in the NiceGUI monitor:** ⏳ pending.
  Pick this up in a separate PR (PR-B).

When **Step 3** lands, **delete this file in that same commit** — the
remaining content below is purely the Step-3 spec + "do not" guardrails.

---

## Step 2 (done): triage outcome

Six artifacts were on disk at start of work:

* `contact_card/oom-031e9f63…` and `oom-db48128d…`
* `record/oom-df5366aa…` and `oom-e4c2aff5…`
* `vault_toml/slow-unit-bca8ee9d…` and `slow-unit-fa13b6d1…`

(The doc originally listed four. The other two appeared during the same
PR #8 monitor session that produced the first batch and were caught
implicitly by the same triage.)

**None of the six reproduce against current main.** Direct replay of each
artifact at 256 MB rss/malloc limits returned `Err` in 0 ms; 10,000
iterations of `contact_card oom-031e9f63` finished in 1.25 s with no
allocation spike. Fresh 5-minute campaigns × 3 targets (≈25.7 M total
executions, peak RSS 994–1457 MB — well under the 2 GB libfuzzer default)
produced zero new findings.

Most plausible cause: libfuzzer samples RSS periodically and attributes
the limit-crossing event to whichever input was running at that instant,
so long-running campaigns whose accumulated corpus and instrumentation
state push the process over the threshold can save innocent inputs as
"OOM artifacts". Same noise pattern explains the slow-units under CPU
contention.

Outcome:

1. The six inputs were dropped into `core/tests/data/fuzz_regressions/`
   so the existing `must not panic` replay loop in
   [core/tests/fuzz_regressions.rs](../core/tests/fuzz_regressions.rs)
   locks in their current safe behaviour as a regression guard. Cheap
   defense-in-depth.
2. While reading the `contact_card` decoder during triage, a real
   peer-supplied DoS surface was found: `display_name` was unbounded
   variable-length CBOR text, and the orchestrator at
   [core/src/vault/orchestrators.rs:509](../core/src/vault/orchestrators.rs#L509)
   reads contact-card bytes off disk where any of those files could
   have been written by a sync peer. A hostile peer's card with a
   multi-GB `display_name` would OOM the recipient before any
   signature check could run. Capped at 4 KiB on parse with a new
   `CardError::DisplayNameTooLong` variant; tests pin both the
   boundary and the over-cap rejection.

Skipped on purpose: speculative parser-bound additions to `record`/
`vault_toml`. Without a reproducible bug they would be gold-plating;
record's variable-length fields (notably `unknown` map values) are a
plausible future hardening target but were not load-bearing for any
artifact found here.

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

These items are presentation-layer only — no parser, state-machine, or
subprocess changes.

---

## What NOT to do

* **Do not commit the raw `artifacts/` or `corpus/` directories.**
  `core/fuzz/.gitignore` already prevents this. Promoting findings into
  named regression tests under `core/tests/` is the right pattern; the raw
  fuzzer outputs are noisy and not human-meaningful filenames.
* **Do not delete the `core/fuzz/` directory itself.** It contains the fuzz
  crate's `Cargo.toml` and `fuzz_targets/`, both tracked.
* **Do not paper over future OOM findings with `#[cfg(fuzzing)]` size
  limits.** Caps must apply to the production decoder too — a hostile sync
  peer can ship the same malformed input to a real client (the
  `display_name` cap added in PR-A is the pattern to follow).

---

## Sign-off

Before marking the whole follow-up done:

* `cargo test --release --workspace` stays green (the parser-side
  regression tests from PR-A continue to pass).
* The dashboard verification listed under §3 above passes against three
  concurrent campaigns.
* This file is deleted in the same commit that ships the last UI patch.
