# NEXT_SESSION.md — the whole fuzz corpus replays in seconds (#655), the harness is split (#649), and the mutation harness can see `core/tests/`

Branch `feature/diff-replay-split`, worktree `.worktrees/diff-replay-split`,
base `66a9db76` (`main`, immediately after PR #656 merged).

The user chose this slice by options-plus-recommendation: **#649 split +
#655**, then the #655 design (**persistent worker + progress**, over an opt-out
env var or corpus sampling), then a mid-slice scope widening (**fix the
mutation harness's Rust probe here**, over filing it).

**Four issues filed:** [#660](https://github.com/hherb/secretary/issues/660)
(`conformance.py`'s `parse_known_args` falls through to the full verifier on an
unrecognised flag), [#661](https://github.com/hherb/secretary/issues/661)
(the scoped Rust probe's cargo behaviour is measured, not pinned by a control),
and from the review round [#663](https://github.com/hherb/secretary/issues/663)
(Python re-reads each input by path) and
[#664](https://github.com/hherb/secretary/issues/664) (make the replay target an
enum). The slice closes **#649** and **#655** in code.

**Read §(1f) first.** The PR's first Linux CI run did not fail a test: the
worker's process-group kill, spelled `kill -KILL -<pgid>`, is `kill(-1)` under
procps-ng 4.0.4, and it killed the GitHub runner. No reviewer caught it; the
cancelled, log-less CI job did. Fixed with `kill(2)` through `rustix`, and
proven in `ubuntu:24.04` in both directions.

**The headline: the replay that proves the two decoders agree could not, in
practice, be run on the inputs it exists for.** 74,924 fuzz-discovered inputs
took ~3.3 h at ~0.16 s of `uv run` start-up each, printing nothing. Through one
worker: **74,973 inputs in 27.48 s, every one agreeing** — the first time that
corpus has been replayed end to end on this machine. §(1c).

---

## (0) Starting state

`git fetch origin && git log --oneline main..origin/main` returned empty;
`main` was `66a9db76`. PR #656 was merged; `.worktrees/diff-replay-split` from
the previous slice's name was reused as a NEW branch after
`.worktrees/diff-replay-ci` was removed and `feature/diff-replay-ci` deleted
(two-dot diff against `main` measured EMPTY first). The two detached
`.claude/worktrees/*` checkouts belong to other sessions and were left alone.

---

## (1) What shipped

Run `git log --oneline main..HEAD` for the current set — a review round will add
commits this table does not list.

| SHA | What |
|---|---|
| `4922b9df` | #649 — `differential_replay.rs` split along the #641/#646 seams, behaviour-preserving |
| `93d9258d` | the mutation harness's Rust probe takes `test` / `features` |
| `2d246cf6` | #655 — `conformance.py --diff-replay-serve`, and Section DRS |
| `03b89ced` | #655 — DRS cannot recurse if the serve flag is ever unrecognised |
| `74fb0969` | #655 — the corpus replays through one worker, with progress |
| `a56c35d9` | #655 — protocol doc, CLAUDE.md, fuzz README, test.yml, threat model |
| `ba1b9bd1` | ROADMAP, CLAUDE.md harness gotchas, a spec-freshness false positive, #660/#661 citations |
| `6952aec2` | this baton and the `NEXT_SESSION.md` retarget |
| `8343d2b6`..(this commit) | the review round — §(1f) lists each commit against its finding |

### (1a) #649 — the split, as a move

`core/tests/differential_replay.rs` was **573** lines (the issue said 541; the
#656 review grew it). It now holds the four `#[test]` fns and nothing else.
The items moved, unchanged, into `differential_replay_helpers/`:

- `targets.rs` — `TARGETS`, the two classification lists, `MIN_CORPUS_INPUTS`. **#641 edits this.**
- `rust_decoder.rs` — `RustRejection` + `rust_decode`. **#641 edits this too.**
- `tolerance.rs` — `tokens_agree`. **#646 edits this.**

The tests stayed at the binary root **because a `#[test]` fn's module path is
its name**, and those names are cited by handoffs, mutation specs and the CI
step's negative control. Evidence it is a move: the `--list` name set diffed
against a pre-move baseline (4 = 4, nothing added or removed); every moved code
line textually identical apart from `pub` (sorted-line diff; the only
differences were two doc sentences whose location words — "300 lines up",
"neighbouring" — the move made false); replay green with the same per-target
counts; clippy clean.

### (1b) The mutation harness could not see any of it — fixed here

The first mutation row on the moved `tokens_agree` reddened both tests it named
and still read **`NOT_LIVE`**, "artifact contents unchanged across 2 file(s)".
The Rust liveness probe ran `cargo build --release -p <package>`: the LIBRARY
only. No file under `core/tests/` contributes to it, so **every `core/tests/**`
mutation in this repo was unprovable** — including the feature-gated binary that
is a blocking CI step, and everything #641/#646 will touch.

`RustProbe` gains optional `test` and `features`; the reading becomes
`cargo build --release -p P --features a,b --test T`. Absent, the argv is byte
for byte the old one (pinned). A malformed scope is a `SpecError`, not a silent
fall-back to the unscoped build. The same row then read `yes (artifact)` /
`RED_AS_EXPECTED`.

```toml
probe = { package = "secretary-core", test = "differential_replay", features = ["differential-replay"] }
```

### (1c) #655 — one worker instead of a process per input

**The measurement that chose the design** (2026-09-13, before any code): one
interpreter decoded the 74,924-input runtime corpus in ~30 s, 0.2–0.4 ms each.
The ~0.16 s per input was `uv run` start-up, ~99.7% of the cost — so the fix is
to stop paying it, not to sample the corpus or skip it.

**Python** (`conformance_lib/diff_replay.py`): both modes share one pure verdict
function (`replay_bytes` / `replay_path`; the `if target ==` chain became a
dispatch table). `--diff-replay-serve` reads `{"target", "path"}` per line and
writes the verdict plus `path` echoed, plus `traceback` on an `error`. A
malformed request is answered as `BadRequest` and the loop continues;
`sys.stdout` points at stderr while serving so a printing decoder cannot desync
the stream. **Single-shot output is byte-identical** to before on all 50
committed inputs plus the unknown-target and missing-file shapes (an oracle
captured before the refactor, diffed twice).

**Section DRS** checks what a reused interpreter could break that per-input
spawning could not: the protocol in-process, and **serve-vs-single-shot verdict
equivalence on every committed input across processes**. No codec module holds
mutable module state today (audited) — now checked rather than assumed.
Registered; REG is **30/30**.

**Rust** (`differential_replay_helpers/`):

- `python_worker.rs` — the worker. Per input: a 60 s wait, then the whole
  **process group** killed. `uv run` FORKS Python rather than exec'ing it
  (measured with `ps`), so killing `uv` alone would orphan a spinning
  interpreter. The kill is `kill(2)` through `rustix`, because the workspace
  forbids `unsafe` — it first went through the `kill` utility, which is the
  §(1f) Critical. The response must echo its path. Any transport failure
  retires the worker; an `error` answer does not. After **3 inputs in a row
  with no answer from a worker** no further worker is started, and the rest
  are reported as ONE harness failure.
- `python_bridge.rs` — now pure: `serve_command()` and `parse_verdict()`,
  moved verbatim out of the old spawn function.
- `agreement.rs` — `judge()`, the verdict comparison lifted out of the test
  body, message text unchanged.
- `corpus.rs::inputs_in` — sorted, so failure lists are stable.
- `progress.rs` — start / at-most-every-10 s / finish lines written to the
  process's **stderr handle, which libtest does not capture**. They show
  without `--nocapture`, so a CI log now proves how much was replayed.

| Case | Before | After |
|---|---|---|
| 74,973 inputs (runtime fuzz corpus + committed), this machine | ~3.3 h implied, silent | **27.48 s**, all agreeing |
| 50 committed inputs (CI shape), local | 12.79 s | **1.42 s** |
| unit tests in the binary | 4 | **36** at `6952aec2`, **43** after the review round (4 original names unchanged) |

### (1d) Measured mutation evidence — pasted, gates named per row

**Every row below is `scripts/mutate.py` output.** 11 Rust rows (10 distinct
mutations; CI647 ran before and after the worker) and 8 Python rows, all
`RED_AS_EXPECTED`. The Rust rows use the scoped probe except CI647, which
mutates `core/src`.

| # | Mutation | Gate | Live | Outcome | Reds |
|---|---|---|---|---|---|
| CI647 | Rust names missing_field where Python names repeated_array_value, through the worker | `cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay` | yes (artifact) | RED_AS_EXPECTED | differential_replay_full_corpus |
| M649a | tokens_agree made strict at its new path: the witness and the breadth test both red | `cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay` | yes (artifact) | RED_AS_EXPECTED | tolerance_admits_only_phase_dependent_pairs, differential_replay_full_corpus |
| W2 | a timeout kills only the leader: the interpreter uv forked is orphaned | `cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay` | yes (artifact) | RED_AS_EXPECTED | a_silent_worker_times_out_and_its_whole_process_group_is_killed |
| W3 | an answer is accepted whatever input it names | `cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay` | yes (artifact) | RED_AS_EXPECTED | a_response_must_be_json_and_echo_the_path_it_answers, an_answer_for_a_different_path_is_a_harness_failure_and_retires_the_worker |
| W4 | a healthy worker is discarded after every answer: the per-input spawn cost returns | `cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay` | yes (artifact) | RED_AS_EXPECTED | one_worker_answers_many_inputs, an_error_verdict_is_a_harness_failure_but_keeps_the_worker |
| W1b | a verdict no longer resets the count, so failures spread across a long run abandon it | `cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay` | yes (artifact) | RED_AS_EXPECTED | a_verdict_resets_the_failure_count |
| W5 | no cap: a worker that cannot come up is restarted for every input | `cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay` | yes (artifact) | RED_AS_EXPECTED | a_worker_that_cannot_stay_up_is_abandoned_after_the_failure_cap |
| A1 | a Python harness failure is scored as agreement (#595 restated) | `cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay` | yes (artifact) | RED_AS_EXPECTED | a_python_harness_failure_is_never_a_verdict |
| B1 | an accept with no bytes becomes an empty acceptance | `cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay` | yes (artifact) | RED_AS_EXPECTED | an_accept_without_reencoded_bytes_is_a_harness_failure_not_an_empty_accept |
| G1 | progress cadence boundary off by one | `cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay` | yes (artifact) | RED_AS_EXPECTED | progress_is_due_only_once_the_interval_has_passed |
| PS1 | rust_build_argv drops --test: the scoped probe silently builds the library again | `uv run --with pytest python3 -m pytest scripts/mutation_harness/tests/test_rust_probe_scope.py -q` | yes (interpreter) | RED_AS_EXPECTED | test_a_scoped_probe_builds_that_test_target_with_its_features |
| PS2 | the runner forwards the package alone, dropping test/features | `uv run --with pytest python3 -m pytest scripts/mutation_harness/tests/test_rust_probe_scope.py -q` | yes (interpreter) | RED_AS_EXPECTED | test_the_runner_hands_the_whole_probe_to_the_rust_reading |
| PS3 | an empty `test` is accepted (it would reach cargo as `--test ""`, not "build the unscoped default" as this row first said — #662 review) | `uv run --with pytest python3 -m pytest scripts/mutation_harness/tests/test_rust_probe_scope.py -q` | yes (interpreter) | RED_AS_EXPECTED | empty-test |
| DRS1 | serve stops redirecting stdout: a printing decoder corrupts the response stream | `uv run core/tests/python/conformance.py` | yes (interpreter) | RED_AS_EXPECTED | diff-replay serve mode matches single-shot |
| DRS2 | a response stops echoing its request's path | `uv run core/tests/python/conformance.py` | yes (interpreter) | RED_AS_EXPECTED | diff-replay serve mode matches single-shot |
| DRS3 | serve's verdict diverges from single-shot's (the shape an interpreter-state leak would take) | `uv run core/tests/python/conformance.py` | yes (interpreter) | RED_AS_EXPECTED | diff-replay serve mode matches single-shot |
| DRS4 | a non-JSON request kills the serve loop instead of being answered | `uv run core/tests/python/conformance.py` | yes (interpreter) | RED_AS_EXPECTED | diff-replay serve mode matches single-shot |
| DRS5 | the serve flag stops being handled: the child runs the full verifier, and must FAIL one level deep rather than recurse | `uv run core/tests/python/conformance.py` | yes (interpreter) | RED_AS_EXPECTED | diff-replay serve mode matches single-shot |

The pasted CI647 row is the post-worker run; the pre-worker run on the move
commit read identically. PS2/PS3/DRS1/DRS4/DRS5 probe source text via
`inspect.getsource`, because their effect is not an observable return value;
DRS2 and DRS3 probe BEHAVIOUR (they call `serve_response`), which needed the
harness launched under the verifier's deps — §(4).

### (1e) Three findings, from rows that came back wrong first — each rightly

- **W1 → `UNEXPECTED_GREEN`, and the CLAIM was wrong, not only the test.** The
  failure cap first counted only workers that failed before their FIRST answer,
  documented as sparing a healthy worker's run of slow inputs. A respawned
  worker is always fresh, so the second slow input already counts: the
  distinction moved the cap by one input and nothing could tell it from the
  simple rule. Replaced by the simple rule (W1b + W5). The worker's module doc
  keeps the disproof on the record.
- **DRS1–4 → `NOT_LIVE`, then `WRONG_TESTS_RED`.** `NOT_LIVE` was the probe
  interpreter lacking the verifier's deps (§(4)). Then: the section title began
  `--diff-replay-serve`, and the `expect_red` name was written without those
  dashes, so a `-` preceded it — and `expect_red` matches a whole token whose
  edges may not be `-`. (This bullet first concluded such a title "can never be
  matched"; executing `gate.names_a_red` shows the name WITH its `--` matches.
  #662 review.) The title was changed anyway and is citable ("diff-replay serve
  mode matches single-shot, input by input").
- **DRS4 → `WRONG_TESTS_RED` again after that**: the section let a raising serve
  loop escape as a traceback with no `FAIL:` line, which would also skip REG. It
  now reports it.

### (1f) The review round — and the defect every reviewer missed

`/pr-review-toolkit:review-pr` ran five reviewers (code, silent failures, tests,
comments, type design). None found a Critical defect. **CI found it:** the
PR's first `cargo test (ubuntu-latest)` run was **CANCELLED** five minutes
after the job's 30-minute cap, and GitHub kept **no log at all**
(`BlobNotFound`). A cancelled job with no log is a runner that died, not a
slow test.

**Root cause — `python_worker.rs` killed every process the user owned.** The
worker's process-group kill ran `kill -KILL -<pgid>`. procps-ng 4.0.4's `kill`
(Ubuntu 24.04, CI's image) reads `-<pgid>` as an unknown option, and its
`case '?'` branch computes `pid = '0' - optopt`, which is **-1**
(`src/kill.c` at tag v4.0.4). So `kill(-1, SIGKILL)`. Every retire ran it,
including the healthy end of each target, so the first worker unit test to
finish killed the test binary and the runner. macOS's BSD `kill` parses the
same argv correctly, which is why every local run passed. One reviewer read
the procps source and concluded the spelling worked.

Measured, both directions, in containers:

| Where | What ran | Result |
|---|---|---|
| `ubuntu:24.04`, procps-ng 4.0.4 | `/usr/bin/kill -KILL -145` | a bystander outside group 145 **killed**; `kill -KILL -- -145` spared it |
| `ubuntu:24.04`, procps-ng 4.0.4 | the **pre-fix** test binary, `python_worker` filter | the binary itself SIGKILLed (**exit 137**) after 3 tests; a bystander in its own session **killed** |
| `debian:bookworm`, procps-ng 4.0.2 | same argv / same pre-fix tests | the group LEADER alone killed; `a_silent_worker_times_out_and_its_whole_process_group_is_killed` **FAILED** (a second, different Linux breakage) |
| `rust:1.97.0-bookworm`, arm64 | the **fixed** kill (`8343d2b6`), the CI step verbatim, cold `uv` | **37 passed**, 50 of 50 committed inputs, 6.73 s |
| `ubuntu:24.04`, procps-ng 4.0.4 | the **final** review-round binary (`b80fb182`), a bystander in its own session, cold `uv` | **43 passed**, "50 of 50 compared" across the seven finish lines, bystander **ALIVE** |

All four are arm64 (Docker on Apple silicon); CI is x86_64. The only
platform-specific path is `kill(2)`, whose negative-pid semantics are POSIX.

**Fix** (`8343d2b6`): `rustix::process::kill_process_group`, a safe `kill(2)`
wrapper (the workspace forbids `unsafe`; `rustix` 1.1.4 was already locked via
`tempfile`/`fs4`, now a unix-only dev-dependency with `process`, exact pin). A
group id of 0 or 1 is refused. CLAUDE.md records the trap beside the replay
command.

**Every review finding was fixed or filed** — one commit each; `git log` has
the reasoning:

| Finding | Commit |
|---|---|
| **Critical** — `kill -KILL -<pgid>` is `kill(-1)` on procps-ng 4.0.4 | `8343d2b6` |
| the group-kill test's `kill -0` probe read "could not run" as "dead" | `8343d2b6` |
| DRS scored two identical `error` verdicts as equivalence (a broken `replay_bytes` printed PASS 50) | `f3b54d24` |
| DRS had no per-ROOT floor (losing `diff_regressions/` passed on 49) | `d0473fd9` |
| a group kill after EVERY retire, post-reap (pgid-reuse window); the leader-died case untested | `76ea39d9` |
| reply-expecting worker tests shared the 400 ms timeout budget | `9238b74e` |
| progress/worker tests that could not fail on what they are named for | `0c1ff782` |
| the cap counts answers, not verdicts — docs said "verdict"; its test looped below the cap | `de6db9e5` |
| `judge`'s token tolerance untested at its call site | `6269e800` |
| an unclassified target took the loose comparison (predates #655) | `3d486e5a` |
| a reject without `error_class`/`detail` parsed with defaults (predates #655) | `e6e36a69` |
| which corpus dirs count as committed was untested (predates #655) | `32043a5e` |
| past the cap: a harness line per skipped input, and "replayed N" when nothing was | `0995a9b9` |
| four comments still pointing into the pre-`judge` test loop | `1e2848de` |
| a broken line continuation in the harness-failure message | `24e99606` |
| "about a minute" vs 27.5 s | `a90ad142` |
| protocol doc described the REJECTED cap rule | `f110f84e` |
| stdout-redirect overclaim; BadRequest's Rust-side cost | `642ebe3b` |
| two docs named only single-shot mode | `712eb5e3` |
| the protocol doc records this round's contract changes | `ecf4b4cc` |
| CLAUDE.md: "a `--` title can never be matched" (false, by execution) | `df5a1990` |
| CLAUDE.md: 136 → 156 lines, 65 → 66 files, 29/29 → 30/30 | `a6451368` |
| CLAUDE.md: the kill-utility trap | `1a08f0e1` |
| `RustProbe` validated nothing when built directly; `["a,b"]` passed | `7fa23a50` |
| a GREEN row's gate need not build its scoped probe's target (false green); spec refusals were tracebacks, exit 1 | `b80fb182` |
| Python re-reads each input by path (predates #655) | filed **#663** |
| make the target an enum (the fuller fix behind `3d486e5a`) | filed **#664** |

**Mutation evidence for the review round** — `scripts/mutate.py` output, after
`--self-test` 20/20. Each row removes one fix. All 11 `RED_AS_EXPECTED`, exit 0,
tree clean afterwards.

| # | Mutation | Gate | Live | Outcome | Reds |
|---|---|---|---|---|---|
| K1 | the group kill signals the leader alone: the forked child survives both the timeout and a dead leader | `cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay` | yes (artifact) | RED_AS_EXPECTED | a_silent_worker_times_out_and_its_whole_process_group_is_killed, a_leader_that_dies_leaving_a_forked_child_has_its_group_killed |
| K2 | group id 1 is accepted, so a wrong id could widen the SIGKILL to kill(-1) | `cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay` | yes (artifact) | RED_AS_EXPECTED | a_group_id_that_would_widen_the_kill_is_refused |
| K3 | no group kill after a leader that exited unsuccessfully: its forked child is left running | `cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay` | yes (artifact) | RED_AS_EXPECTED | a_leader_that_dies_leaving_a_forked_child_has_its_group_killed |
| E1 | an error answer counts toward the worker-failure cap | `cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay` | yes (artifact) | RED_AS_EXPECTED | an_error_verdict_is_a_harness_failure_but_keeps_the_worker |
| P1 | the start line prints total where committed belongs (passed the old contains('3') test) | `cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay` | yes (artifact) | RED_AS_EXPECTED | a_start_line_names_the_target_and_both_counts |
| P2 | the finish line swaps two counts | `cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay` | yes (artifact) | RED_AS_EXPECTED | a_finish_line_names_both_counts_so_a_ci_log_proves_what_was_replayed |
| J1 | judge compares tokens strictly, dropping the phase-dependent tolerance at its call site | `cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay` | yes (artifact) | RED_AS_EXPECTED | a_phase_dependent_pair_on_a_compared_target_agrees, differential_replay_full_corpus |
| J2 | a target in neither classification list falls back to the loose comparison | `cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay` | yes (artifact) | RED_AS_EXPECTED | an_unclassified_target_is_a_harness_failure_not_the_loose_comparison |
| B2 | a reject missing error_class/detail parses with defaults again | `cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay` | yes (artifact) | RED_AS_EXPECTED | a_reject_without_a_string_class_and_detail_is_a_harness_failure |
| C1 | the gitignored runtime corpus counts toward the committed floor (#656's fail-open) | `cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay` | yes (artifact) | RED_AS_EXPECTED | only_the_seed_and_regression_directories_count_as_committed |
| DRS6 | replay_bytes raises NameError in both modes: two identical error verdicts must not pass DRS | `uv run core/tests/python/conformance.py` | yes (interpreter) | RED_AS_EXPECTED | diff-replay serve mode matches single-shot, input by input |

DRS6's other direction was measured by hand: the same planted `NameError`
against the pre-fix section (`git show 6952aec2:`) printed `PASS 50 committed
inputs over 7 targets`. The DRS per-root floor (`d0473fd9`) is not a harness row
— the mutation that proves it deletes a directory — and was measured by hand in
both directions: PASS on 49 inputs before, FAIL naming the root after.

**The finding that generalises, again:** five reviewers read a subprocess
kill and none ran it on the platform that mattered; the one who read the
procps source read it wrong. A command-line spelling is a contract with
whichever implementation is on PATH. Where a syscall is available, call it.

### The measured gate set

Re-run in full after the review round, at `b80fb182` (the table below it is
the original slice's run, kept for comparison):

| Gate | Result after the review round |
|---|---|
| `cargo test --release --locked --workspace` | 0 — **2157 passed, 0 failed**, 99 suites (unchanged: the replay binary stays out of this run) |
| the differential-replay step (CI spelling) | 0 — **43 passed**, 1.41 s |
| both `cargo clippy ... --tests -- -D warnings` spellings, rustdoc `-D warnings`, `cargo fmt --all --check` | all 0 |
| `uv run core/tests/python/conformance.py` | 0 — 0 FAIL, REG **30/30**, DRS "50 committed inputs … each decoded" |
| `uv run --with pytest python3 -m pytest scripts/mutation_harness -q` | 0 — **278 passed** (C10/N4 included) |
| `scripts/mutate.py --self-test` | 0 — 20/20 |
| six hygiene guards, `--self-test` first, 12 invocations | all 0 |
| `actionlint .github/workflows/test.yml` | 0 |
| `spec_test_name_freshness.py` | exit 1, **98** unresolved — unchanged (#642) |
| the replay in `ubuntu:24.04` with procps-ng 4.0.4 | 43 passed, bystander alive — §(1f) |

The original slice's run, at `6952aec2`:

| Gate | Result |
|---|---|
| `cargo test --release --locked --workspace` | 0 — **2157 passed, 0 failed** over 90 test binaries + 9 doc-test suites (unchanged from `main`: `required-features` keeps the replay binary out of this run) |
| the differential-replay step (CI spelling) | 0 — **36 passed**, 1.42 s |
| same, with the 74,924-file runtime corpus symlinked in | 0 — 1 passed (full corpus), **27.48 s** |
| `cargo clippy --release --locked -p secretary-core --features differential-replay --tests -- -D warnings` | 0 |
| `cargo clippy --release --locked --workspace --tests -- -D warnings` | 0 |
| `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace` | 0 |
| `cargo fmt --all --check` | 0 |
| `uv run core/tests/python/conformance.py` | 0 — 0 FAIL, REG **30/30** |
| `uv run --with pytest python3 -m pytest scripts/mutation_harness -q` | 0 — **262 passed** (249 + 13) |
| `uv run scripts/mutate.py --self-test` | 0 — 20/20 |
| six hygiene guards, `--self-test` first, 12 invocations | all 0 |
| `actionlint .github/workflows/test.yml` | 0 |
| `uv run core/tests/python/spec_test_name_freshness.py` | exit 1, **98** unresolved = `main`'s count (#642). This branch briefly made it 101 — `replay_bytes`, a Python name the heuristic took for a Rust fn; added to its known-Python list, self-test green |

---

## (2) What this slice does **not** claim

- **Serve-vs-single-shot equivalence is checked on the COMMITTED corpus only.**
  A verdict that depended on interpreter state could in principle surface only
  on some sequence of gitignored fuzz inputs. Single-shot `--diff-replay` stays
  so such an input can be re-run in isolation. Section DRS's LIMIT says so.
- **The fuzz corpus is still not replayed in CI.** CI has no `core/fuzz/corpus/`.
  What changed is that a developer who has fuzzed can now replay it in half a
  minute instead of never.
- **The DRS recursion guard was not measured in its unguarded form** — running
  that is the cascade it prevents. DRS5 measures the guarded path.
- **The 5.98 s CI replay and 36 s step figures from #656 are stale** (they
  measured the per-input spawn) and are kept in CLAUDE.md/test.yml as flagged
  history. **Re-measure from this PR's CI log**; nothing here does.
- **The token comparison, the tolerance, and #641/#646/#658 are unchanged.**
- **That cargo names the test binary under `--test` is measured, not pinned** —
  #661.
- **The kill fix is proven on Linux in containers (arm64), not yet by CI
  (x86_64).** This PR's first CI run died before producing a log; the re-run on
  the pushed review round is the first CI evidence. Read its replay step's
  finish lines ("50 of 50 compared") rather than trusting its green tick.
- **A native write to file descriptor 1 is not redirected** by serve mode; it
  fails closed as a non-JSON line (#662 review narrowed the docs, not the
  mechanism).

---

## (3) What is next — with acceptance criteria

**(a) #641 — widen the token comparison to `record` and `block_file`.** Now
cheap to iterate: the full fuzz corpus (7,454 `record` inputs) replays in
seconds, and #649 put the edit in `targets.rs` + `rust_decoder.rs` +
`agreement.rs`. **Acceptance:** both targets in `TOKEN_COMPARED_TARGETS`, a
Rust `rule_token()` per error variant (exhaustive match) and typed Python
exceptions, Section RTV-style identity checks, and **a full-corpus local run
with the runtime corpus present** recorded in the handoff alongside CI.
Mutation-prove with the scoped probe.

**(b) #612 — `manifest_uniqueness_kat.rs` (measure; it was 848).** Acceptance
unchanged: under 500 via `manifest_uniqueness_kat_helpers/`, name set diffed.

**(c) #657 — pin that the CI step stays wired.** Still reds nothing if deleted.

**(d) #660 — `parse_known_args` fall-through.** Small; see the issue's options.

**(e) #646 / #658** — unchanged; #646 is a spec slice as much as code.

**(f) #661, #633, #642, #623 / #624 / #625 / #626 / #628 / #629 / #630 / #635 /
#640 / #643 / #648 / #653 / #654** stay open.

### Issues this slice closes — verify against the code, not this document

**#649** and **#655.** Per the `(#N)`-not-`Closes #N` convention they stay open
until a human closes them.

```bash
wc -l core/tests/differential_replay.rs core/tests/differential_replay_helpers/*.rs \
      core/tests/differential_replay_helpers/python_worker/tests.rs   # every file < 500
grep -c "diff-replay-serve" core/tests/python/conformance.py           # >= 1
grep -c "command.process_group(0);" core/tests/differential_replay_helpers/python_worker.rs  # 1 (the bare "process_group(0)" also matches its doc comment: 2)
grep -c '"DRS"' core/tests/python/conformance_lib/sections/registry.py            # 1
grep -c '"test", "features"' scripts/mutation_harness/spec.py                      # 1
```

---

## (4) Open decisions and risks

### The finding that generalises: an instrument's blind spot looks like the code's

M649a's first `NOT_LIVE` was not the mutation failing to land — it was the probe
unable to see the directory. Every `core/tests/**` row in this repo had that
blind spot, and because `NOT_LIVE` is the fail-SAFE outcome, nobody had written
one. **When a measurement comes back "nothing to see", ask whether the
instrument could have seen it.** The same shape produced W1's
`UNEXPECTED_GREEN`, one level up: a documented distinction no test could
observe, because it barely existed.

### Mutation-harness gotchas this session hit (now in CLAUDE.md)

- A **Python probe imports its module in the harness's own interpreter**, which
  lacks `conformance.py`'s PEP 723 deps. A probe on anything reaching `cbor2`
  reads `NOT_LIVE` with an import traceback. Launch as
  `uv run --with cryptography --with pynacl --with "pqcrypto<1" --with argon2-cffi --with blake3 --with cbor2 scripts/mutate.py SPEC`.
- The probe `expr` must evaluate to a **string** (compared against
  `repr(equals)`); `str(...)` it.
- An `expect_red` name is matched as a whole token: the characters either side
  of it on the `FAIL:` line may not be `-`, `.`, `/` or a word character. Write
  a `--`-prefixed title WITH its dashes (#662 review corrected "can never be
  matched").
- A GREEN row with a scoped Rust probe must spell its scope in the gate
  (`--test <target>`, each feature or `--all-features`), or the spec is
  refused, exit 2 (#662 review).

### Standing risks this slice does not remove

- **`.gitignore`'s `corpus/` matches directories only**, so a `core/fuzz/corpus`
  SYMLINK (how this session replayed the main checkout's corpus from a
  worktree) shows as untracked. It was removed after each run; do not commit one.
- **The harness is still not in CI**; adoption is a convention.
- **Five of the six PEP 723 deps remain unbounded** and `ed25519_verify` keeps
  its fail-open shape (#544 / #550).
- **Files past 500 lines**: `card.rs`, `manifest_uniqueness_kat.rs`,
  `canonical/value.rs`, `manifest/encode/tests.rs`, `sync/state.rs` — #625 /
  #612 / #603 / #630 / #626. `differential_replay.rs` is off that list.

---

## (5) How to resume — the exact commands

```bash
# FIRST — it has fired in three of the last five sessions:
git fetch origin && git log --oneline main..origin/main

cd /Users/hherb/src/secretary/.worktrees/diff-replay-split
pwd && git branch --show-current && git worktree list

# --- the replay, CI shape (a fresh worktree has no corpus/) ---
cargo test --release --locked -p secretary-core \
  --features differential-replay --test differential_replay      # 43 passed, ~1.4 s

# --- the replay over the real fuzz corpus (the point of running it locally) ---
# In the MAIN checkout it just works. From a worktree, borrow main's corpus and
# REMOVE the link afterwards (the gitignore rule does not cover a symlink):
ln -s /Users/hherb/src/secretary/core/fuzz/corpus core/fuzz/corpus
cargo test --release --locked -p secretary-core \
  --features differential-replay --test differential_replay -- differential_replay_full_corpus
rm core/fuzz/corpus && git status --short                        # no corpus entry

# --- prove the gate is not vacuous, through the worker ---
SCRATCH=$(mktemp -d)
cat > "$SCRATCH/ci647.toml" <<'EOF'
[[mutation]]
id = "CI647"
lang = "rust"
path = "core/src/vault/manifest/token.rs"
old = '| ManifestError::DuplicateTrashUuid => RuleToken::RepeatedArrayValue,'
new = '| ManifestError::DuplicateTrashUuid => RuleToken::MissingField,'
gate = "cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay"
expect = "red"
expect_red = ["differential_replay_full_corpus"]
note = "Rust names missing_field where Python names repeated_array_value"
probe = { package = "secretary-core" }
EOF
uv run scripts/mutate.py "$SCRATCH/ci647.toml"   # RED_AS_EXPECTED, exit 0
git status --short                                # MUST be empty

# A mutation under core/tests/ needs the SCOPED probe, or it reads NOT_LIVE:
#   probe = { package = "secretary-core", test = "differential_replay", features = ["differential-replay"] }

# --- the rest of the gate set ---
cargo test --release --locked --workspace
cargo clippy --release --locked --workspace --tests -- -D warnings
cargo clippy --release --locked -p secretary-core --features differential-replay --tests -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
uv run scripts/mutate.py --self-test                                 # 20/20
uv run --with pytest python3 -m pytest scripts/mutation_harness -q   # 278 passed
uv run core/tests/python/conformance.py                              # REG 30/30, 0 FAIL
actionlint .github/workflows/test.yml

# --- six hygiene guards, --self-test FIRST, as LITERAL commands ---
bash ffi/scripts/check-lean-binding.sh --self-test         && bash ffi/scripts/check-lean-binding.sh
bash ios/scripts/check-public-log-hygiene.sh --self-test   && bash ios/scripts/check-public-log-hygiene.sh
bash android/scripts/check-log-hygiene.sh --self-test      && bash android/scripts/check-log-hygiene.sh
bash scripts/check-secret-slot-hygiene.sh --self-test      && bash scripts/check-secret-slot-hygiene.sh
uv run scripts/check-error-payload-hygiene.py --self-test  && uv run scripts/check-error-payload-hygiene.py
uv run scripts/check-test-support-placement.py --self-test && uv run scripts/check-test-support-placement.py
```

---

## (6) Where this document lives

`NEXT_SESSION.md` at the repo root is a **symlink**, retargeted this session to
`docs/handoffs/2026-09-14-corpus-replay-worker-shipped.md`. This file is the
single authored baton — do not create a second copy, and do not sync it to
`main` during a pause window.
