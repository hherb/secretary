# NEXT_SESSION.md — the whole fuzz corpus replays in seconds (#655), the harness is split (#649), and the mutation harness can see `core/tests/`

Branch `feature/diff-replay-split`, worktree `.worktrees/diff-replay-split`,
base `66a9db76` (`main`, immediately after PR #656 merged).

The user chose this slice by options-plus-recommendation: **#649 split +
#655**, then the #655 design (**persistent worker + progress**, over an opt-out
env var or corpus sampling), then a mid-slice scope widening (**fix the
mutation harness's Rust probe here**, over filing it).

**Two issues filed:** [#660](https://github.com/hherb/secretary/issues/660)
(`conformance.py`'s `parse_known_args` falls through to the full verifier on an
unrecognised flag) and [#661](https://github.com/hherb/secretary/issues/661)
(the scoped Rust probe's cargo behaviour is measured, not pinned by a control).
The slice closes **#649** and **#655** in code.

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
| (next) | this baton and the `NEXT_SESSION.md` retarget |

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
  interpreter. The kill goes through the `kill` utility, because the workspace
  forbids `unsafe`. The response must echo its path. Any transport failure
  retires the worker; an `error` verdict does not. After **3 inputs in a row
  with no verdict** no further worker is started.
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
| unit tests in the binary | 4 | **36** (4 original names unchanged) |

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
| PS3 | an empty `test` is accepted and would build the unscoped default | `uv run --with pytest python3 -m pytest scripts/mutation_harness/tests/test_rust_probe_scope.py -q` | yes (interpreter) | RED_AS_EXPECTED | empty-test |
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
  interpreter lacking the verifier's deps (§(4)). Then: the section title began `--diff-replay-serve`,
  and `expect_red` matches a whole token whose edges may not be `-`. The title
  is now citable ("diff-replay serve mode matches single-shot, input by input").
- **DRS4 → `WRONG_TESTS_RED` again after that**: the section let a raising serve
  loop escape as a traceback with no `FAIL:` line, which would also skip REG. It
  now reports it.

### The measured gate set

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
- An `expect_red` name cannot start or end with `-`, `.`, `/` or a word
  character adjacent to it on the line.

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
  --features differential-replay --test differential_replay      # 36 passed, ~1.4 s

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
uv run --with pytest python3 -m pytest scripts/mutation_harness -q   # 262 passed
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
