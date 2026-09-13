# NEXT_SESSION.md — the decoder-agreement gate now runs in CI (#647), and a mutation row names its gate (#651)

Branch `feature/diff-replay-ci`, worktree `.worktrees/diff-replay-ci`,
base `53fd6635` (`main`, immediately after PR #652 merged).

This slice is **(a)** from the previous baton's §(3) queue, taken together with
**#647** by the user options-plus-recommendation, on the reasoning that widening
a gate matters less than making it run at all.

**Four issues filed:** [#655](https://github.com/hherb/secretary/issues/655)
(the fuzz-corpus replay trap), plus
[#657](https://github.com/hherb/secretary/issues/657) and
[#658](https://github.com/hherb/secretary/issues/658) from the #656 review, and
[#659](https://github.com/hherb/secretary/issues/659) — filed from this PR's CI
and then fixed in it, see §(1f).
The slice closes **#647** and **#651**.

**The headline: the gate that exists to prove the two decoders agree was the
one gate nothing ran — for three slices, while four documents cited its
results.** That is §(1a).

---

## (0) The starting-state check did NOT fire — first time in four sessions

`git fetch origin && git log --oneline main..origin/main` returned empty;
`main` was already `53fd6635`. **Run it anyway.** It fired in three of the
previous four sessions, and the symlink gives no signal when it is stale.

Housekeeping: `.worktrees/mutation-harness` removed and
`feature/mutation-harness` deleted (merged as PR #652; two-dot diff against
`main` EMPTY, so `-D` was measured rather than judged — note `git branch -d`
warns "not yet merged to HEAD" after a squash-merge, which is expected and is
not the check). Three older local branches deliberately left alone, unchanged
ruling.

---

## (1) What shipped

Three substantive commits, then the baton and its corrections. The count is
deliberately not written out — it went stale twice while this table was being
edited, which is the same lesson as every RE-MEASURE note in `CLAUDE.md`. Run
`git log --oneline main..HEAD` for the current set.

| SHA | What |
|---|---|
| `22b84a75` | #651 — every mutation row names its gate |
| `512ea18c` | #647 — the replay runs in CI |
| `6e0b9872` | #651 — four documents corrected |
| `e4526cb7` … | the baton, then its own corrections — a figure reconciled across four documents, two counts corrected against their logs, and a §(3) verification block that did not verify |

### (1a) #647 — the defect

`core/tests/differential_replay.rs` is `#![cfg(feature =
"differential-replay")]` and no workflow enabled the feature, so the file was
not merely unrun: it was **not compiled**. The corpus comparison, #634's
rule-token tolerance, that tolerance's negative control and its committed
witness were all local-only, while `CLAUDE.md`, `ROADMAP.md` and two handoffs
cited results from them.

`test.yml`'s `rust-test` job now runs it as a Linux-only step:

```
cargo test --release --locked -p secretary-core \
  --features differential-replay --test differential_replay
```

A **step, not a job**, for three measured reasons: `cargo test
(ubuntu-latest)` is already one of `main`'s 24 required contexts, so the gate
binds on day one with no ruleset edit; that job already installs `uv` and
caches the cargo build, both of which the replay needs; and a separate job's
`rust-cache` entry would pay a cold dependency build for a test whose BODY runs in
seconds (the split is in §(2); do not read the 36 s step figure as a test time).
Linux-only mirrors `clean-room conformance` — the decoders are
platform-independent and the macOS leg would pay a cold `pqcrypto` wheel build
for no new signal. `-p secretary-core` rather than `--workspace` because the
feature gates exactly one test file and no `src/` code.

**Negative-controlled, because a gate that runs and catches nothing is #546
restated.** Re-pointing one ORDERED token, a pair §4.2 grants no licence. The
row is in the table under §(1c) — pasted from `mutate.py` rather than shaped by
hand, which the first version of this document did not manage on the very slice
that added the Gate column (#656 review).

### (1b) The measurement that shaped the design, and a live trap

The replay feeds `core/fuzz/corpus/<target>/` **as well as** the committed
seeds, and that directory is gitignored runtime fuzz output that grows without
bound.

| Case | Inputs | Result |
|---|---|---|
| CI shape (no runtime corpus), local | 50 | 4 passed, **11-24 s** (three runs) |
| CI shape, on the `ubuntu-latest` runner | 50 | 4 passed, **5.98 s** |
| One `conformance.py --diff-replay`, warm | 1 | **0.16 s** |
| This machine, corpus present | **74,924** | killed at 10 min; ~3.3 h implied |

So **every** `--features differential-replay` spelling is unusable on a
checkout that has fuzzed, and **it presents as a hang** — `cargo test` prints
nothing but "has been running for over 60 seconds". Say the trap belongs to the
TEST, not to the scope flag: `corpus_dirs` pushes `core/fuzz/corpus/<target>`
unconditionally, and `differential_replay_full_corpus` lives in the same binary
`--test differential_replay` selects, so the narrow command this slice added
hangs identically. An earlier draft of this section blamed `--workspace` and
recommended the narrow form as the escape, which would have sent the next
session into the same three hours (#656 review). Documented in the Commands
block and filed as **#655**. A fresh `git worktree` has no `corpus/`, which is
why this branch's worktree reproduced the CI shape for free.

### (1c) #651 — a mutation result is a property of ONE gate

The 2026-09-10 handoff recorded M8 as **"GREEN, by design … nothing catches it
and nothing should"**. The first half is right; the second generalised one
gate's answer to every gate. Re-measured here with the harness rather than
trusted — `UNEXPECTED_RED`, exit 1, twice.

**Name the CHECK, because the obvious guess is wrong.** Section RTV's **check
1 does not fire**: it iterates `_TOKENED_CLASSES`, the seven
`ManifestRejection` subclasses, and `ArraySortOrderViolation` is a plain
`ValueError` subclass that is not among them. The sole catch is **check 4**,
the corpus-token SET EQUALITY, reported on the `PASS 3` line. Neither
implementation is wrong: §4.2 frees the ORDER two readers may report rules in
and says nothing about a raise site changing WHICH rule it names.

**Four carriers, found by sweep rather than by the one the issue named** —
`CLAUDE.md`, `ROADMAP.md`, the 2026-09-10 handoff, and that slice's design
spec. ROADMAP **contradicted itself in adjacent bullets**: its #634 entry made
the unscoped claim while its #644 entry, the next one down, recorded the gate
mismatch correctly. (Adjacent at the merge-base; this slice inserts a bullet
between them, which is why an earlier draft here said "two bullets apart" and
"directly below" in one breath — #656 review.)

The structural half: `render_markdown` gains a per-row **Gate** column and
`render_json` a `gate` key, so the generalisation cannot be written from a
pasted table again. Per row, not a caption — a spec may mix gates, and those
are exactly the specs where the ambiguity bites.

**Every mutation row below is `mutate.py` output, pasted.** The first version
of this document shaped both its tables by hand, omitted the very column this
slice added, and gave one of them its gate as a prose CAPTION — the form the
paragraph above argues against, in a document that genuinely mixes gates
(#656 review). This single run demonstrates the point instead of asserting it:
two instruments, five rows, each naming its own.

| # | Mutation | Gate | Live | Outcome | Reds |
|---|---|---|---|---|---|
| CI647 | Rust names missing_field where Python names repeated_array_value | `cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay` | yes (artifact) | RED_AS_EXPECTED | differential_replay_full_corpus |
| R1 | _cell stops escaping backslashes, so a backslash before a pipe bares the pipe | `uv run --with pytest python3 -m pytest scripts/mutation_harness/tests/test_report.py scripts/mutation_harness/tests/test_types.py -q` | yes (interpreter) | RED_AS_EXPECTED | test_a_backslash_before_a_pipe_in_the_gate_does_not_add_a_column |
| R2 | _code_span fences an escaped value, putting the escape on screen | `uv run --with pytest python3 -m pytest scripts/mutation_harness/tests/test_report.py scripts/mutation_harness/tests/test_types.py -q` | yes (interpreter) | RED_AS_EXPECTED | test_a_value_carrying_a_backslash_is_left_unfenced |
| R3 | delimiter row loses a group, so GFM renders a paragraph not a table | `uv run --with pytest python3 -m pytest scripts/mutation_harness/tests/test_report.py scripts/mutation_harness/tests/test_types.py -q` | yes (interpreter) | RED_AS_EXPECTED | test_markdown_marks_a_row_that_measured_nothing |
| R4 | header columns reordered against the rows | `uv run --with pytest python3 -m pytest scripts/mutation_harness/tests/test_report.py scripts/mutation_harness/tests/test_types.py -q` | yes (interpreter) | RED_AS_EXPECTED | test_the_column_set_and_its_order_are_pinned |

A side finding worth carrying: the report tests indexed cells **positionally**
(`cells[3]` for Live). A column INSERTION silently repoints such an assertion
onto whatever lands at that index — this very change would have moved two of
them with no failure. They read by header NAME now.

### (1d) Two CLAUDE.md claims this branch itself falsified

Not stale by age — falsified by the code in this branch, which is the harder
case to notice:

- "Almost none of this runs in CI … not even COMPILED in CI" is rewritten to
  what #647 leaves true, with the residual as a scope rather than a caveat.
- The #546 paragraph's "never enabled in `test.yml`" now reads as the history
  it is. **Verified before writing** that the #647 step would not have caught
  the `pqcrypto` break either — but state the property that was actually
  checked, which is an IMPORT CLOSURE and not a directory: `diff_replay.py`
  imports only `codec/*` plus `rejection`, and no `codec/` module reaches
  `derivations.hybrid_verify`, so nothing on the `--diff-replay` path calls
  `ml_dsa_65_verify`. The first wording said that function is "reachable only
  from `sections/`", which is false — it lives in `derivations.py` and
  `wire/card.py` and `wire/golden_vault_verify.py` both import it. Same
  conclusion, sound reason (#656 review).

### (1e) The #656 review round — what a four-agent review found

Every finding below was measured, not argued, and each one is a defect in this
branch rather than in what it replaced. They are recorded here because three of
them are the same failure this slice is ABOUT, committed while writing it.

**Two gates that could pass having proven nothing.**

- `--test differential_replay` was tied to `--features differential-replay` by
  nothing but the text of one `run:` line, and with the feature off the target
  compiles to an EMPTY harness. Measured both ways on the same command: exit 0
  with `running 0 tests` before, **exit 101** after a `[[test]]` entry with
  `required-features` in `core/Cargo.toml`. So dropping the flag in a later
  edit would have restored the #647 state under a step name that still claimed
  to run the replay, inside a required context. The `--workspace` step's own CI
  log shows that 0-test binary, which is how it was found.
- `MIN_CORPUS_INPUTS` counted the gitignored runtime corpus toward the floor,
  so on a fuzzed machine — the only machine the floor protects, CI having no
  `corpus/` — a deleted committed seed still cleared it by tens of thousands.
  The floor is now over committed inputs only, proven by staging exactly that
  state: **38 committed against 41 total, floor 39, reds.**

**Three measured claims that were wrong, each carried in three documents.** The
36 s CI figure is a STEP duration, ~30 s of it cargo; the replay is 5.98 s and
CI is FASTER than local, so the "cold `uv` environment" attribution was
backwards. `-p secretary-core` does not avoid the CLI and bridge crates, which
are pulled in through `core`'s own `[dev-dependencies]` and appear in the
step's log. And the hang trap belongs to `corpus_dirs`, not to `--workspace`,
so §(5)'s resume block was recommending as an escape the very command that
hangs.

**The five-column sweep this slice should have done itself.** #651 added a
sixth column and left the count asserted in five places — `CLAUDE.md`,
`scripts/mutate.py` twice, a test docstring, and the NORMATIVE §7 of the
2026-09-11 design spec that `report.py` cites by name, whose example table
still showed the M8 row with no gate. All now state the RULE (the table carries
what a reader needs to INTERPRET a row) rather than a number, which is the only
version that survives the next column.

**Three test gaps, all measured by mutation before being closed.** The
delimiter row was read by no test, and a five-group separator under a
six-column header reddened nothing while making GFM render the block as a
paragraph rather than a table. Column ORDER and column NAMES were unpinned.
And `_cell` escaped `|` but not `\`, so an ordinary `grep 'a\|b'` gate came
out as `\\|` — an escaped backslash followed by a BARE pipe, silently adding a
column — while the oracle could not see it, being the inverse of the same
`replace`. Both halves fixed: `_cell` escapes the backslash first, and the
oracle scans by parity.

**One value type that still admitted a false green.** `gate = ""` parsed
(`_require_str` checks the type), `bash -c ""` exits 0, and an
`expect = "green"` row then reported `GREEN_AS_EXPECTED` having run no gate.
Refused in `MutationSpec.__post_init__` now, where PR #652 put the same class
of guard. `gate = "true"` stays legal — the claim is that a gate was NAMED.

**Two structural items filed rather than fixed:** #657 (nothing pins that the
CI step stays wired) and #658 (the floor counts inputs, not strict token
comparisons — ~7 of 39 on `manifest_body` reach one).

**The generalisation.** Three of these are this slice's own thesis applied to
itself: it corrected four carriers of one over-general claim while creating a
new one in the correction, shipped a per-row Gate column and then pasted two
hand-made gateless tables, and documented a trap with the wrong cause. A sweep
for the phrase you are fixing is not a sweep for the property you changed.

### (1f) `cargo audit`: a yanked `der`, fixed by a lockfile-only bump (#659)

`cargo audit --deny warnings` red this PR on `der 0.8.0`, **yanked** — a
supply-chain signal, not a vulnerability. It is pre-existing: `main`'s
scheduled audit on 2026-09-07 failed identically. It surfaced HERE only because
`audit.yml` is path-gated on `**/Cargo.toml`, and the #656 review's
`required-features` entry touched `core/Cargo.toml`. `cargo audit` is not a
required context, which is also why the failure sat on `main` unremarked.

The chain, read from `Cargo.lock`: `secretary-core` → `ml-dsa 0.1.0-rc.8` →
`pkcs8 0.11.0-rc.11` (and `spki 0.8.0`) → `der 0.8.0`. **It looks like a bump of
the ML-DSA-65 primitive and is not one**, and the distinction was measured:

- `ml-dsa`'s `pkcs8` dependency is OPTIONAL, enabled only by its `pkcs8` and
  `default` features. `secretary-core` takes it with `default-features = false,
  features = ["alloc", "zeroize"]`, and `alloc = ["pkcs8?/alloc"]` — the `?`
  applies `alloc` to `pkcs8` only if something else already enabled it. So the
  whole `pkcs8`/`spki`/`der` subtree is NEVER COMPILED. It is in `Cargo.lock`
  only because Cargo resolves the lockfile across all optional dependencies,
  and `cargo audit` reads the lockfile rather than the build graph.
- `cargo tree -i der@0.8.0 --target all -e all` and the same for
  `pkcs8@0.11.0-rc.11` both print nothing — before AND after the bump.
- `pkcs8` asks for `der ^0.8.0-rc.12` and `spki` for `der ^0.8`, and `0.8.1` /
  `0.8.2` exist unyanked, so no manifest needed to change and `ml-dsa` stays
  exactly where it was.

`cargo update -p der@0.8.0 --precise 0.8.2`. The lockfile diff is one version,
one checksum and its two dependents' references; `cargo update` reported every
other package unchanged. A warm `cargo build --release --locked --workspace`
recompiled **zero** crates after it, which is Cargo's own statement that no
compiled artifact's dependency graph moved. CLAUDE.md's rule for a primitive
crate — "re-run KATs explicitly; a passing suite is necessary but not
sufficient" — was followed anyway, since the chain runs through one:
`ml_dsa_65_nist_keygen_kat`, `ml_dsa_65_nist_sigver_kat`,
`hybrid_sig_wire_kat`, both golden-vault binaries and `conformance.py` all pass.

**Do not "tidy" this into a manifest pin.** Nothing compiles `der` 0.8, so an
exact pin in `core/Cargo.toml` would be a security-path-looking annotation on
code that is not on the path — the misleading kind. If `ml-dsa`'s `pkcs8`
feature is ever enabled, THAT edit is where this subtree needs review.

### The measured gate set

| Gate | Result |
|---|---|
| `cargo test --release --locked --workspace` | 0 — **2157 passed, 0 failed** over **90** test binaries plus 9 doc-test suites. It was 91: the `required-features` entry stops the default run building the 0-test `differential_replay` binary at all, and that binary no longer appears in the log |
| the new differential-replay step | 0 — **4 passed**, 11-24 s local / 5.98 s on CI |
| `cargo clippy --release --locked --workspace --tests -- -D warnings` | 0 |
| `cargo clippy … -p secretary-core --features differential-replay --tests -- -D warnings` | 0 — a NEW `rust-lint.yml` step. The line above never linted `differential_replay.rs`, because cargo skips a target whose features are unmet, so ~540 lines on a blocking test path were outside the `-D warnings` gate |
| `cargo fmt --all --check` | 0 |
| `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace` | 0 |
| `uv run scripts/mutate.py --self-test` | 0 — **20/20** |
| `uv run --with pytest python3 -m pytest scripts/mutation_harness -q` | 0 — **249 passed** (238 at the merge-base; +4 for #651, +7 for the #656 review round) |
| `uv run core/tests/python/conformance.py` | 0 — 0 FAIL, REG **29/29** |
| six hygiene guards, `--self-test` first, 12 invocations | all 0 |
| `cargo audit --deny warnings` | exit 1 on `der 0.8.0` (yanked) before the bump, **0** after; see §(1f) |
| `actionlint` on `test.yml` AND `rust-lint.yml` | 0, **and both new step names parsed back in full** (the unquoted-`#` truncation trap this file warns about four times) |

**Branch scope — re-derive it, do not quote this.** Run
`git diff origin/main...HEAD --name-only`. The first version of this block
listed "two `docs/` files" where there were three plus the `NEXT_SESSION.md`
symlink, and claimed **"No Rust, no FFI, no `core/`"** — a claim the #656
review then falsified twice over. That scope choice was itself the defect: two
comments under `core/` asserted in the present tense that the replay "runs in
no CI workflow (#647)", citing the issue this branch closes, and they were left
behind precisely because `core/` was declared out of scope.

The branch now touches `core/` deliberately, in four places, none of them
crypto or on-disk format — plus the root `Cargo.lock`, for the §(1f)
`der` bump, which changes no compiled artifact:

- `core/Cargo.toml` — the `[[test]]` entry whose `required-features` binds the
  target to its feature.
- `core/tests/differential_replay.rs` and
  `core/tests/differential_replay_helpers/corpus.rs` — the committed-only
  input floor.
- `core/src/vault/manifest/token/tests/mapping.rs` — a doc comment, stale in
  both of its clauses.
- `core/tests/python/conformance_lib/sections/rule_token_vocabulary.py` — the
  same stale sentence.

Still untouched: every crypto primitive, every on-disk byte, the FFI crates,
and all four platform trees. README checked and deliberately NOT edited: it
documents specs and protocols and names no CI job at all, so that split is
established rather than inferred.

---

## (2) What this slice does **not** claim

- **CI replays the COMMITTED corpus, not the fuzz corpus.** 50 inputs:
  `core/fuzz/seeds/` plus `core/tests/data/diff_regressions/`.
  `core/fuzz/corpus/` is gitignored, so agreement on fuzz-DISCOVERED inputs is
  still proven only by whoever runs the fuzzer. Do not read "the differential
  replay is in CI" as "the fuzz corpus is differentially replayed in CI".
- **Only `manifest_body` is token-compared.** The five ordinary targets are
  #641 and `manifest_file` is blocked by #640. #647 changes where the existing
  comparison RUNS, not what it covers.
- **The tolerance is unchanged and still broader than §4.2 licenses** — 58 of
  136 unequal pairs, four groups with no licence, tracked by #646.
- **The CI timing, split — and the split is the point (#656 review).** The step
  is **36 s** on `ubuntu-latest`, of which **29.91 s** is cargo ("Finished
  `release` profile ... in 29.91s", ~60 crates recompiled because the
  `-p … --features` feature set differs from the preceding `--workspace` build
  and re-fingerprints that graph in the shared target dir) and **5.98 s** is
  the replay itself over all 50 inputs. Local test bodies measure 11-24 s, so
  **CI is faster on the part that does the work** and the 50 `uv` spawns are
  bounded above by ~6 s. An earlier version of this bullet read the 36 s as a
  test time and attributed the difference to a cold `uv` PEP 723 environment;
  the step's own log refutes both halves, and the mistake matters because it
  points the next reader at the wrong lever — the real one is the feature-set
  thrash, not `uv`. Do not compare a step duration against a test duration.
- **`-p secretary-core` does NOT avoid the CLI and bridge crates**, which this
  document and the workflow comment both claimed. `core`'s
  `[dev-dependencies]` pull in `secretary-ffi-bridge`, which depends on
  `secretary-cli`, so both appear in the step's own log. What the narrowing
  drops is the Tauri desktop crate, the two FFI wrapper crates and the browser
  host, plus re-running a suite the flag does not change.
- **`MIN_CORPUS_INPUTS` keeps a shrunken corpus failing rather than passing
  vacuously** — over COMMITTED inputs only since the #656 review, because
  counting the gitignored runtime corpus made the floor fail open on the one
  machine it protects (measured: a deleted seed with `fuzz/corpus/` populated
  gave 38 committed against 41 total, and now reds). It still does not floor
  how many inputs reach a STRICT token comparison, which is ~7 of 39 on
  `manifest_body` — **#658**.
- **Nothing pins that the CI step itself stays wired.** Deleting it is
  invisible to every gate in the tree. Now filed as **#657** rather than
  recorded here only: a residual that lives in a handoff the symlink will
  repoint away from is how the #647 gap itself survived three slices. The
  feature/target half IS pinned — `required-features` in `core/Cargo.toml`
  turns `--test differential_replay` without `--features` from exit 0 and
  `running 0 tests` into exit 101 (measured both ways).

---

## (3) What is next — with acceptance criteria

**(a) #649 — `differential_replay.rs` (measured 541 lines).** Its
`differential_replay_helpers/`
already exists, so the destination is not in question, and it is now worth more
than before: the file is on a blocking CI path. **Acceptance:** under 500,
split along the seams #641 and #646 will each edit so those two do not collide
in one file, committed as a behaviour-preserving move with the test name set
diffed against a MEASURED baseline.

**(b) #641 — widen the token comparison to `record` and `block_file`**, the two
targets carrying decrypted user content. Higher value now that the comparison
runs in CI. Each needs its own Rust taxonomy and typed Python exceptions;
scope it to those two and keep `TOKEN_COMPARED_TARGETS` partitioning `TARGETS`.

**(c) #612 — `manifest_uniqueness_kat.rs` (measured 848 lines).** Reopened
once already. `80c3c488` is the worked example. **Acceptance:** under 500,
sharing `Case`/`Verdict`/surgery helpers through a
`manifest_uniqueness_kat_helpers/`. The convention is
`<test-name>_helpers/` — there is no directory called `_helpers/` in this
tree, and naming the convention rather than a non-existent path is what an
acceptance criterion has to do (#656 review).

**(d) #655 — the fuzz-corpus replay trap, filed this slice.** The documented
local command is unusable on a fuzzed checkout and fails as a hang.
**Acceptance:** either a bound on how many runtime-corpus inputs replay, or an
opt-out, or progress output — any of the three turns a three-hour silent hang
into something a developer can act on. Decide deliberately; sampling a corpus
weakens a decoder-agreement check and that tradeoff belongs in the issue.

**(e) #646** — narrowing the tolerance needs §4.2 to settle two of the four
groups first, so it is a spec slice as much as a code one.

**(f) #633, #642** unchanged from the last baton.

**(g) #623 / #624 / #625 / #626 / #628 / #629 / #630 / #635 / #640 / #643 /
#648 / #653 / #654 stay open and untouched.**

### Issues this slice closes — verify against the code, not this document

**#647** and **#651.** Per the `(#N)`-not-`Closes #N` convention they stay open
until a human closes them. Checkable in five commands:

```bash
grep -c "differential-replay" .github/workflows/test.yml          # 5 (the step + its comment)
grep -c "Gate" scripts/mutation_harness/report.py                 # 1 (the column)
grep -c '"gate": r.spec.gate' scripts/mutation_harness/report.py  # 1
grep -c "GREEN UNDER THE TOLERANCE" CLAUDE.md                     # 1 (the correction)
grep -c "GREEN \*\*under this gate\*\*" ROADMAP.md                  # 1 (the correction)
```

**The last two check for the CORRECTION, not for the absence of the old
phrase, and the reason is worth keeping.** The obvious check —
`grep -c "nothing catches it and nothing should"` expecting 0 — does not
work in either file and fails DIFFERENTLY in each, which is how it would
have been believed. ROADMAP returns **2**, because both corrections quote
the sentence they are correcting. CLAUDE.md returns **0**, but only because
its correction capitalises the first word, so a case-sensitive grep misses
it by luck rather than by fact. A check that returns the expected answer for
the wrong reason is worse than no check; this was caught by running the
block rather than by reading it.

---

## (4) Open decisions and risks

### The finding that generalises furthest: a result is a property of its instrument

#651 is not a documentation slip. The measurement was correct, the write-up
dropped the one fact that scoped it, and **no reader of the evidence could tell**
— the pasted table named no gate. Generalise it: when recording a measurement,
ask what varies between runs that the record does not carry. Here it was the
gate; the same question applied to a filtered `cargo test` gave #587's
`--lib`/`--test` trap, and applied to a denominator gave #644's census.

### The residual this slice deliberately leaves open

**Nothing pins that the CI step stays wired.** Deleting those lines from
`test.yml` reds no test, no guard, and no self-test — the same shape as a
dropped registry entry before #644's `execution_census`, one layer up in the
build. The honest fix is a workflow-parsing guard, which is a slice rather than
a footnote, so it is **filed as #657** and not merely recorded here: this
document's own §(0) says the symlink gives no signal when it is stale, and a
residual that lives only in a handoff is how the #647 gap survived three
slices. The #656 review made that call; the first version of this section said
"no issue filed", which is against the repo's standing fix-or-file rule.

**What IS pinned, since the same review:** the step cannot run the wrong thing.
`required-features` binds `--test differential_replay` to its feature, so the
flag and the target can no longer drift apart silently — measured at exit 0
with `running 0 tests` before, exit 101 after.

### A measurement trap this session hit

`uv run scripts/mutate.py spec.toml | tail -40` reported `EXIT=0` while the
harness exited **1** — `$?` after a pipe is `tail`'s status. That is already in
memory for `cargo test | grep` and it is the same trap. Capture to a file and
read `$?` from the unpiped command.

### Standing risks this slice does not remove

- **The harness is still not in CI**, so nothing stops a future slice
  hand-rolling one. Adoption is a convention enforced by review.
- **Five of the six PEP 723 deps remain unbounded**, and `ed25519_verify` still
  has the "no exception means success" shape whose failure direction is
  fail-**open** (#544 / #550). #647 does not help: `--diff-replay` verifies no
  signature.
- **The `unknown`-subtree residual is untouched.**
- **`card.rs` (1264), `manifest_uniqueness_kat.rs` (848), `canonical/value.rs`
  (1082), `manifest/encode/tests.rs` (620), `sync/state.rs` (570),
  `differential_replay.rs` (541)** are all past the 500-line guideline —
  #625 / #612 / #603 / #630 / #626 / #649.

---

## (5) How to resume — the exact commands

```bash
# FIRST, and BEFORE reading this file — it fired in three of the four sessions
# before this one:
git fetch origin && git log --oneline main..origin/main

cd /Users/hherb/src/secretary/.worktrees/diff-replay-ci
pwd && git branch --show-current && git worktree list

# --- the gate this slice added, i.e. the exact CI step ---
cargo test --release --locked -p secretary-core \
  --features differential-replay --test differential_replay   # 4 passed, 11-24s

# DO NOT run ANY --features differential-replay form on a checkout that has
# fuzzed — the line above included. `corpus_dirs` pushes core/fuzz/corpus/
# unconditionally, so the trap belongs to the TEST, not to the scope flag:
# the narrow command replays those 74,924 files exactly as `--workspace`
# does, takes hours, and presents as a HANG. That is #655. Move the
# directory aside first. A fresh `git worktree` has no corpus/ and
# reproduces the CI shape for free.

# --- prove the CI gate is not vacuous, end to end ---
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

# --- prove the step cannot run the wrong thing (#656 review) ---
# Without its feature the target is refused, not run empty. Before the
# `required-features` entry in core/Cargo.toml this was exit 0 + "running 0
# tests", so dropping --features from test.yml would have been invisible.
cargo test --release --locked -p secretary-core --test differential_replay
echo "expect 101, and 'requires the features: differential-replay'"

# NOTE: read the exit code from the UNPIPED command. `... | tail -40` then
# `echo $?` reports tail's status, which cost a cycle this session.

# --- re-measure #651 rather than trusting this document ---
cat > "$SCRATCH/m8.toml" <<'EOF'
[[mutation]]
id = "M8-recheck"
lang = "python"
path = "core/tests/python/conformance_lib/codec/manifest_decode.py"
old = 'token = "array_sort_order"'
new = 'token = "rule2_indefinite_length"'
gate = "uv run core/tests/python/conformance.py"
expect = "green"
note = "handoff 2026-09-10 M8: recorded as GREEN by design"
probe = { module = "conformance_lib.codec.manifest_decode", expr = "ArraySortOrderViolation.token", equals = "rule2_indefinite_length", syspath = "core/tests/python" }
EOF
uv run scripts/mutate.py "$SCRATCH/m8.toml"   # UNEXPECTED_RED, exit 1 — Section RTV check 4

# --- the rest of the gate set ---
cargo test --release --locked --workspace
cargo clippy --release --locked --workspace --tests -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
uv run scripts/mutate.py --self-test                                 # 20/20
uv run --with pytest python3 -m pytest scripts/mutation_harness -q   # 249 passed
uv run core/tests/python/conformance.py                              # 29/29, 0 FAIL
actionlint .github/workflows/test.yml

# NOTE the pytest module form. `uv run --with pytest pytest` intermittently
# HANGS on this machine.

# --- six hygiene guards, --self-test FIRST, as LITERAL commands ---
# (zsh does not word-split an unquoted variable; a `for g in "bash x.sh"` loop
#  reports FAIL on all four bash guards.)
bash ffi/scripts/check-lean-binding.sh --self-test         && bash ffi/scripts/check-lean-binding.sh
bash ios/scripts/check-public-log-hygiene.sh --self-test   && bash ios/scripts/check-public-log-hygiene.sh
bash android/scripts/check-log-hygiene.sh --self-test      && bash android/scripts/check-log-hygiene.sh
bash scripts/check-secret-slot-hygiene.sh --self-test      && bash scripts/check-secret-slot-hygiene.sh
uv run scripts/check-error-payload-hygiene.py --self-test  && uv run scripts/check-error-payload-hygiene.py
uv run scripts/check-test-support-placement.py --self-test && uv run scripts/check-test-support-placement.py

# --- branch scope: workflow + scripts + docs ONLY ---
git diff origin/main...HEAD --name-only | grep -E "^(core|ffi|desktop|ios|android|cli|browser)/" || echo "clean"
```

---

## (6) Where this document lives

`NEXT_SESSION.md` at the repo root is a **symlink**, retargeted this session to
`docs/handoffs/2026-09-12-differential-replay-ci-shipped.md`. This file is the
single authored baton — do not create a second copy at the root, and do not
sync it to `main` during a pause window (that produces an add/add conflict).
