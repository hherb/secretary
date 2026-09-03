# NEXT_SESSION.md — a deterministic missing-required-key rejection (#597)

Branch `feature/deterministic-required-key`, worktree
`.worktrees/deterministic-required-key`, base `a3de38dd` (`main`, i.e. immediately
after PR #601 merged).

This slice is **(a)** from the previous baton's queue, taken as written. It is
**Python-only**: zero Rust, zero `core/tests/data/`, zero `core/fuzz/seeds/`, zero
normative `docs/`. **No issue was filed this session** — nothing was found that is
not closed here or already tracked.

**A starting-state note that cost a cycle and will cost the next one too.** The
baton this session opened was the **#594** handoff, and it named #597 as slice (a).
That was correct, but the tree had moved: PR #601 merged while that document sat at
`NEXT_SESSION.md`, so local `main` was two commits behind and the authoritative
baton was already the #601 one. `git fetch origin` before reading the baton is the
whole fix. This is the **third consecutive session** to hit it.

---

## (1) What shipped

### Commits

| SHA | What |
|---|---|
| `8241a6fc` | the slice: helper, seven call sites, probe, Section DET, registry row |
| `66878c33` | CLAUDE.md + ROADMAP (the package layout doc rode in `8241a6fc`) |
| `75ba09a9` | review round: Section DET's structural half had **three** demonstrated blind spots |
| *(this)* | the baton — a commit cannot cite its own SHA, so this row stays symbolic |

### The defect, measured before the fix

`core/fuzz/seeds/contact_card/pre_sig.cbor` omits **both** `self_sig_ed` and
`self_sig_pq`. On `main`, eight consecutive `--diff-replay` runs under
`PYTHONHASHSEED` 0..7 named `self_sig_pq` four times and `self_sig_ed` four times.
A `set`/`frozenset` of strings iterates in hash order and CPython salts string
hashing once per **process**, so the decoder reported whichever required key it
reached first.

The blast radius was smaller than the issue's title suggests and larger than its
"at minimum `py_decode_contact_card`" scope line: **three** live sites, found by
reading rather than by assuming.

| site | before | after |
|---|---|---|
| `codec/card.py` (`py_decode_contact_card`) | `for f in REQUIRED_CARD_FIELDS:` | helper |
| `codec/record.py` (`_validate_record_field`) | `for k in REQUIRED_FIELD_KEYS:` | helper |
| `codec/trash_entry.py` (`py_decode_trash_entry`) | `for f in REQUIRED:` | helper |
| `codec/record.py` (`py_decode_record`) | already `sorted(...)` | helper |
| `codec/manifest_decode.py` (`py_decode_manifest`) | already `sorted(...)` | helper |
| `codec/manifest_schema.py` (`_decode_manifest_entry_map`) | already `sorted(...)` | helper |
| `codec/manifest_schema.py` (`_decode_strict_entry_map`) | already `sorted(...)` | helper |

All three of the unsorted ones were verified nondeterministic **by execution**
across four hash seeds before any code changed, not inferred from the shape.

**Nothing else in the package renders an unordered collection into a message.** An
AST sweep for `for` loops over set literals or bare names, plus a grep for
`set(`/`frozenset(`/`.join(`, found: `wire/card.py:52` already reports
`sorted(missing)` (the whole set, so it has no first-key choice to make);
`merge/records.py:165,231,297` and `merge/clocks.py` are all `sorted(...)` already,
and one apparent set-difference at `clocks.py:39` is a `list + list` concat;
`sections/manifest_canonicality_kat.py:109,135` and `sections/conflict.py:221` are
comparisons whose failure text is already sorted.

### What landed

- **`codec/required_keys.py`** (54 lines) — `first_missing_key_in_sorted_order`,
  returning the lexicographically first absent key or `None`. Callers keep their
  own exception type and message, because they deliberately differ (`KeyError` for
  the record/card/trash decoders, `ValueError` for the manifest ones) and unifying
  that would change observable rejection behaviour rather than determinism.
- **All seven sites route through it**, including the four that already sorted.
  That is the point rather than churn: **four sorted and three did not**, which is
  what a hand-copied rule looks like after a while. The rule now lives in one
  NAME, the way `_check_sorted_and_distinct` (#594) put both of its rules in one.
- **`required_key_probe.py`** (248 lines) — a spawnable module holding one `Case`
  per required-key site, each declaring two or more deliberately-absent keys, and
  decoding **twice**: once omitting all of them, once with only `missing[0]`
  restored.
- **Section DET** (`sections/required_key_determinism.py`, 285 lines) — one
  registry row; REG goes 24 → 25 drivers.

### The review round, and why check 3 needed it

Checks 1 and 2 below were sound as first written. **Every one of the review's
three important findings was in check 3**, the structural half — the half whose
whole job is stopping a NEW site from reintroducing the defect — and each one
was demonstrated by planting the verbatim #597 shape in a tree and watching the
section report GREEN. They are recorded here because the pattern is more
instructive than any of them individually: **the checks that assert about the
code under test were right; the check that asserts about the SHAPE OF THE TREE
was wrong three ways, and all three were invisible to a green run.**

| # | The blind spot | Measured |
|---|---|---|
| 1 | `_codec_modules` used `glob`, not `rglob` — a `codec/` **subpackage** was invisible to both structural checks | `codec/sub/thing.py` with `for k in SUB_REQUIRED_KEYS:` scanned GREEN, under a PASS line counting 13 modules against a 14-module tree |
| 2 | the census was **count parity**, not a mapping | an 8th call site no case exercises, balanced by an 8th case duplicating an existing one, scanned GREEN under `PASS 8 required-key call sites under codec/, one case each` — a line literally false in that state |
| 3 | the name matchers were **case-sensitive** | a decoder written `required_keys = {...}` / `for required in required_keys:` scanned GREEN — and `required_keys` is exactly what `manifest_schema.py:155` and `:261` bind, so the missed spelling is the one 2 of the 7 live sites use |

Finding 1 is not hypothetical in this repo: CLAUDE.md's own convention splits a
module into a directory module past 500 lines, and `codec/record.py` is already
355. Finding 2 is this repo's signature overclaim shape — a PASS line asserting
a mapping that the code only counted. All three are fixed in `75ba09a9`; call
sites are now discovered through `ast`, keyed `codec/<path>::<function>` by
enclosing `def`, and compared as **sets in both directions** (an uncovered site
names itself; a case that has drifted off its check names itself; a duplicate
`Case.site` is its own issue, because it would hide an uncovered site behind a
comparison that still balances). All three probes now red, each naming the exact
site, and the original six mutations still red.

Two prose corrections rode along, both in the same direction: the probe's "one
case per required-key presence check **in the verifier** — seven" was one short
(there are eight; the eighth, `wire/card.py`, is deliberately outside the
helper), and CLAUDE.md's paragraph named only the *location* limit and neither
the name-shape limit nor findings 1 and 2.

### The three things Section DET pins, and why it needs all three

1. **Seed agreement.** The probe is spawned once per seed in `_HASH_SEEDS` (eight,
   fixed rather than `random`, so a regression is a deterministic red) and every
   run's stdout must be byte-identical. Subprocesses are not incidental: a
   process's hash salt is fixed at interpreter start and cannot be varied from
   inside one, which is why #597's own reproduction is a shell loop.
2. **The documented choice, with an ambiguity control.** Determinism alone is
   satisfied by reporting a constant, so each case also asserts the rejection names
   the lex-first absent key **and names no other absent key**. The control against
   a vacuous fixture is the second decode: restoring `missing[0]` must move the
   rejection onto `missing[1]`. **That makes the ambiguity a property of the
   DECODER, not of the case table** — a `len(missing) >= 2` assertion alone is
   satisfied by a wrong table, which M4 below proves.
3. **Structure, both directions.** Every `first_missing_key_in_sorted_order` call
   site under `codec/` must be matched to its own case **by enclosing function**
   (an uncovered site, a drifted case, and a duplicated `Case.site` are each
   their own issue), and no `codec/` `for` loop may iterate a required-key set
   directly. Without check 3, checks 1 and 2 are a snapshot of seven inputs.
   See "The review round" above for the three ways this check was wrong first.

### Non-vacuity, by execution

Six mutations. **Every restore verified by sha256**, never by `git diff` — the
three new files are untracked, which makes `git diff` vacuous for them (the trap
the #593 baton recorded). The mutation harness **asserts the substitution applied**
(`count(old) == 1`) before running anything, which is the other half of that trap:
a patch that fails to apply looks exactly like a mutation nothing catches.

| # | Mutation | Result |
|---|---|---|
| M1 | `sorted(required)` → `required` in the helper | seed agreement reds (8 distinct outputs) **and** every ambiguous case's lex-first check reds |
| M2 | one site (`card.py`) restored to the pre-fix raw loop | **all four** checks red: seed agreement, that case's lex-first, the census (6 ≠ 7), and the raw-iteration scan naming `codec/card.py:59` |
| M3 | a case declares only ONE absent key | the table-hygiene check reds |
| M4 | a case declares an absent key that is **not** actually required (`fingerprint`, an `Option` on `TrashEntry`) | the **restored** decode reds — the control catching a wrong table |
| M5 | helper deterministic but picks the LAST absent key | seed agreement stays **silent**; every lex-first check reds |
| M6 | the `codec/` glob points at a directory that does not exist | the empty-scan check reds |

**M5 is the one that matters most**, and M6 second. M5 proves check 2 is
independent of check 1 rather than a restatement of it. M6 closes the fail-open
hazard this repo keeps re-finding: a glob matching nothing would let both
structural checks report "no violations" having read no source at all.

The review round added four more — three reproducing its own findings against
the fixed section, one exercising a direction that did not exist before it:

| # | Probe | Result |
|---|---|---|
| R1 | the #597 shape in a `codec/` **subpackage** | reds, naming `codec/sub/thing.py:5 (SUB_REQUIRED_KEYS)` |
| R2 | an 8th call site no case covers, balanced by a duplicate 8th case | **two** issues: the duplicate `Case.site`, and the uncovered site by name |
| R3 | the #597 shape under the lowercase name `required_keys` | reds, naming `codec/trash_entry.py:155 (required_keys)` |
| R4 | a `Case.site` renamed so it matches no call site | **two** issues: the uncovered real site, and the drifted case |

All six original mutations still red after the fix, every restore sha256-
verified. M2 now reds with a better message than the bare count mismatch it used
to produce: it names the drifted case as well as the raw iteration.

### The measured result

- **`conformance.py` PASS**, exit 0, **25/25 sections**, REG reporting
  `25 drivers discovered, 25 registered`. Section DET's own cost is **0.27 s** for
  its eight subprocesses.
- **`--diff-replay` verdicts unchanged, measured across the WHOLE committed
  corpus** rather than on the one input the issue names: for all **38** seed files,
  `status` / `error_class` / exit code are identical to `main` (run under a pinned
  `PYTHONHASHSEED=0` on both sides, from a throwaway detached `main` worktree), and
  exactly **one** `detail` string moved — `contact_card/pre_sig.cbor`,
  `'self_sig_pq'` → `'self_sig_ed'`. That is #597's acceptance criterion, executed.
- **`cargo test --release --workspace`: 99 binaries, 2057 passed, 0 failed,
  21 ignored.** **This is `main`'s own number**, and it is not the previous baton's:
  that recorded **2038** for a tree whose Rust is byte-identical to this one
  (`git diff main --name-only` returns zero non-`.py` paths, and
  `git diff c6064f30 origin/main` is empty). One of the two measurements was taken
  from an incomplete run; this one was tallied twice, by `awk` and by an
  independent Python parse, off a file whose `CARGO EXIT: 0` was echoed
  immediately after the run rather than read through a filter.
- `cargo fmt --all --check`, `cargo build --release --workspace`,
  `cargo clippy --release --workspace --tests -- -D warnings` all exit 0.
- `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace` exit 0, forced
  non-cached (`touch core/src/lib.rs` first): **59 s over 402 lines** of output,
  documenting every crate — not the ~5 s no-op the #575 trap describes.
- **Both gates no CI job covers**: `cargo test --release --workspace --features
  differential-replay` exit 0 (2058 — the +1 is the replay test itself), with
  `[manifest_body] replayed 27 input(s)` and every target replayed;
  `core/fuzz` checks clean under the pinned nightly.
- **All six hygiene guards pass, each `--self-test` first**, and `git status` after
  them shows no probe residue (#516).
- **`spec_test_name_freshness.py` = 90**, the baseline, and its output is
  **byte-identical to `main`'s** — diffed in full against the detached `main`
  worktree, not inferred from the count.
- `pyflakes` clean over the entrypoint and the whole package.
- **Format / fixture invariants — all four EMPTY:** `core/tests/data/`,
  `core/fuzz/seeds/`, the UDL, and
  `git diff main...HEAD --stat -- docs/ ':!docs/handoffs/' ':!docs/manual/'`.
  Untracked files were checked too (`git status --untracked-files=all` over those
  trees), since a `git diff` cannot see a new file.

---

## (2) What this slice does **not** claim

- **The structural half of Section DET scans `codec/` only, and matches by NAME
  SHAPE.** It recurses now (finding 1), so a future directory-module split stays
  covered — but a required-key check placed in `wire/` or `merge/` is still
  invisible to it, as is one iterating a required set bound to a name that
  contains neither `REQUIRED` nor a `_KEYS` / `_FIELDS` suffix. Matching is
  case-INsensitive as of `75ba09a9`, which is what makes ordinary lowercase
  Python naming visible; it was not before. It reads TEXT through `ast`, not
  resolved identities. This is a narrower guarantee than "no decoder can
  reintroduce the bug"; it is "no decoder under `codec/` can, under the
  spellings the seven use".
- **`wire/card.py` deliberately does not use the helper.** It reports the whole
  missing set, already `sorted(...)`, so it has no first-key choice to make.
  Routing it through a helper that returns ONE key would be a behaviour change,
  not a determinism fix.
- **The seed set is eight fixed values, not a proof over all seeds.** Eight was
  chosen because the pre-fix probe produced **seven distinct outputs** across
  exactly those eight, so the check is not resting on a lucky pair. It remains a
  sample.
- **Only the `detail` TEXT was ever at risk, and that is unchanged by this slice.**
  The verdict was stable before and after; `core/tests/differential_replay.rs`
  scores reject-vs-reject as agreement without comparing `detail`. This closes a
  reproducibility trap, not a correctness bug. Do not record it as one.
- **`conformance.py` gained no new spec claim.** No normative document changed, so
  `README.md` was deliberately left alone: its description of what the verifier
  proves about `docs/` is still exactly true.

---

## (3) What is next — with acceptance criteria

**(a) #600 — `encode_manifest` can emit array-element repeats its own decoder
rejects.** Inherited as (b) from the last baton and unchanged: #586's map-key twin
is closed, so the asymmetry is now visible, and §4.2's writer half makes the
encoder formally non-conformant with its own frozen spec. **Acceptance:** the
encoder rejects a repeat in each of the four constrained arrays (`recipients`
explicitly excepted); `generate_manifest_uniqueness_kat` starts failing at its
`encode_manifest` call — the tripwire its module doc describes — so the generator
must move to building bodies by ciborium surgery the way
`array_sort_disciplines_are_enforced_and_not_vacuous` already does. **Do not
regenerate the corpus to make it pass.**

**(b) #604 — `manifest_canonicality_kat.json` has no `expect_cause` column.** New
since the last queue was written, and the natural follow-on to #601: #590's cause
vocabulary (`ArraySortOrder` / `IndefiniteLength` / `NonShortestForm` /
`Unclassified`) is pinned on the Rust side only, so a clean-room reader has nothing
to agree with. **Acceptance:** the corpus carries a cause per rejecting row, the
6/3 split stays asserted by count, and both languages replay it.

**(c) #589 — the 21 duplicate-key guards are hand-copied, not a type invariant.**
**Acceptance:** expressed once; all 21 sites route through it; deleting the single
implementation reds more than one test. (This slice is the same shape one directory
over, and its Section DET census is a worked example of the structural half.)

**(d) #596 — a `manifest_body` cargo-fuzz target, the natural eighth.**
**Acceptance:** `core/fuzz/fuzz_targets/manifest_body.rs` exists,
`cargo fuzz run manifest_body` starts from the committed seeds, and `CLAUDE.md`'s
"Seven targets" line becomes eight.

**(e) #602 / #603 stay open and untouched** — `identity::card` and `sync::state`
are outside #586's choke point, and `canonical/value.rs` is past the split
threshold. **(f) #587 likewise.**

### Issues this slice closes — verify against the code, not this document

**#597.** Per this repo's `(#N)`-not-`Closes #N` convention it stays open until a
human closes it. Nothing here closes **#600, #604, #589, #596, #602, #603, #587**.

---

## (4) Open decisions and risks

### Rulings taken (both put to the user with options and confirmed before implementation)

1. **One shared pure helper, all seven sites routed through it** — rather than
   three one-word `sorted(...)` insertions at the broken sites. The weaker option
   satisfies #597's acceptance criteria literally and leaves seven loops that each
   independently have to remember the rule. Cost: five files touched instead of
   three, including code that was not buggy.
2. **A new Section DET spawning subprocesses under N seeds** — rather than an
   in-process permutation test on the helper alone. The weaker option is hermetic
   and fast but pins only the helper's own logic: a future decoder that bypasses
   the helper is invisible to it, and it does not reproduce the issue's own
   two-seed repro. Cost: subprocess spawning inside the verifier (measured at
   0.27 s) and one more registry row.

### What the review round is evidence for

**The checks that assert about the code under test were right; the check that
asserts about the SHAPE OF THE TREE was wrong three ways, and every one was
invisible to a green run.** Checks 1 and 2 reason about decoder behaviour and
were sound as first written. Check 3 reasons about the file tree — which
directories exist, which names are used, how many call sites there are — and
each of its three assumptions (`codec/` is flat; a count is a mapping;
required-key sets are spelled in upper case) was false, and false silently. When
a guard's subject is the tree rather than the code, plant the thing it is meant
to catch **in the tree** and watch it fire: a mutation of the code under test
does not exercise that half at all. Six mutations had been run before the review
and none of them touched it.

### A verification trap worth carrying forward

**A `cmd && grep` chain reports GREP's exit code.** The differential-replay gate
was reported here as FAILED by the background task runner, because the command
ended with `grep -E "replayed [0-9]+ input"` over output that had no such line —
test stdout is captured without `--nocapture`. `cargo` had exited **0**. This is
the same root cause the last baton recorded twice (`cargo test | grep`, and ANSI
colour defeating an anchored `^error` filter): **judge a command by its exit
status, echoed immediately, never by a filter's output.** The correct incantation
for that expectation is
`cargo test --release -p secretary-core --features differential-replay --test differential_replay -- --nocapture`.

### Standing risks this slice does not remove

- **Five of the six PEP 723 deps remain unbounded** (`cryptography`, `pynacl`,
  `argon2-cffi`, `blake3`, `cbor2`), and `ed25519_verify` still has the "no
  exception means success" shape whose failure direction would be fail-**open**
  (#544 / #550). Section DET adds no dependency, but it does add a **subprocess
  spawn of `sys.executable`** to the CI gate — a new way for that job to fail if a
  future runner sandboxes process creation.
- **`encode_manifest` remains a non-conformant writer** for §4.2's
  repeated-array-value rules (#600) and validates no v1 sentinel (#587).

### Housekeeping

`.worktrees/` holds `d5-macos-mutation`, `d5-macos-trash-settings`,
`noncanonical-cause` (merged as #601 — removable) and this slice's. The scratchpad
also holds a detached `main` worktree used for the baseline diffs; remove it with
`git worktree remove --force <path>` if `git worktree list` still shows it.

---

## (5) How to resume — the exact commands

```bash
git fetch origin                                        # FIRST. See the note in §(1).
cd /Users/hherb/src/secretary/.worktrees/deterministic-required-key
pwd && git branch --show-current && git worktree list   # expect feature/deterministic-required-key

# --- the gate this slice is actually about ---
uv run core/tests/python/conformance.py                 # expect exit 0, "PASS", 25/25 sections
uv run --with pyflakes python -m pyflakes core/tests/python/conformance.py \
                                          core/tests/python/conformance_lib

# --- #597's own reproduction, now an assertion ---
for s in 0 1 2 3 4 5 6 7; do PYTHONHASHSEED=$s uv run core/tests/python/conformance.py \
  --diff-replay contact_card core/fuzz/seeds/contact_card/pre_sig.cbor; done | sort -u | wc -l
# expect 1 (it was 2 on main)

# --- the cross-language contract (no CI job covers this one) ---
cargo test --release --workspace --features differential-replay
cargo check --release --features differential-replay --tests -p secretary-core
# For the per-target counts you must pass --nocapture, or the line is CAPTURED and
# a grep for it reports failure while cargo exited 0 (see §(4)):
cargo test --release -p secretary-core --features differential-replay \
  --test differential_replay -- --nocapture      # expect [manifest_body] replayed 27 input(s)

# --- the rest of the gate set ---
cargo fmt --all --check
cargo build --release --workspace                       # separate from the test run ON PURPOSE
# Redirect, then echo $? — a `| grep` pipeline reports GREP's exit code:
cargo test --release --workspace > /tmp/suite.txt 2>&1; echo "CARGO EXIT: $?"
grep -E "^test result" /tmp/suite.txt | \
  awk '{p+=$4; f+=$6; i+=$8} END {print NR, p, f, i}'   # expect 99 2057 0 21
cargo clippy --release --workspace --tests -- -D warnings
touch core/src/lib.rs   # rustdoc caches; a ~5s run did nothing (this one takes ~1 min)
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
cd core/fuzz && PATH="$HOME/.rustup/toolchains/nightly-2026-04-29-aarch64-apple-darwin/bin:$PATH" cargo check
cd -

# --- six hygiene guards, --self-test FIRST every time ---
# (run each as a literal command; zsh does not word-split an unquoted variable,
#  so a `for g in "bash x.sh"; do $g; done` loop reports FAIL on all of them)
bash ffi/scripts/check-lean-binding.sh --self-test         && bash ffi/scripts/check-lean-binding.sh
bash ios/scripts/check-public-log-hygiene.sh --self-test   && bash ios/scripts/check-public-log-hygiene.sh
bash android/scripts/check-log-hygiene.sh --self-test      && bash android/scripts/check-log-hygiene.sh
bash scripts/check-secret-slot-hygiene.sh --self-test      && bash scripts/check-secret-slot-hygiene.sh
uv run scripts/check-error-payload-hygiene.py --self-test  && uv run scripts/check-error-payload-hygiene.py
uv run scripts/check-test-support-placement.py --self-test && uv run scripts/check-test-support-placement.py
git status --short                                      # #516: no probe residue

# --- citation freshness: 90, and byte-identical to main (no normative docs/ edit here) ---
uv run core/tests/python/spec_test_name_freshness.py

# --- format / fixture invariants: all FOUR must be EMPTY ---
git diff main...HEAD --stat -- core/tests/data/
git diff main...HEAD --stat -- core/fuzz/seeds/
git diff main...HEAD -- ffi/secretary-ffi-uniffi/src/secretary.udl
# NORMATIVE docs only. A git pathspec glob CROSSES `/`, so `docs/*.md` would also
# match docs/manual/**; exclude the two non-normative trees by name.
git diff main...HEAD --stat -- docs/ ':!docs/handoffs/' ':!docs/manual/'
# A git diff cannot see an untracked file, so check for new ones too:
git status --short --untracked-files=all -- core/tests/data/ core/fuzz/seeds/ docs/
```

Re-proving Section DET is not vacuous (M1, the cheapest of the six):

```bash
# Drop the sort in the helper; every seed-agreement and lex-first check must red.
# Restore by sha256 — `git diff` is VACUOUS for these three files while untracked.
shasum -a 256 core/tests/python/conformance_lib/codec/required_keys.py
```

---

## (6) Where this document lives

`NEXT_SESSION.md` at the repo root is a **symlink**, retargeted this session to
`docs/handoffs/2026-09-03-deterministic-required-key-shipped.md`. This file is the
single authored baton — do not create a second copy at the root, and do not sync it
to `main` during a pause window (that produces an add/add conflict).
