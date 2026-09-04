# NEXT_SESSION.md — the manifest encoder stops emitting bodies its own decoder rejects (#600)

Branch `feature/encoder-uniqueness`, worktree `.worktrees/encoder-uniqueness`,
base `6d4c1cb3` (`main`, i.e. immediately after PR #605 merged).

This slice is **(a)** from the previous baton's queue, taken as written. It is
Rust **and** Python: the same defect existed in both encoders and both are
closed here. **Zero `core/tests/data/`, zero `core/fuzz/seeds/`, zero normative
`docs/`** — all three measured, and the first of those is the slice's central
piece of evidence rather than a housekeeping note.

**No issue was filed this session.** Nothing was found that is not closed here
or already tracked.

---

## (0) The starting-state trap, hit for the FOURTH consecutive session

The previous baton's §(1) opened with a note that its own session had opened a
stale handoff, and called it "the third consecutive session to hit it". This
session made it four, and the failure was slightly worse: local `main` was
**two** commits behind (`a3de38dd`, so PRs #606 and #605 were both invisible),
`NEXT_SESSION.md` pointed at the **#601** handoff, and the queue in that
document listed **#597 as slice (a)** — which had already shipped as PR #605.
Roughly fifteen minutes went into re-deriving #597's live sites before
`git worktree add ... origin/main` printed `6d4c1cb3 Make a missing-required-key
rejection deterministic (#597) (#605)` and gave it away.

**`git fetch origin && git log --oneline main..origin/main` BEFORE reading
`NEXT_SESSION.md`.** Not after. The baton is a symlink into `docs/handoffs/`,
so a stale checkout resolves it silently to an old file with no marker of any
kind. Local `main` was fast-forwarded to `6d4c1cb3` this session, which does not
prevent the next occurrence.

---

## (1) What shipped

### Commits

| SHA | What |
|---|---|
| *(the slice)* | `uniqueness.rs`, three `ManifestError` variants, decoder re-routing, surgery helper, KAT migration, the Python twin, CLAUDE.md + ROADMAP |
| *(this)* | the baton — a commit cannot cite its own SHA, so this row stays symbolic |

### The defect

`docs/vault-format.md` §4.2 forbids a repeated value in four of the five sorted
manifest arrays, and since #594's spec uplift states it in **both** directions:

> Repeated values are forbidden in four of the five; writers MUST NOT emit
> them and readers MUST reject them

`decode_manifest` enforced all four (`DuplicateBlockUuid` /
`DuplicateTrashUuid` / `VectorClockDuplicateDevice`). **`encode_manifest`
enforced none.** `Manifest` is `pub` with `pub` array fields and is re-exported
at `secretary_core::vault`, so a caller handing it two `BlockEntry`s with the
same `block_uuid` got a well-formed, sorted, **signed** body this codebase's own
decoder refuses to open.

The clean-room `py_encode_manifest` had the identical gap. That is the shape
#594 had already had to repair once between the two *readers*.

Availability, not confidentiality — the manifest is owner-signed, so the
producer is a caller in this process (merge, repair and every block-CRUD path
build a `Manifest` in memory). But a format frozen for decades with a
clean-room mandate cannot ship an encoder that contradicts its own reader, and
#599 had just made the writer half normative, so the encoder was formally
non-conformant with `docs/`.

### What landed

- **`core/src/vault/manifest/uniqueness.rs`** — `has_repeat` (sort a copy, scan
  adjacent pairs) and `check_no_repeated_array_values`. **Both directions call
  it**: the decoder's three hand-copied scans in `decode/entries.rs` now route
  through `has_repeat`, and `check_no_repeated_array_values` is
  `encode_manifest`'s first statement. Seven copies of one sentence from a
  frozen spec is how two directions drift, which is what #600 *was*.
- **Three NEW `ManifestError` variants** — `EncodeDuplicateBlockUuid`,
  `EncodeDuplicateTrashUuid`, `EncodeVectorClockDuplicateDevice`.
- **`conformance_lib/codec/array_uniqueness.py`** — `first_repeated_value`,
  shared by `_check_sorted_and_distinct` (reader) and a new
  `check_no_repeated_array_values` in `manifest_encode.py` (writer).
- **`manifest/test_support/surgery.rs`** — `copy_entry_field` + `BodyArray`,
  with its own five tests. `test_support.rs` became `test_support/mod.rs` in
  the same stroke: it was 438 lines and the helper would have pushed it past
  the 500-line threshold.
- **The uniqueness KAT migrated**, exactly as #600's issue text prescribed.
- **Section MUQ gained the writer half** cross-language, and a `#600` ref in
  the registry row.

### Two rulings, both put to the user with options before implementation

1. **Three new variants, not a reuse of the decoder's three.** Follows #586's
   ruling from one slice earlier: "the bytes you gave me repeat a uuid" and
   "the value you asked me to encode repeats one" are different events, and
   collapsing them leaves a caller unable to tell a corrupt file from a
   malformed in-memory manifest. Cost: 3 arms on a non-`#[non_exhaustive]`
   public enum. `cargo build --release --workspace` confirms that costs
   nothing downstream today.
2. **One shared helper, both directions** — rather than an encoder-side scan
   beside three untouched decoder copies. Cost: the diff touches decoder code
   that was not buggy.

### The KAT migration, and why the fixture did not change

`generate_manifest_uniqueness_kat` built its four rejecting bodies by handing
`encode_manifest` a `Manifest` carrying the repeat. **The tripwire the file's
module doc described fired exactly as written** — `encode_case` panicked at its
`encode_manifest` call, in the generator *and* in the replay's
rebuild-and-compare, and it was the only failure in the whole workspace suite.

`Case` now carries two columns where it carried one:

- **`mutate: fn(&mut Manifest)`** — kept, and now drives a **writer-side
  assertion**: `encode_manifest(&mutated)`'s verdict must equal
  `expect_accept`, against a new `expect_encode_err` column. §4.2's two halves
  are now executable from one table.
- **`plant: fn(&mut Value)`** — the sole source of the fixture bytes, applied
  to the parsed all-distinct baseline.

**Every row's bytes are byte-identical to the ones #594 generated.** That is
asserted on every run (the pre-existing rebuild-and-compare) and confirmed
externally by `git diff main...HEAD --stat -- core/tests/data/` being empty. It
holds for a reason worth keeping: `ciborium`'s parse/re-encode is the identity
on a canonical body, and the §4.2 sorts are **stable**, so a mutated manifest
would have sorted into the same positions the baseline did.

The one thing this arrangement cannot cross-check is a `plant` that has drifted
from its `mutate` on a REJECT row — the encoder produces nothing to compare
against. The two ACCEPT rows carry that cross-check instead (surgery and
encoder must agree byte for byte), and mutation M6 proves it fires: the drifted
body was the **same length**, so a length-only check would have missed it.

### Non-vacuity, by execution — eleven mutations

Every patch asserted `s.count(old) == 1` **before** the run, and every restore
was verified by **sha256**, not by `git diff` — `uniqueness.rs`,
`surgery.rs` and `array_uniqueness.py` are untracked, so `git checkout` on them
is a silent no-op. That is not hypothetical: **M1's first restore attempt was
exactly that no-op**, caught only because the sha256 check failed.

| # | Mutation | Result |
|---|---|---|
| M1 | `has_repeat` → always `false` | **16 red** in the lib target — 4 encode, 3 **decode**, 8 unit, 1 surgery. Plus `manifest_uniqueness_kat_replays`, which these counts omit (#608 review: M1/M2/M3 are lib-target SUBTOTALS, the same filter trap this document diagnoses for M4 without applying it upward) |
| M2 | drop `check_no_repeated_array_values(manifest)?` from `encode_manifest` | **4 red** (the encode tests only — the unit tests still pass, correctly) |
| M3 | per-block walk scoped to `blocks[0]` | **2 red**, both the non-first-block tests |
| M4 | `recipients` "tidied up" into a fifth rule | **3 red** in the lib target, including the pre-existing decoder test, **plus the corpus row** — measured in a separate run, see below |
| M5 | drop the `sort_unstable` | **2 red** — the only two tests whose input order separates the repeat |
| M6 | a `plant` drifted from its `mutate` | **1 red**, by the ACCEPT cross-check, message naming the drift |
| M7 | `expect_encode_err` swapped for the decode variant | **1 red** |
| P1 | `first_repeated_value` → always `None` | MUQ red, **both halves** |
| P2 | drop the Python encoder call | MUQ red, **writer half only** |
| P3 | Python writer scoped to `blocks[0]` | MUQ red, **the summary case only** |
| P4b | `recipients` tidied into the Python writer | MUQ red, naming the exception |

**P4's first attempt passed, and that was a bad mutation rather than a
vacuous test** — it added `("recipients", "recipients")` to the *top-level*
array table, and `recipients` is per-block, so it scanned an empty list. The
tell was that the result contradicted the prediction. A mutation that does not
express its intent looks exactly like a test that does not catch it; P4b is the
one that expresses it.

### The measured result

- **`cargo test --release --workspace`: 99 binaries, 2081 passed, 0 failed, 21
  ignored.** Test **name set** diffed against a `main` baseline built this
  session in a throwaway detached worktree (`cargo test -- --list` on both):
  **22 added, 0 removed**, and the 22 are exactly the tests written here. A
  count alone cannot distinguish that from "22 added, 3 silently deleted".
- `cargo fmt --all --check`, `cargo build --release --workspace` (run
  separately from the test run on purpose), and
  `cargo clippy --release --workspace --tests -- -D warnings` all clean.
  Clippy caught one `needless_lifetimes` in the KAT's surgery helper; fixed.
- `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace` clean, forced
  non-cached with `touch core/src/lib.rs` first.
- **`conformance.py` PASS**, 25/25 sections, REG reporting `25 drivers
  discovered, 25 registered`. `pyflakes` clean over the entrypoint and package.
- **Both gates no CI job covers:** `cargo test --release --workspace --features
  differential-replay` clean (2082 passed), and `core/fuzz` checks under the
  pinned nightly. `manifest_body` still replays **27** inputs — unchanged, as
  it must be.
- **All six hygiene guards pass, each `--self-test` first.** No probe residue
  in `git status` afterwards.
- **`spec_test_name_freshness.py` = 90, and its output is byte-identical to
  `main`'s** — `diff`ed in full against the baseline worktree, not inferred
  from the count.
- **Format / fixture invariants — all four empty:** `core/tests/data/`,
  `core/fuzz/seeds/`, the UDL, and normative `docs/` (the pathspec is
  `-- docs/ ':!docs/handoffs/' ':!docs/manual/'`; a bare `-- docs/` always
  shows this baton, and `docs/*.md` would also match `docs/manual/**` because
  a git pathspec glob crosses `/`).

### README was deliberately not touched

Checked rather than assumed: `README.md`'s manifest-layer row already reads
"✅ Complete", and nothing in it asserts anything about encoder validation.
`ROADMAP.md` and `CLAUDE.md` both changed.

---

## (2) What this slice does **not** claim

- **`recipients` is still §4.2's exception, on both sides.** Four rules, not
  five. Three Rust tests, one Python writer case and the corpus row exist to
  red if someone folds it in, and M4/P4b prove all of them fire. Do not "tidy
  up" the asymmetry — it narrows a v1-frozen decoder.
- **The three new variants are a public API change.** Nothing outside
  `core/src` matches `ManifestError` exhaustively today — every bridge fold
  binds `VaultError::Manifest(_)` with a wildcard — but that is a property of
  the current fold shape, not a guarantee. `cargo build --release --workspace`
  is what confirms it, and it is green.
- **`encode_manifest` still validates no v1 sentinel** (#587), untouched.
- **The surgery helper is duplicated THREE times, deliberately.**
  `manifest/test_support/surgery.rs` (unit tests),
  `manifest_uniqueness_kat.rs`'s `generate` module, and
  `manifest_canonicality_kat.rs`'s pre-existing `reverse_array`. An
  integration test sees only `secretary_core`'s public API and cannot reach a
  `#[cfg(test)]` module; promoting test-only manifest surgery onto the shipped
  surface to spare thirty lines is the worse trade. TWO of the three say so
  (`test_support/surgery.rs` and `manifest_uniqueness_kat.rs`, each naming the
  other two); `manifest_canonicality_kat.rs`'s `reverse_array` carries no such
  note, so the copy least likely to be recognised as load-bearing is the one
  with no cross-reference. "Each copy says so" was false when written
  (#608 review).
- **The writer check costs a second pass over four short arrays on every
  manifest save AND on every vault OPEN.** §4.3 step 4 re-encodes the parsed
  manifest through `encode_manifest` itself (`decode/mod.rs:219`) — not through
  a lower-level helper, and deliberately so, since step 4's whole claim is that
  the bytes it compares against are the bytes a writer would emit. So the check
  runs on the every-open path too. It **cannot fire** there:
  `parse_manifest_map` has already rejected all four repeat shapes with the
  DECODE-side variants by then, which the three `rejects_duplicate_*` tests
  pin. The cost is negligible either way, but it is real and it is on a hotter
  path than "every save".
- **`manifest_to_canonical` stays infallible.** The check is a separate
  statement in `encode_manifest`, so that function's long "Infallible" doc
  contract is untouched.
- **#602 / #603 / #604 stay open and untouched.**

---

## (3) What is next — with acceptance criteria

**(a) #604 — `manifest_canonicality_kat.json` has no `expect_cause` column.**
Inherited as (b) and now the top of the queue. #590's cause vocabulary
(`ArraySortOrder` / `IndefiniteLength` / `NonShortestForm` / `Unclassified`) is
pinned on the Rust side only, so a clean-room reader has nothing to agree with —
and this slice just set the opposite precedent twice over (§4.2's writer half is
now asserted in both languages). **Acceptance:** the corpus carries a cause per
rejecting row (`null` for the three `rule4_float` rows, caught earlier by
`reject_floats_and_tags`), `assert_rejection_mechanism` reads the column instead
of matching on the label suffix, the 6/3 split stays asserted by count, and both
languages replay it. Note this one **does** touch `core/tests/data/`, unlike the
last three slices.

**(b) #589 — the 21 duplicate-key guards are hand-copied, not a type
invariant.** This slice is the same shape one directory over, and its
`has_repeat` is a worked example: one name, both directions, deleting it reds
both. **Acceptance:** expressed once; all 21 sites route through it; deleting
the single implementation reds more than one test.

**(c) #602 — `identity::card` and `sync::state` are outside #586's choke
point**, including the hybrid-signed `ContactCard::signed_bytes`. No live
exposure (all three build keys from fixed literals) but that is a property of
today's call sites, not of the encoder. **Acceptance:** those paths reject a
duplicate key too, or `card.rs`'s deliberately-permissive `encode_map` is
documented as a reviewed exception with the hostile-peer test fixtures that
need it named.

**(d) #596 — a `manifest_body` cargo-fuzz target, the natural eighth.** The
`--diff-replay` wiring exists and the seed corpus is 27 bodies. **Acceptance:**
`core/fuzz/fuzz_targets/manifest_body.rs` exists, `cargo fuzz run manifest_body`
starts from the committed seeds, and `CLAUDE.md`'s "Seven targets" line becomes
eight.

**(e) #603 (`canonical/value.rs` past the split threshold) and #587 stay open
and untouched.**

### Issues this slice closes — verify against the code, not this document

**#600.** Per this repo's `(#N)`-not-`Closes #N` convention it stays open until
a human closes it. Nothing here closes **#604, #589, #602, #603, #596, #587**.

---

## (4) Open decisions and risks

### A scope decision worth recording

**The Python encoder was fixed in the same slice**, though #600's issue text is
entirely about Rust. The reasoning: leaving `py_encode_manifest` non-conformant
would recreate, on the writer side, exactly the divergence #594 had just closed
on the reader side — and this repo's whole clean-room claim is that the two
implementations agree. It was measured behaviour-preserving for every existing
caller first: all SEVEN pre-#600 routes to `py_encode_manifest` (not four —
#608 review; see that function's docstring for the enumeration) run *after* the reader
has already rejected such a body, so the check is observably a no-op in the
existing suite. That is also why Section MUQ exercises it **directly** rather
than through a corpus row — a body the writer must refuse is, by construction,
a body the writer cannot produce for a fixture.

### A THIRD claim, corrected the same way, and the cargo trap under it

"Three Rust tests, one Python writer case and the corpus row exist to red if
someone folds `recipients` in, and M4/P4b prove all of them fire." The Rust and
Python halves were measured; **the corpus row was not**. M4 had been run as
`cargo test --release -p secretary-core --lib manifest:: --test
manifest_uniqueness_kat`, and the positional filter `manifest::` applies to
**every** target named — the corpus test is `manifest_uniqueness_kat_replays`,
which does not contain that substring, so it was silently filtered out. The run
reported 3 red and looked complete.

**A `cargo test` positional filter applies across all `--lib` / `--test`
targets, so a filter tuned to lib module paths can run ZERO integration tests
while exiting normally.** Re-run alone (`--test manifest_uniqueness_kat`, no
filter), the corpus row does red. The claim was right; the evidence for it did
not exist until it was re-measured.

### The review round: two claims in the first commit were FALSE

Both were found by re-reading the code against the prose after the commit was
pushed and PR #608 opened, and both are this repo's signature failure mode —
**documentation written from the plan rather than from the diff**. They are
recorded rather than quietly amended because the pattern is more instructive
than either one.

1. **"The decoder's three hand-copied scans now route through `has_repeat`" was
   not true.** It was the approved design, it was in the commit message, the
   PR body, `ROADMAP.md` and `CLAUDE.md` — and `decode/entries.rs` still had
   three verbatim `ids.sort(); ids.windows(2).any(...)` blocks. The encoder
   half had been built, the decoder half had been *described*. Fixed in the
   code (the design was right), and the fix is what makes M1 red **16** tests
   instead of 12 — the three decoder tests among them. That delta is the
   evidence the sharing is real; before it, "one helper, both directions" was
   a sentence with no execution behind it.
2. **"The check does not run on decode" was false**, and it was a claim about
   a hot path. §4.3 step 4 re-encodes through `encode_manifest`, so it does.
   Harmless — unreachable by ordering — but the disclosure was wrong in the
   direction that understates cost, and the ordering it depends on was
   undocumented. Now stated in `check_no_repeated_array_values`'s own doc,
   including what a reversal would look like.

**The habit that catches this class: grep for the thing the sentence claims,
in the file the sentence names, before the sentence ships.** Both were found
in under a minute that way. Neither was found by 2081 passing tests, by
clippy, or by writing the sentence carefully.

### Two verification traps worth carrying forward

- **`git checkout` is a SILENT NO-OP on an untracked file, so it is not a
  restore.** M1's mutation targeted `uniqueness.rs`, which is new in this
  branch and therefore untracked; `git checkout` printed nothing and changed
  nothing, and only the sha256 check revealed the tree was still mutated. The
  #601 baton recorded this same trap for `cause.rs`. **Restore by inverse
  patch, and verify by sha256** — every mutation here does.
- **A backgrounded compound command inherits the `cd` from its FIRST line.**
  `cd /Users/hherb/src/secretary && git worktree remove ...` followed on the
  next line by `cargo test --release --workspace` ran the whole suite **in the
  main repo, against `main`**, not in the worktree. Caught before drawing any
  conclusion from it, but a number from that run would have been indisplaceably
  wrong and looked completely ordinary. This is CLAUDE.md's "never run cargo
  from the main repo when the work is in a worktree" — the failure mode is not
  a bad push, it is a **plausible measurement of the wrong tree**.

### Standing risks this slice does not remove

- **Five of the six PEP 723 deps remain unbounded** (`cryptography`, `pynacl`,
  `argon2-cffi`, `blake3`, `cbor2`), and `ed25519_verify` still has the "no
  exception means success" shape whose failure direction would be fail-**open**
  (#544 / #550).
- **`encode_manifest` validates no v1 sentinel** (#587), so it can still emit a
  body its decoder rejects for a *different* reason. #600 closed the
  repeated-value class, not the general one.
- **`identity::card` and `sync::state` remain outside the duplicate-key choke
  point** (#602), including a hybrid-signed path.

### Housekeeping

**Done, not pending.** `.worktrees/deterministic-required-key` (merged as
PR #605) and the throwaway detached `main` worktree used for the baseline diffs
were both removed this session, and the stale `feature/deterministic-required-key`
branch deleted. `git worktree list` now shows only the repo, two
`.claude/worktrees/` checkouts this session did not create, and this slice's.

---

## (5) How to resume — the exact commands

```bash
# FIRST, before reading the baton — this has cost four consecutive sessions:
cd /Users/hherb/src/secretary && git fetch origin && git log --oneline main..origin/main

cd /Users/hherb/src/secretary/.worktrees/encoder-uniqueness
pwd && git branch --show-current && git worktree list   # expect feature/encoder-uniqueness

# --- the gates this slice is actually about ---
cargo test --release --workspace --lib manifest::       # uniqueness + encode + surgery
cargo test --release -p secretary-core --test manifest_uniqueness_kat

# --- the cross-language contract (no CI job covers this one) ---
cargo test --release --workspace --features differential-replay

# --- the rest of the gate set ---
cargo fmt --all --check
cargo build --release --workspace                       # separate from the test run ON PURPOSE
# Redirect, then echo $? — a `| grep` pipeline reports GREP's exit code:
cargo test --release --workspace > /tmp/suite.txt 2>&1; echo "CARGO EXIT: $?"
grep -E "^test result" /tmp/suite.txt | \
  awk '{p+=$4; f+=$6; i+=$8} END {print NR, p, f, i}'   # expect 99 2081 0 21
cargo clippy --release --workspace --tests -- -D warnings
touch core/src/lib.rs   # rustdoc caches; a ~5s run did nothing
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
cd core/fuzz && PATH="$HOME/.rustup/toolchains/nightly-2026-04-29-aarch64-apple-darwin/bin:$PATH" cargo check
cd -

# --- the clean-room verifier: 25 sections, MUQ now reports TWO PASS lines ---
uv run core/tests/python/conformance.py
uv run --with pyflakes python -m pyflakes core/tests/python/conformance.py \
                                          core/tests/python/conformance_lib

# --- six hygiene guards, --self-test FIRST every time ---
# (run each as a literal command; zsh does not word-split an unquoted variable,
#  so a `for g in "bash x.sh"; do $g; done` loop reports FAIL on all of them)
bash ffi/scripts/check-lean-binding.sh --self-test         && bash ffi/scripts/check-lean-binding.sh
bash ios/scripts/check-public-log-hygiene.sh --self-test   && bash ios/scripts/check-public-log-hygiene.sh
bash android/scripts/check-log-hygiene.sh --self-test      && bash android/scripts/check-log-hygiene.sh
bash scripts/check-secret-slot-hygiene.sh --self-test      && bash scripts/check-secret-slot-hygiene.sh
uv run scripts/check-error-payload-hygiene.py --self-test  && uv run scripts/check-error-payload-hygiene.py
uv run scripts/check-test-support-placement.py --self-test && uv run scripts/check-test-support-placement.py

# --- citation freshness: 90, and byte-identical to main ---
uv run core/tests/python/spec_test_name_freshness.py

# --- format / fixture invariants: all FOUR must be EMPTY ---
git diff main...HEAD --stat -- core/tests/data/
git diff main...HEAD --stat -- core/fuzz/seeds/
git diff main...HEAD -- ffi/secretary-ffi-uniffi/src/secretary.udl
# NORMATIVE docs only. A git pathspec glob CROSSES `/`, so `docs/*.md` would
# also match docs/manual/**; exclude the two non-normative trees by name.
git diff main...HEAD --stat -- docs/ ':!docs/handoffs/' ':!docs/manual/'
```

Re-proving the guardrails are not vacuous — note the restore, which `git
checkout` cannot do for these files:

```bash
# The three files this slice adds are UNTRACKED, so `git checkout` on them is a
# silent no-op and `git diff` is vacuous. Restore by inverse patch and verify:
shasum -a 256 core/src/vault/manifest/uniqueness.rs \
              core/src/vault/manifest/test_support/surgery.rs \
              core/tests/python/conformance_lib/codec/array_uniqueness.py
```

---

## (6) Where this document lives

`NEXT_SESSION.md` at the repo root is a **symlink**, retargeted this session to
`docs/handoffs/2026-09-04-encoder-uniqueness-shipped.md`. This file is the
single authored baton — do not create a second copy at the root, and do not sync
it to `main` during a pause window (that produces an add/add conflict).

---

## Review round (#608): one blocking finding, and what it generalises to

Five specialist reviews plus a differential re-measurement. Recorded here rather
than folded silently into the prose above, because three of these are the same
class this document already spends a section on: **a claim written from the plan
rather than from the diff.**

### Blocking — the writer half made the reader half vacuous

Adding §4.2 enforcement to `py_encode_manifest` gave the READER a backstop, and
Section MUQ could not see it. `py_decode_manifest` re-encodes through
`py_encode_manifest` for the §4.3 step-4 comparison, so deleting the decoder's
own distinctness check no longer made a repeat-carrying body decode `Ok` — the
encoder refused it one step later, with a message containing every fragment
MUQ's reader assertion (`if want not in detail`) looked for.

Measured in both directions, which is the only reason it is a finding rather
than a worry:

| tree | decoder's distinctness half deleted | MUQ reader half |
|---|---|---|
| merge-base `6d4c1cb3` | body **accepted** | **fails all four rows** |
| this branch, before the fix | rejected — **by the encoder** | **passes** |
| this branch, after the fix | rejected by the encoder | **fails all four rows** |

The fix is `manifest_encode.ENCODER_REFUSAL_PREFIX`, defined beside the code
that emits it so the two cannot drift. MUQ's reader half **rejects** that
prefix; its writer half **requires** it.

**The Rust side was never exposed**, and the contrast is the lesson: it asserts
the decode and encode variants *separately*, so a backstop can never satisfy a
decode assertion. The Python side had the same discriminator available in its
message text and simply did not use it.

**Generalises to:** whenever a rule is added to one direction of a round-trip,
ask what the other direction's tests would still catch. Enforcement added in
one place can silently *subtract* coverage in another.

### A two-sided property was pinned at one end only

Every `vector_clock_summary` fixture in the tree — Rust unit, Rust encode, the
corpus row, the Python writer case — planted its repeat in `blocks[1]`,
deliberately, to catch a walk scoped to `blocks[0]`. Nothing caught the mirror
image. `for block in m.blocks.iter().skip(1)` passed the **entire workspace
(2081 tests)** and `conformance.py`'s 25/25; the Python `[1:]` equivalent
likewise printed MUQ's full PASS line. Both ends are now planted in both
languages, and both mutations red.

This is the dual of the weakness #599's review found in the same corpus, which
is worth noticing: closing one side of a symmetry is where the other side gets
created.

### `Case`'s three columns made two invalid states representable

`expect_accept: bool` + `expect_err: Option` + `expect_encode_err: Option`
admitted a REJECT row with no predicates, which **passed** — degrading to
"rejected somehow", exactly the vacuity #599 removed. Worse, the
surgery-vs-encoder byte cross-check keyed on `expect_encode_err.is_none()`
rather than on acceptance, so setting one unrelated field on an ACCEPT row
silently disabled the corpus's only defence against `plant` drifting from
`mutate`. Replaced by `Verdict::{Accept, Reject { decode, encode }}`;
`accepts()` is derived. The cross-check still fires (verified: 1671 vs 1671
bytes — same length, so a length check would miss it).

### Smaller, each verified

- **`edit(mutated)` was unguarded** in MUQ's writer half. `IndexError` is not in
  `_REJECTION_EXCEPTIONS` and `main()` does not guard `section.run()`, so a
  shape-drifted control row produced a traceback with **no `FAIL:` line** and
  silently skipped RC, DET and REG. Now reported as an issue per case.
- **`first_repeated_value`'s `sorted()` was unreachable from either caller** —
  removing it left MUQ fully green. The Rust twin has been pinned since #600;
  the Python side got the shared helper without the test. Now pinned by
  `_shared_helper_issues`.
- **`parsed.get(array, [])` was fail-open** one token from a fail-loud
  `row[id_key]`. Both hard-index now.
- **`sign_manifest` had no negative test**, though it is the harm this whole
  slice is about. Added.
- **Doc corrections:** a cited test name that does not exist
  (`surgery_is_byte_preserving_when_it_plants_nothing`); "deleting
  `sort_unstable` leaves every other test in this file green" (it reds two, as
  this document's own M5 row said); #597's drift count inverted (three drifted,
  not four); `py_encode_manifest`'s caller list naming two of seven; "each copy
  says so" for the three surgery helpers; and CLAUDE.md's largest-module
  ranking, which had been wrong for three PRs and which #600 edited without
  fixing.

### Filed rather than fixed

`#609` — `save_block` does not check `trash`, so re-saving a trashed
`block_uuid` puts it in **both** arrays; trashing it again then wedges
permanently on `EncodeDuplicateTrashUuid`, with `restore_block` refusing
(`BlockUuidAlreadyLive`) and `purge_block` only setting `purged_at_ms`.
Pre-existing, and **#600 improves it** — before the writer check this wrote a
signed manifest carrying the duplicate and bricked the vault at next open. What
remains is the root cause and a `CorruptVault` label on what is a state bug.

`#610` / `#611` / `#612` — the `BlockError` shared-variant precedent, the
missing block index on `EncodeVectorClockDuplicateDevice`, and
`manifest_uniqueness_kat.rs` at 810 lines.
