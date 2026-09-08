# NEXT_SESSION.md — the manifest encoder's v1 sentinels come behind the writer obligation (#587)

Branch `feature/manifest-sentinel`, worktree `.worktrees/manifest-sentinel`,
base `cd20bec1` (`main`, i.e. immediately after PR #627 merged).

This slice is **(not in the previous baton's queue at all)** — it was chosen
over items (a)–(e) because it is the only remaining item where the **code can
produce a wrong artifact**. The choice was put to the user
options-plus-recommendation and the recommendation was taken, as were three
design rulings inside it (§(1)).

**One issue filed:** [#630](https://github.com/hherb/secretary/issues/630).
**Two issues REOPENED:** [#612](https://github.com/hherb/secretary/issues/612)
and [#618](https://github.com/hherb/secretary/issues/618) — see §(0), this is
the most important thing in this document. The slice closes **#587**.

---

## (0) The starting-state check FIRED THIS TIME — and a new failure mode with it

`git fetch origin && git log --oneline main..origin/main` returned
`cd20bec1`, i.e. **`main` had moved and the local checkout was one commit
behind**. The `NEXT_SESSION.md` symlink therefore resolved to
`2026-09-07-cause-coverage-shipped.md` — the baton from *two* slices ago —
and it read as a perfectly coherent, current document. There is no marker of
any kind. I read the whole thing before the fetch result was in.

**Run the fetch BEFORE reading the baton, not alongside it.** Three batons
have now said this; this is the first session where it actually mattered.

### The tracker is not a reliable record of what is done — in BOTH directions

This repo's known hazard is `(#N)`-not-`Closes #N`, so **done issues stay
open**. This session found the opposite, which nothing had recorded:

| Issue | Tracker said | Code says |
|---|---|---|
| [#612](https://github.com/hherb/secretary/issues/612) | CLOSED (`cd20bec1`) | `manifest_uniqueness_kat.rs` is **848 lines**, no `_helpers/` dir |
| [#618](https://github.com/hherb/secretary/issues/618) | CLOSED (`0f570e06`) | no spec sentence, no KAT, no section (REG was 26), and `differential_replay.rs:313` still reads `(Err(_), PyOutcome::Reject(_)) => true` |

Both were closed by `hherb` at a merge moment, attributed by GitHub's
timeline to commits that did **other work** — `cd20bec1` is #602/#627 (the
card dedupe), `0f570e06` is #589/#582/#617 (the decoder slot invariant).
Each merge message cites several `(#N)`s, and the sweep evidently took one
too many.

Both are **reopened with the measurement inline**, on the user's explicit
instruction after being shown the discrepancy. **Verify liveness against the
CODE, not the tracker state, in both directions** — the existing memory note
covers only the stale-open direction.

Housekeeping done at the same time: `.worktrees/card-dedupe` removed and
`feature/card-dedupe` deleted (merged as PR #627). **Three older local
branches deliberately left alone**, unchanged ruling —
`feature/manifest-uniqueness-parity` and `feature/noncanonical-cause` are
squash-merged (net deletions against `main`, so `-d` refuses and `-D` is
destructive), and `backup-pre-reword-1787543234` is a deliberate backup.

---

## (1) What shipped

### Commits

| SHA | What |
|---|---|
| `189b842c` | **#587** — `manifest/sentinel.rs` + wiring, 3 new `Encode*` variants, the Python twin, Section MSN, the §4.2 spec paragraph |
| `ebb117a2` | CLAUDE.md + ROADMAP, with the three counts it moves **re-measured** rather than incremented |
| *(this)* | the baton — a commit cannot cite its own SHA, so this row stays symbolic |

### The defect

`Manifest.manifest_version`, `.format_version` and `.suite_id` are `pub`
fields with no type-level invariant. `decode_manifest` has rejected anything
but the v1 sentinels since v1 (`decode/mod.rs:368-380`). **`encode_manifest`
validated none of them** — its only guard was #600's
`check_no_repeated_array_values` — so a caller could set
`manifest_version: 7`, the encoder would serialise it, and `sign_manifest`
(whose step 1 *is* `encode_manifest`) would hybrid-sign the result: **a signed
manifest no v1 client can open.** `py_encode_manifest` had the identical gap.

Fourth and last member of the #586 / #600 / #602 family. Availability, not
confidentiality — the manifest is owner-signed, so the producer is always a
local caller building a body in memory. But #599 had already made §4.2's
writer half normative for the array rules, and the schema declares the
sentinel values, so both encoders were formally non-conformant with `docs/`.

### The three rulings put to the user before implementation

All three answered with the recommendation:

1. **New `Encode*` variants**, not a reuse of the decoder's three — following
   #600, against #587's own issue text (which predates #600's ruling and says
   "reusing the three existing error variants. No new error surface").
2. **Encoder only** — leave the decoder's control flow alone.
3. **One normative §4.2 sentence**, mirroring #600's uplift.

### What landed

- **`core/src/vault/manifest/sentinel.rs`** (119) + `sentinel/tests.rs` (270),
  mirroring `uniqueness.rs` (121) / `uniqueness/tests.rs` (164) exactly.
  `check_v1_sentinels` is `encode_manifest`'s **first** statement, ahead of
  #600's check.
- **Three new `ManifestError` variants**, `EncodeUnsupported{ManifestVersion,
  FormatVersion,SuiteId}`, each carrying the observed value.
- **`codec/manifest_encode.py`'s `check_v1_sentinels`**, raising behind #600's
  existing `ENCODER_REFUSAL_PREFIX`.
- **Section MSN**, registered — REG **26 → 27**.
- **`docs/vault-format.md` §4.2** gains one normative paragraph (12 lines).
- `test_support` gained `build_manifest_map_with_sentinels`;
  `build_manifest_map_with_overrides` is now its v1 special case — **one body,
  two entry points**, rather than a second near-identical builder.
- **13 tests added, 0 removed** (2122 → 2135).

### Non-vacuity, by mutation

Twelve mutations, every restore **sha256-verified by the harness**, which
aborts rather than reporting a failed restore.

| # | Mutation | Result |
|---|---|---|
| M1 | delete the wiring from `encode_manifest` | RED — 3 |
| M2 | drop the `format_version` arm | RED — 4 |
| M3 | drop the `suite_id` arm | RED — 3 |
| M4 | report the EXPECTED v1 value, not the observed one | RED — 2 |
| M5 | reverse §4.2 field order | RED — 6 |
| M6 | swap the two `encode_manifest` preconditions | RED — 1 (the precedence test alone) |
| M7 | **delete the DECODER's sentinel check** | RED — **4** (`the_decode_side_check_is_not_backstopped_by_this_one`, `each_v1_sentinel_is_rejected_in_both_directions`, `the_decoder_reports_the_same_field_order_as_the_writer`, and the pre-existing `decode::tests::rejects_unsupported_manifest_version`). **Recorded as "RED — 1" until the #631 review** — measured through `cargo test --lib manifest::sentinel`, which reports `590 filtered out`, and the pre-existing decoder test is in those 590. |
| P1 | delete the wiring from `py_encode_manifest` | RED |
| P2 | **delete the Python READER's sentinel check** | RED, with the intended diagnostic |
| P3 | drop `suite_id` from the Python table | RED |
| P4 | reverse §4.2 field order in the Python table | RED |
| P5 | drop the field name from the refusal message | RED |

**M7 and P2 are the pair that matters**, and they are the same property in two
languages: neither encoder may stand in for its own reader.

### The measurement that made ruling 1 load-bearing rather than stylistic

Stated separately because it is the one claim in this slice that a reviewer
should re-run rather than trust:

> With the three variants **collapsed onto the decoder's** (in `sentinel.rs`,
> `sentinel/tests.rs` **and** `file/sign/tests.rs`) *and* `parse_manifest_map`'s
> own sentinel rejection deleted, `cargo test --release -p secretary-core --lib`
> reported **602 passed, 0 failed, exit 0**.

So under the design #587's issue text proposed, the decoder's sentinel check
could have been deleted with the whole lib suite green. With separate
variants, that deletion reds **four** tests — see the M7 row. This
paragraph said "exactly one test" until the #631 review, and the way it
went wrong is the lesson §(4) below claims as this slice's most
transferable one, committed in the same breath: the mutation was measured
through a FILTERED target (`--lib manifest::sentinel`, `590 filtered out`)
and written up as a whole-suite claim. The ruling is unaffected — under
collapsed variants NO test reds — but the count understated the pin.

**A near-miss inside that very measurement is worth more than the result.** My
first run of it reported "one test still caught it", which would have made the
ruling look unnecessary. It was an artefact: I had rewritten the variant names
in `sentinel/tests.rs` but not in `file/sign/tests.rs`, so the surviving
failure was my own incomplete mutation, not a real catch. **A counterfactual
mutation must be applied to every site that names the thing being
counterfactualised**, or it measures the mutation's incompleteness instead.

### The measured gate set

- **`cargo test --release --workspace`: 99 binaries, 2135 passed, 0 failed, 21
  ignored**, exit 0.
- **Test NAME SET additive-only, proven without a baseline build**: the diff
  adds **13** `#[test]` attributes (1 tracked + 12 in the new untracked file),
  removes **0**, and removes **0** function definitions — exactly the 2122 →
  2135 delta. A rename cannot hide inside a count that reconciles that way.
- `--features differential-replay` exit 0 (2136 passed).
- `cargo fmt --all --check`, `cargo build --release --workspace`,
  `cargo clippy --release --workspace --tests -- -D warnings`,
  `RUSTDOCFLAGS="-D warnings" cargo doc` (forced non-cached) all exit 0.
- **`conformance.py` exit 0**, **27** sections, REG `27 drivers, 27
  registered`, **0 `FAIL` lines** — checked by exit code AND grep.
- **All six hygiene guards pass, each `--self-test` first.** No probe residue.
- **`spec_test_name_freshness.py` = 90**, unchanged; the §4.2 paragraph cites
  no test name (verified by grepping the added lines, not assumed).
- `core/fuzz` checks clean under the pinned nightly.
- **Format invariants — `core/tests/data/`, `core/fuzz/seeds/` and the UDL
  diffs all EMPTY.** Normative `docs/` is `vault-format.md` only, +12 lines.
- Every **code** file created or touched is under 500 (`sentinel.rs` 119,
  `sentinel/tests.rs` 270, `manifest_sentinel_writer.py` 299, `error.rs` 475).
  The prose files touched are not and are not expected to be — `CLAUDE.md`
  is 1846 and `docs/vault-format.md` 775.

### `clippy --tests` earned its place again

`cargo test` compiled green while `clippy --release --workspace --tests`
failed on `type_complexity` for `[(&str, fn(&mut Manifest)); 3]`. Fixed with
two named types (`BreakCase`, `ParityCase`) rather than an `#[allow]`. The
baton has flagged this run as non-redundant for three sessions; it fired here.

### README was deliberately not touched

Checked, not assumed. `grep -niE "587|sentinel|manifest_version|encode_manifest"`
returns one hit — #399's "**no `manifest_version` bump**" note, about a
different slice — and README cites no `conformance.py` section count (its
38/38 · 118/118 figures are the *conformance KAT* harnesses, untouched). This
slice changes no user-visible behaviour, no on-disk format and no FFI surface.
`ROADMAP.md` and `CLAUDE.md` both changed.

---

## (2) What this slice does **not** claim

- **It is NOT the "one rule, both directions" shape #600 and #602 used, and
  that is the deliberate part.** The decoder keeps its own three inline
  comparisons. `parse_manifest_map` interleaves each with the `Once::require`
  that produces the value, so hoisting the requires to feed a shared checker
  changes which error a body reports when it both declares a bad sentinel and
  omits a later required key — `UnsupportedManifestVersion` today,
  `MissingField` after — silently, on a v1-frozen decoder. That is the #589
  `Once::set` lesson. **Generalise the inverse**: "put the rule in one place"
  is right most of the time and is not free when one direction's control flow
  is itself observable.
- **The two directions still cannot drift on WHICH fields are sentinels**, and
  that is a test (`each_v1_sentinel_is_rejected_in_both_directions`), not a
  structural guarantee. They cannot drift on the VALUES, because the three
  constants are single-sourced.
- **Section MSN ADDS no JSON fixture, deliberately** (it does *load* one, the
  `manifest_uniqueness_kat.json` control row it borrows a valid body from) — a sentinel rejection
  happens before any byte is produced, so a byte corpus would assert nothing.
  Do not "complete" the corpus family by adding one.
- **Rust and Python use DIFFERENT anti-backstop mechanisms**, and neither is
  required to adopt the other's: Rust discriminates by error TYPE (the three
  `Encode*` variants), Python by the `cannot encode:` message prefix, because
  its two directions raise the same class.
- **`sign_manifest`'s refusal test lives in `file/sign/tests.rs`**, not with
  the rule, because it needs `fixture_hybrid_keypair`. Duplicating a signing
  fixture to co-locate one test is how two fixtures drift.
- **No new error surface downstream.** `ManifestError` is not
  `#[non_exhaustive]`, but every bridge fold binds `VaultError::Manifest(_)`
  with a wildcard; `cargo build --release --workspace` is what confirms that,
  and it passed.
- **#621 / #623 / #624 / #625 / #626 / #628 / #612 / #618 / #596 / #603 /
  #609 / #610 / #611 / #619 / #620 / #630 stay open and untouched.**

---

## (3) What is next — with acceptance criteria

**(a) #612 — `manifest_uniqueness_kat.rs` (848 lines), REOPENED.** Now the
cheapest real item, and the tracker believed it was done, so it will be lost
again if not taken soon. `80c3c488` is the worked example (the canonicality
twin, 956 → 488 with a `_helpers/` directory, committed as a pure move).
**Acceptance:** under 500, sharing its `Case` / `Verdict` / surgery helpers
through a `manifest_uniqueness_kat_helpers/` rather than a second test binary,
committed as a behaviour-preserving move with the test name set diffed.

**(b) #618 — the DuplicateKey-outranks-WrongType precedence, REOPENED.** The
property #589 pinned is Rust-only: `docs/` does not state it, `conformance.py`
agrees only by construction (`manifest_schema.py` raises the duplicate before
the value is decoded — incidental, not pinned), and `differential_replay.rs`
cannot see it. **Acceptance:** a normative §4.2/§4.3 sentence, a KAT with
malformed second copies at top level and nested, both replays reading the
column, and a new registered section (REG 27 → 28). Check the Python side for
the #608 backstop trap — this slice hit it twice more and both times the
discriminator was the thing that saved it.

**(c) #621 — the multi-violation precedence divergence.** Rust says
`ArraySortOrder`, Python says rule 2, same bytes, offset 929. Both reject, so
nothing is unsafe. **Needs a ruling from the user before implementation**, and
declaring it unspecified is legitimate and much cheaper. **Worth noting this
slice deliberately avoided adding a second instance of it**: MSN's
`_field_order_issues` and Rust's
`a_body_violating_two_sentinels_names_the_first_in_field_order` pin the
multi-sentinel case in both languages precisely so the sentinel rule does not
acquire #621's shape.

**(d) #625 — `card.rs` is 1264 lines.** Directory module split by ROLE, every
file under 500, behaviour-preserving move with the name set diffed, and
`golden_vault_001` / `conformance.py` / the byte-identity tests green
throughout — they are what pin the signed byte form.

**(e) #630 — `manifest/encode/tests.rs` is 620 lines**, filed by this slice
(which deliberately did not grow it). Four subjects in one file: byte
identity, sort disciplines, repeated-value writer rules, `unknown` splices.

**(f) #596 — a `manifest_body` cargo-fuzz target, the natural eighth.** The
`--diff-replay` wiring exists and the seed corpus is 38 bodies. **Acceptance:**
the target exists, starts from the committed seeds, and CLAUDE.md's "Seven
targets" line becomes eight.

**(g) #623 / #624 / #626 / #628 / #603 / #609 / #610 / #611 / #619 / #620 stay
open and untouched.**

### Issues this slice closes — verify against the code, not this document

**#587.** Per the `(#N)`-not-`Closes #N` convention it stays open until a human
closes it — and, per §(0), **do not close it from a merge sweep without
checking the code first.** Its acceptance is checkable in four commands:

```bash
# 1. The encoder refuses all three sentinels, and still emits a v1 body.
cargo test --release -p secretary-core --lib manifest::sentinel     # 12 passed
# 2. The signature is refused before it is produced.
cargo test --release -p secretary-core --lib sign_manifest_refuses  # 2 passed
# 3. The clean-room writer half is registered and green.
uv run core/tests/python/conformance.py | grep -A3 "Section MSN"
# 4. REG went up by one.
uv run core/tests/python/conformance.py | grep "section registry"   # 27/27
```

---

## (4) Open decisions and risks

### The finding that generalises furthest: a counterfactual measures its own completeness

Recorded above in §(1) and repeated here because it is the transferable part.
I ran the "would reused variants have been invisible?" mutation, got "one test
caught it", and that answer was **produced by my own incomplete edit** — I had
renamed the variants in two of the three files that name them. The honest
result (whole suite green, exit 0) only appeared once the third file was
included.

**Generalise it:** a counterfactual mutation is a claim about a *design*, and
it is only as good as its coverage of every site that names the thing being
counterfactualised. Grep for the identifier across the tree before running it,
not just in the file you are editing. This is the same class as the
`--lib`/`--test` filter trap and the integration-binary-subtotal trap CLAUDE.md
already records: **a measurement scoped more narrowly than its claim.**

### The verification trap this session DID hit after all

This section originally read "the verification trap this session did NOT
hit", and claimed that every "verified by mutation" comment in `sentinel.rs`,
`manifest_sentinel_writer.py`, the commit message and ROADMAP "was written
from harness output". Both halves were true and neither was sufficient: the
M7 figure WAS written from harness output, and the harness had been given a
FILTERED target. Writing from harness output is necessary, not sufficient —
**read what the harness filtered before quoting what it counted.** The
`--lib manifest::sentinel` run that produced "RED — 1" says `590 filtered
out` on the same line it says `12 passed`.

That makes three traps of one shape in this document — the filtered target
here, the two-of-three-files counterfactual above, and the
integration-binary subtotal CLAUDE.md records — which is why the
generalisation above is stated as **a measurement scoped more narrowly than
its claim** rather than as three separate rules.

The `602 passed, exit 0` figure remains the whole-design counterfactual and
is the one to re-run if doubted; the command is in §(1). Note it is a
whole-DESIGN change, not a one-line mutation, so it cannot be re-derived by
reverting a single hunk.

One stale citation did slip in and was caught by re-reading: `sentinel.rs`'s
module doc named a test
(`every_v1_sentinel_field_is_checked_on_the_write_side`) that does not exist —
I had renamed it to `each_v1_sentinel_is_rejected_in_both_directions` while
writing the tests. Nothing mechanical catches a doc-comment citation to a
`#[cfg(test)]` item: the #92 rustdoc gate only sees public items, and
`spec_test_name_freshness.py` only scans `docs/`. **Re-read your own module
docs against the test names you actually shipped.**

### A scope decision worth recording

**The `sign_manifest` test went where its fixture already lived**, not with
the rule it tests. The alternative — copying `fixture_hybrid_keypair` into
`sentinel/tests.rs` — would have created a second signing fixture to keep one
test co-located. Co-location is worth less than a single fixture — the same
call `test_support/mod.rs` makes one file over, where
`build_manifest_map_with_overrides` became the v1 special case of
`build_manifest_map_with_sentinels` rather than a second near-identical
builder.

(An earlier draft cited "#602's review" for this. That is the wrong
citation and the #631 review caught it: #602's review round concluded the
*opposite* about its own two hostile-fixture tests — that they legitimately
solved the problem DIFFERENTLY, `card.rs` assembling bytes inline rather
than reaching for the shared permissive encoder, because it wanted PUSH
order. What that review actually corrected was a doc claiming they shared
one helper. The principle invoked here is real and in-repo; it just is not
that paragraph's.)

### Standing risks this slice does not remove

- **Two issues were closed while unimplemented** (§(0)). Reopened, but the
  process that closed them is unchanged.
- **Five of the six PEP 723 deps remain unbounded** (`cryptography`, `pynacl`,
  `argon2-cffi`, `blake3`, `cbor2`), and `ed25519_verify` still has the "no
  exception means success" shape whose failure direction is fail-**open**
  (#544 / #550).
- **Multi-violation precedence is unspecified and divergent** (#621), and
  `differential_replay.rs:313` scores reject-vs-reject as agreement without
  comparing `detail` (#618) — which is why #621 is invisible to it, and will
  stay invisible after #621 is fixed.
- **The `unknown`-subtree residual is untouched**: no duplicate-key or
  key-order check looks inside an `UnknownValue`, deliberately.
- **`card.rs` (1264), `manifest/encode/tests.rs` (620), `sync/state.rs` (570),
  `canonical/value.rs` (1082) and `manifest_uniqueness_kat.rs` (848) are all
  past the 500-line guideline** — #625 / #630 / #626 / #603 / #612.
- **#628 asks whether "call the check first" should be a `CheckedEntries`
  newtype.** #587 adds a *second* "call it first" precondition to
  `encode_manifest`, so it makes that question slightly more pressing rather
  than less. Nothing stops a future encode path skipping both.

---

## (5) How to resume — the exact commands

```bash
# FIRST, and BEFORE reading the baton — this fired this session (§0):
git fetch origin && git log --oneline main..origin/main

cd /Users/hherb/src/secretary/.worktrees/manifest-sentinel
pwd && git branch --show-current && git worktree list   # expect feature/manifest-sentinel

# --- the gates this slice is actually about ---
cargo test --release -p secretary-core --lib manifest::sentinel   # expect 12 passed
cargo test --release -p secretary-core --lib sign_manifest_refuses # expect 2 passed
uv run core/tests/python/conformance.py                            # 27 sections; REG 27/27

# --- the rest of the gate set ---
cargo fmt --all --check
cargo build --release --workspace          # separate from the test run ON PURPOSE
# Redirect, then echo $? — a `| grep` pipeline reports GREP's exit code:
cargo test --release --workspace > /tmp/suite.txt 2>&1; echo "CARGO EXIT: $?"
grep -E "^test result" /tmp/suite.txt | \
  awk '{p+=$4; f+=$6; i+=$8} END {print NR, p, f, i}'   # expect 99 2135 0 21
# NOT redundant with the above — it caught a type_complexity error this slice:
cargo clippy --release --workspace --tests -- -D warnings
touch core/src/lib.rs   # rustdoc caches; a ~5s run did nothing
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace

# The cross-language contract (no CI job covers this one). SLOW, and it holds
# cargo's package-cache lock — run it BEFORE the fuzz check, not in parallel.
cargo test --release --workspace --features differential-replay
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

# --- citation freshness: 90, unchanged from main's baseline ---
uv run core/tests/python/spec_test_name_freshness.py

# --- format invariants. The first THREE must be EMPTY; the fourth is
#     vault-format.md only, +12 lines. ---
git diff origin/main...HEAD --stat -- core/tests/data/
git diff origin/main...HEAD --stat -- core/fuzz/seeds/
git diff origin/main...HEAD -- ffi/secretary-ffi-uniffi/src/secretary.udl
# NORMATIVE docs only. A git pathspec glob CROSSES `/`, so `docs/*.md` would
# also match docs/manual/**; exclude the two non-normative trees by name.
git diff origin/main...HEAD --stat -- docs/ ':!docs/handoffs/' ':!docs/manual/'
```

Re-running this slice's mutation harnesses (each asserts every restore's
sha256 and **aborts** rather than poisoning the next mutation):

```bash
python3 <scratchpad>/mutate587.py     # M1-M7, Rust: the rule, its wiring, and the decoder
python3 <scratchpad>/mutate587py.py   # P1-P5, Python: the twin plus its reader
```

Re-proving the design ruling by execution — the fastest way to see why the
three `Encode*` variants are not a style choice. Collapse them onto the
decoder's in **all three** files that name them (`sentinel.rs`,
`sentinel/tests.rs`, `file/sign/tests.rs` — missing the third measures your
own edit, §4), delete `parse_manifest_map`'s sentinel rejection, and run
`cargo test --release -p secretary-core --lib`: **602 passed, exit 0.**

Re-proving the defect itself:

```bash
# Before #587, this produced a signed manifest no v1 client could open.
git show 189b842c^:core/src/vault/manifest/encode.rs | sed -n '/^pub fn encode_manifest/,/^}/p'
sed -n '/^pub fn encode_manifest/,/^}/p' core/src/vault/manifest/encode.rs
```

---

## (6) Where this document lives

`NEXT_SESSION.md` at the repo root is a **symlink**, retargeted this session
to `docs/handoffs/2026-09-08-manifest-sentinel-shipped.md`. This file is the
single authored baton — do not create a second copy at the root, and do not
sync it to `main` during a pause window (that produces an add/add conflict).
