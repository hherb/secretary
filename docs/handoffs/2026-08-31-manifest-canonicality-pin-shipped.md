# NEXT_SESSION.md — pin the #572 manifest canonicality contract (#578, #583, #585, #592)

Branch `feature/manifest-canonicality-pin`, worktree `.worktrees/manifest-canonicality-pin`,
base `e29cb216` (`main`, i.e. immediately after PR #584).
Commits of substance run from `2f260a34` (the design spec) through the PR-review fix wave;
`git rev-list --count main..HEAD` is the authoritative count — deliberately not written out
here, because it has already been wrong once: the figure was pinned before two further
waves landed. This document's own SHA is likewise not quoted, since it *is* the tip commit
and any SHA written for it is falsified by its own amendment.
**The whole-branch review has RUN**, after the first baton was written at `43b5a4d5`. It
returned **five findings — two Important, three Minor** — and the first Important one is a
**regression this branch itself created**. A single fix wave, `88114077`, closed all five.
Two issues were filed: **#593** and **#594**.

**PR #595 is OPEN**, and every check passed except one: CodeQL flagged a
`rust/cleartext-logging` alert (#289) on a `#[cfg(test)]` `panic!` message. It is a false
positive — test-only code, and the traced values are non-secret UUIDs — and has been
dismissed "used in tests", matching 20+ prior dismissals of that rule in this repo. CodeQL
is not in the `protect_main` required-check set.
**A four-reviewer PR review then ran and returned three Critical and six Important
findings**, the worst of them again something this branch shipped: `py_decode_manifest`
was fail-OPEN on every known scalar field, accepting nine manifest bodies `decode_manifest`
rejects. A second fix wave closed **all nine plus every suggestion**, adding three pinning
guard sections (MSH / MOC / MAS), corpus floors on MCK, and one Rust test, and filed
**#596**. See §(1) "The PR review, and the second fix wave" below for the full record.
Nothing from that review is deferred.

---

## (1) What shipped

### Commits

| SHA | What |
|---|---|
| `2f260a34` | design spec |
| `ae6fa038` | nine-task implementation plan |
| `c6ee36a5` | **T1 (#578)** — Property F generates forward-compat `unknown` bags at all three manifest levels |
| `afd4a0b5` | **T2 (#585, #592)** — span-recording CBOR scanner for §4.2 subtrees |
| `e9155a7c` | **T2 fix round 1** — scanner bounds check + indefinite-major validation |
| `b739bb74` | **T3 (#585)** — strict §4.2/§4.3 manifest **body** decoder in `conformance.py` |
| `070cc298` | **T3 fix round 1** — byte retention extended into block/trash entries; all 9 top-level keys required |
| `fabe8452` | **T3 fix round 2** — `kdf_params` / `vector_clock` entries reject unknown keys; block/trash required fields validated |
| `c9247bbe` | **T4 (#585, #583)** — `manifest_body` differential-replay target |
| `2c8562fb` | **T5 (#583)** — the per-rule canonicality corpus + its 21 fuzz seeds |
| `40c42888` | **T6 (#583, #592)** — replay the corpus through both reader strategies |
| `ee7181dd` | **T7 (#592)** — byte retention in the **record** decoder, at both nesting levels |
| `1674573b` | **T8 (#592)** — name the `cbor2` duplicate-collapse trap in §4.2; scope §6.2's `canonical=True` |
| `43b5a4d5` | **T9** — closeout: full gate set, three doc corrections, the first baton |
| `88114077` | **post-review fix wave** — findings A-E of the whole-branch review, all in `conformance.py` |
| *(this)* | baton update: the fix wave, #593 / #594, and the sharpened boundaries in §(2) |

`33 files changed, 4775 insertions(+), 150 deletions(-)` at `88114077`. The figure is quoted
at the last **code-bearing** commit on purpose, so this baton update does not falsify it.

### What the slice actually establishes

PR #584 (`a2da3d24`, #572) made `decode_manifest` re-encode the parsed `Manifest` and
demand its own input bytes back, and wrote two normative claims into the **frozen** spec
to match — a five-row per-rule table and a two-part reader obligation for `unknown`
subtrees. **Nothing executable checked any of it.** That is what this slice closes:

- **#585** — `conformance.py` now has a real `py_decode_manifest` / `py_encode_manifest`
  pair over a span-recording CBOR scanner, replacing the bare `cbor2.loads` the golden
  vault's manifest body used to go through. It enforces the five array sort disciplines,
  requires all nine known top-level keys, rejects duplicate keys at every **known** level,
  and ends with the §4.3 step-4 re-encode-and-compare against its own input.
- **#583** — `core/tests/data/manifest_canonicality_kat.json`: 21 rows, replayed by both
  languages, asserting Rust's verdict and the Python byte-retaining reader's verdict agree
  row for row.
- **#592** — the finding that reshaped the work. A `cbor2.loads`-based reader **cannot**
  satisfy §4.2's two-part obligation: `cbor2.loads` returns a `dict`, so a duplicate key
  inside an `unknown` subtree is collapsed before any encoder is chosen, and the re-encode
  then fails against an input Rust accepts. The fix is byte retention, and it had to land
  in the **record** decoder as well.
- **#578** — manifest Property F now generates `unknown` bags instead of hardcoding
  `BTreeMap::new()` at all three strategies.

### The whole-branch review, and the fix wave `88114077`

Five findings, **all** of them in `core/tests/python/conformance.py` — no Rust, no fixture,
no spec text. Two are Important and the first is a regression this branch created.

- **A (Important — a REGRESSION, measured against the pre-branch commit `e29cb216`).**
  Moving record `unknown` subtrees off `cbor2.loads` onto byte retention (T7) silently lost
  two validations `cbor2` had been performing **implicitly**, because
  `_check_canonical_item` checked neither. An invalid-UTF-8 text string inside a
  `RecordField.unknown` subtree was **REJECTED on `main` and ACCEPTED on this branch**;
  Rust rejects it. Same for `F8 14`, a redundant one-byte encoding of `false`. `record` is
  a live **fuzz** and **differential-replay** target, so this would have surfaced as a
  *false* cross-language disagreement once the fuzzer explored it. Fixed by validating
  UTF-8 for major 3.
- **B (Important).** Major 7 diverged wholesale: Rust accepts only `F4` / `F5` / `F6`,
  while Python also accepted `E0`, `F0`, `F7` (undefined), `F8 14`, `F8 20` and `F8 FF`.
  `F7 undefined` is an **ordinary item a v2 writer could emit**, so this was a live
  forward-compat divergence, not a malformed-input curiosity. Fixed by restricting major 7
  to `ai in (20, 21, 22)`.
- **C (Minor).** `naive_accepts` caught bare `Exception`, so a `NameError` in the naive
  reader would have been counted as "rejected" and would have satisfied the positive
  control **for the wrong reason**. Narrowed to `(cbor2.CBORError, ValueError, TypeError)`.
  The implementer found and fixed the identical bug in a **verbatim-duplicated sibling
  helper** that the findings list had not named.
- **D (Minor).** A docstring called the 21 corpus rows "the 'two conformant readers accept
  the same set' property". Twenty-one rows are *evidence* for that property, not the
  property. Reworded; §(2) below states the corrected claim.
- **E (Minor).** Two branches became unreachable once `_decode_head` started validating
  indefinite-length majors (Ruling 4). Commented as unreachable-and-kept-for-defence-in-
  depth, deliberately **NOT deleted**.

**Non-vacuity, by execution rather than by claim.** The scoped re-review reproduced both
mutations independently: deleting the UTF-8 check reds exactly the `invalid-UTF-8 text
string` row, deleting the major-7 restriction reds exactly the `0xF8 0x14` and `0xF7` rows,
and nothing else moves in either case. The three positive controls are load-bearing too —
narrowing the accepted set to `(20, 21)` reds the `null (0xF6)` row. Regression A's closure
was proven end to end by splicing `61 FF` into `Record.unknown["zzz_future"]` and watching
`py_decode_record` reject it with a byte offset.

### The measured result

- **2001 tests green across 98 binaries** (`cargo test --release --workspace`), 0 failed,
  20 ignored. With `--features differential-replay`: **2002 / 98**, including
  `differential_replay_full_corpus`.
- `cargo fmt --all --check` clean. `cargo build --release --workspace` clean (run
  **separately** from the test run on purpose — a leak only a non-test build catches is a
  documented class in this repo). `cargo clippy --release --workspace --tests -- -D warnings`
  clean. `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace` clean, **forced
  non-cached** (`touch core/src/lib.rs` first; the run took 52.9 s and documented all nine
  workspace crates — a 5 s run did nothing, which is the trap #575's T1 review caught once).
- **All six hygiene guards pass, each `--self-test` first** so no green guard is vacuous.
- **`conformance.py` PASS** — the clean-room verifier still decrypts `golden_vault_001`
  from `docs/` alone, now through the strict body decoder rather than `cbor2.loads`.
- **The two gates no CI job covers**, both clean at `43b5a4d5`:
  `cargo check --release --features differential-replay --tests -p secretary-core`, and
  `core/fuzz` under the pinned nightly. `--workspace` builds **neither** (`core/fuzz` is
  workspace-`exclude`d; `differential_replay.rs` is `#![cfg(feature = …)]`), which is
  exactly how they have broken undetected before.
- **`spec_test_name_freshness.py` = 90**, the baseline, with a **member set identical to
  `main`'s** — `comm` empty in both directions on a file-qualified comparison, verified
  against a throwaway detached worktree of `main` rather than assumed from the count.
- **Re-run at `88114077`**, because every figure above was measured at `43b5a4d5`:
  `conformance.py` **PASS**; `cargo test --release --workspace` zero failures across **98**
  `test result: ok` blocks; `cargo test --release --workspace --features
  differential-replay` zero failures including `differential_replay_full_corpus`. The fix
  wave touches one Python file so no Rust gate *could* move — it was re-run rather than
  assumed.
- **No on-disk format change.** `git diff main...HEAD --stat -- core/tests/data/` shows
  **exactly one added path** (`manifest_canonicality_kat.json`, +109) and **zero modified**.
  The uniffi `.udl` diff is **empty**. Both `core/src/` changes are in
  `core/src/vault/record.rs`: the +131-line test **inside `mod tests`**, and — added by the
  PR-review wave — a corrected doc comment on `RecordError::DuplicateKey`, which is *outside*
  `mod tests` and so no longer fits the "inside `mod tests`" phrasing this line used to
  carry. It is a doc comment: no public API, no shipped behaviour, and `cargo doc -D
  warnings` is clean.

### The PR review, and the second fix wave

`/pr-review-toolkit:review-pr 595` ran four reviewers (general code, test coverage,
comment/spec accuracy, silent failures) over the pushed branch. It returned **three
Critical and six Important findings**, and — like the first wave — the most serious was
something this branch itself shipped. All were fixed on the branch; nothing was deferred.

**Critical 1 — `py_decode_manifest` was fail-OPEN on every known scalar field.** It pulled
`manifest_version`, `format_version`, `suite_id`, `vault_uuid`, `owner_user_uuid` and the
four `kdf_params` members out with a bare `cbor2.loads` and never looked at them. Measured:
`manifest_version = 999`, a text `manifest_version`, a 5-byte `vault_uuid`, `suite_id = 999`
and a 3-byte salt all decoded cleanly here and are all rejected by `decode_manifest`. In the
file whose stated purpose is proving `docs/` alone is sufficient to build a **conformant**
reader, a reader LAXER than the frozen-format decoder proves the opposite of what it claims.
Nothing in the tree could see it: the §4.3 step-4 re-encode compares BYTES and every one of
those bodies re-encodes to itself, and all 21 corpus rows mutate only `unknown` subtrees.
`_decode_strict_entry_map` had the same shape one level down — it took no `required_keys`,
so `kdf_params` missing `iterations` or `salt`, and a vector-clock entry missing `counter`,
were accepted. Closed by `_validate_manifest_shape` + `_check_uint`/`_check_fixed_bytes`,
pinned by **Section MSH** (15 mutations, two-sided: no-op'ing the fix reds 16 rows,
a reject-everything decoder reds the positive control).

**Critical 2 — the differential harness could report agreement it never established.**
`run_diff_replay` turned *every* exception into `{"status": "reject"}` with exit 0, and
`differential_replay.rs` scores reject-vs-reject as agreement. A `NameError`, a
`RecursionError`, a `cbor2` API break, a missing input file, a `uv` that could not resolve
its dependencies — each became a green differential test, and **9 of the 21 committed
`manifest_body` seeds are Rust-reject rows**, i.e. exactly the class where the misreading
lands. Closed on both sides: Python now separates a VERDICT (`_REJECTION_EXCEPTIONS`, an
allowlist so a new exception type fails loudly rather than being scored) from a HARNESS
FAILURE (`status: "error"`, exit 3, traceback to stderr); Rust gained `PyOutcome`'s third
arm, which never reaches the agreement match, plus default-deny on an unrecognised status.
A timeout, a signal death and a non-zero exit are now harness failures, and stderr is
carried through instead of being discarded on the agreement path.

**Critical 3 — the corpus was vacuous on all five §4.2 array sort disciplines.** Measured
across all 21 rows: `vector_clock`, `recipients` and `vector_clock_summary` were EMPTY in
every one, and `blocks`/`trash` held at most one element. An array of length 0 or 1 is
sorted whatever any check does, so `_check_sorted` could be made a no-op with the whole
suite green — and the sort disciplines are the *newly narrowing* half of the §4.2 reader
contract (#572), the half a clean-room implementer reading `docs/` alone gets wrong. This is
bit-for-bit the vacuity §(2) below levels at `golden_vault_001`, in the corpus written to
carry that weight instead. `base_manifest` now puts **two entries in all five arrays** at
every level (fixture and seeds regenerated; verdict mix unchanged at 12 accept / 9 reject),
and the REJECTION side is pinned twice — `array_sort_disciplines_are_enforced_and_not_vacuous`
on the Rust side and **Section MAS** on the Python side, each reversing one array at a time.

**The six Important findings**, each closed: three `except Exception` arms that a mutation
proved would score a `NameError`-instead-of-reject as a passing verdict across 12 + 9
assertions; a one-sided positive control (membership-only, so a naive reader returning False
for *everything* satisfied it — now two-sided, asserting agreement on the three
`*__control_canonical` rows, verified by isolated mutation); the outer-map re-encode check,
pinned by nothing until **Section MOC** (disabling it flips three inputs from reject to
accept); and three comment defects — rule 4 attributed to the re-encode when
`reject_floats_and_tags` is what rejects it, a claim that a `Manifest` has no nested
`unknown` bag when it has three, and three comments re-asserting that the re-encode rejects
duplicate keys in nested KNOWN maps, which is the exact reasoning this branch deleted from
`_check_no_duplicate_keys` and which the byte-retention design had already falsified.

**Also closed:** per-target input floors in `differential_replay.rs` (a renamed seeds
directory made every target replay zero inputs, silently — the mechanism behind the
"passed vacuously" note this branch's own module doc recorded); corpus row-count and
verdict-mix floors on the Python replay to match the Rust one; evidence lines on all
fourteen previously-silent guard sections, so a shrunken corpus is visible in a CI log;
`RecursionError` added to the verify path's catch tuple; concurrent draining of the child's
stdout **and stderr** (the old "a single short JSON line cannot fill the pipe" comment
reasoned about stdout only, while the code also piped stderr from a `uv` child whose
cold-cache builds are what `PER_INPUT_TIMEOUT` exists to absorb); the splice width derived
rather than hardcoded; and the "passed for two years" claim corrected to four months — the
repository's initial commit is `450d3490`, 2026-04-25.

**Reviewed and deliberately NOT changed:** the `RFC 8949 §4.2.1` citations. §4.2.1's
bytewise-ordering-of-encodings rule *yields* length-then-bytewise for text-string keys,
which is what `docs/crypto-design.md` §6.2 rule 1 already says; rewriting them to §4.2.3
would introduce an error rather than fix one.

**One finding was filed rather than fixed: #596** — `core/fuzz/seeds/manifest_body/` holds
21 seeds but has no cargo-fuzz target, so its differential corpus can never grow. This was
already recorded as future-work item (e) below, but only in a plan document; it now has an
issue with acceptance criteria, and `core/fuzz/README.md` says so at the seed location.
A `manifest_body` fuzzer is what would have surfaced Critical 1 automatically.

**One CodeQL alert was dismissed, not fixed:** #289, `rust/cleartext-logging` (high), on the
`panic!` message in this branch's new `record.rs` test. Test-only code; the traced values are
`record_uuid`/`device_uuid`, non-secret metadata already in the signed manifest; and
`SecretString`/`SecretBytes` have a redacting `Debug` that prints only a length, so field
plaintext cannot reach it. 32 open alerts of this rule already sit on `main` and 20+ were
previously dismissed "used in tests". CodeQL is not in the `protect_main` required-check set.

**Re-measured after this wave:** `cargo test --release --workspace` **2002 passed, 0
failed**; `--features differential-replay` clean, and the harness now prints its per-target
input counts (3/3/2/1/1/**21**/1); `cargo clippy --release --workspace --tests -- -D
warnings` clean; `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace` clean;
`cargo fmt --all` applied; `conformance.py` **PASS** with every section now emitting
evidence rather than a bare header.

---

## (2) What this slice does **not** claim — read this before citing it

Five boundaries, each stated as a boundary rather than a caveat, because the wider reading
is the one a summary naturally reaches for. The final review found one of them overstated
**in the code itself** (finding D) and had it corrected there too.

**The corpus proves agreement on 21 specific rows, not on all inputs.** Seven subtree
shapes (five §6.2 rule violations plus two accepting controls) x three nesting levels
(manifest body, `blocks[i]`, `trash[i]`). It is a **known-answer test**, not a proof: the
two readers agree on those 21 inputs at those three levels. Nothing here establishes that
they agree on an arbitrary manifest body. The randomized coverage (#578's Property F) and
the `manifest_body` differential-replay target are what widen the input space, and both are
single-language or seed-bounded respectively. A docstring on the replay section asserted the
wider reading — that the 21 rows *were* the "two conformant readers accept the same set"
property rather than evidence for it — and the fix wave reworded it (finding D). Do not
reintroduce the wider phrasing here or there.

**`golden_vault_001` is VACUOUS for every claim this slice pins, and the corpus carries
the whole weight alone.** Verified by execution at the slice tip, decrypting the fixture's
manifest body through the new strict decoder:

```
top-level unknown bag: {}
len(vector_clock) = 1     len(blocks) = 1     len(trash) = 0
  blocks[0].unknown = {}
  len(blocks[0].recipients) = 1
  len(blocks[0].vector_clock_summary) = 1
```

Zero `unknown` subtrees at any level, so it exercises **none** of the unknown-subtree
rules-1/5 tolerance or the rules-2/3/4 rejection. And every one of the five sorted arrays
holds **at most one element**, so it is equally vacuous for the five array sort disciplines
`encode_manifest` enforces. The golden vault validates the known-field path and the crypto;
it validates nothing this slice is about. That was named as a risk in the design spec's §10
and it held.

**A sentence that was wrong when first written here, and is true only now.** This section
originally went on to say the 21-row corpus carried that weight instead. It did not: the
corpus was vacuous on all five sort disciplines in exactly the same way, and for the same
reason — `base_manifest` built three of the arrays empty and the other two with at most one
element. The PR review measured it. As of that fix every corpus row carries **two entries in
all five arrays**, so the claim now holds; before it, the criticism of `golden_vault_001`
applied verbatim to the fixture written to replace it. See §(1) "The PR review, and the
second fix wave", Critical 3.

**The fix wave's new pins are SCANNER-UNIT rows, not cross-language corpus rows — and
there are three of them, not six.** `section_cbor_scanner_units` gained one invalid-UTF-8
reject row and **two** of the six divergent major-7 shapes (`F8 14`, `F7`), plus three
`F4`/`F5`/`F6` positive controls. The other four (`E0`, `F0`, `F8 20`, `F8 FF`) fall to the
same one-line restriction but have **no row of their own**; they were verified by hand
during the fix, not pinned. Every one of these is a Python-only assertion that the
byte-retaining scanner rejects the shape. The 21-row
`manifest_canonicality_kat.json` corpus was **deliberately not extended** with them:
adding a row means regenerating the fixture from Rust ground truth, which was out of the
fix wave's scope. So for those shapes the *cross-language agreement* rests on reading
`ciborium::Value`, not on a replayed Rust verdict. That is a smaller claim than the 21 rows
carry, and it is the honest one. Extending the corpus with them is the obvious companion to
#594's second half.

**#590's title says "five causes"; the corpus fires that variant on 6 of 21 rows, and
`rule4_float` does not reach it at all** — it yields `CanonicalError::FloatRejected`
instead. The two shapes that do reach `NonCanonicalEncoding` are `*__rule2_indefinite_map`
and `*__rule3_non_shortest_int`, at three nesting levels each. **Do not write "the corpus
fires #590 five ways" anywhere**; §(3)(c) states the measured version.

**The manifest's three uniqueness invariants are outside everything this slice pins, and
that is not a corpus defect.** `DuplicateBlockUuid`, `DuplicateTrashUuid` and
`VectorClockDuplicateDevice` are array-level rules; the §4.2 table the corpus is built
against covers per-item encoding rules. A sortedness check passes for a repeated element —
`[x, x]` **is** sorted — so nothing in the sort disciplines implies uniqueness either.
That gap is now **#594**; §(3)(b) has it.

---

## (3) What is next — with acceptance criteria

### Immediate: push and open the PR

The whole-branch review has **run**, and its five findings are closed in `88114077`. CI has
**never run on this branch** — that is the one gate still outstanding. The controller drives
the push.

### Then, in the order the slice's own findings argue for

**(a) #593 — split `conformance.py`. THE NEXT SLICE, not the one after.** Filed during this
closeout, **mandated by the design spec's own §10 risk row** rather than discretionary. The
file went 4303 → **6849** lines (6107 when the issue was filed at `43b5a4d5`, 6187 after the
first fix wave, and the PR-review wave added the rest — the four new guard sections and
`_validate_manifest_shape` are ~660 lines between them). **The count has now been wrong
three times in this document because each wave outgrew it; treat `wc -l` as authoritative.**
The growth also strengthens the case: every wave has added sections, and none has been able
to remove any. The final review's judgement is the load-bearing half and must not be
dropped in a summary: shipping this slice is acceptable **only because** #593 is filed with
concrete acceptance criteria. A clean-room verifier's value is exactly proportional to how
credibly a human can read it. **Acceptance:** a `core/tests/python/conformance/` package
behind a thin entrypoint, the PEP 723 header still the sole dependency declaration, `uv run
core/tests/python/conformance.py` working verbatim, and the `--diff-replay` CLI contract
byte-identical. The issue lists all four constraints.

**(b) #594 — the manifest's three uniqueness invariants are enforced by Rust and stated
NOWHERE in `docs/`.** `DuplicateBlockUuid`, `DuplicateTrashUuid` and
`VectorClockDuplicateDevice` (all three in `core/src/vault/manifest/error.rs`) have
no normative counterpart: `grep -c "uniq" docs/vault-format.md` returns **0**, and §4.2
states the five SORT disciplines and says nothing about uniqueness — a sortedness check
passes for a repeated element, because `[x, x]` **is** sorted. Verified by execution: a body
carrying two `blocks[]` entries that share a `block_uuid` is **ACCEPTED** by the Python
reader and **rejected** by Rust. **This is the clean-room verifier doing exactly what it
exists to do** — building a reader from `docs/` alone surfaced a gap in the spec, not a bug
in the reader — and it is **not** a defect in this slice's corpus, which is built against
the §4.2 per-item table (see §(2)). **It has two halves and they must land together:** the
frozen-spec edit stating the three invariants as normative, and the `py_decode_manifest`
fix. Doing only the second encodes a rule the spec still does not state, which is the
divergence class this whole slice exists to remove. **Acceptance:** §4.2 states all three
invariants; `py_decode_manifest` rejects each; each is pinned by a test row; the golden
vault still decrypts and `conformance.py` still PASSes.

**(c) #590 — "`ManifestError::NonCanonicalEncoding` collapses five causes with no
locator, on the every-open path".** This slice makes #590 *more visible*, which is the
argument for keeping it high in the queue — behind #593 and #594, which the final review
ranked ahead of it. Be exact about how far, because the obvious overstatement is
available. The variant's own doc (`core/src/vault/manifest/error.rs`) groups those causes as
indefinite-length item, map-key disorder, non-shortest-form integer or length prefix, and
this layer's extra one, an array outside its §4.2 sort order. The new corpus fires **two**
(`*__rule2_indefinite_map`, `*__rule3_non_shortest_int`), at three nesting levels each. The
third rejecting shape, `*__rule4_float`, does **not** reach this variant at all — it is
caught earlier by `reject_floats_and_tags` as `CanonicalError::FloatRejected`, which already
carries a `&'static str` field hint. So the gap is real but narrower than "five causes":
six of the 21 rows land on one undifferentiated, locator-free variant.
**Acceptance:** `ManifestError::NonCanonicalEncoding` carries a fieldless cause
discriminant plus a byte offset (the `CborFault` shape `core/src/cbor/mod.rs` already uses,
so it stays data-free by construction); each of those six rows names its own cause; the
payload-hygiene guard passes with **no new allowlist entry**.

**(d) #589 — the 21 duplicate-key guards are hand-copied, not a type invariant.**
**Acceptance:** the duplicate-key check is expressed once (a helper or a type that cannot
be constructed with a repeat), all 21 hand-copied sites route through it, and deleting the
single implementation reds more than one test.

**(e) A `manifest_body` cargo-fuzz target — the natural eighth.**
The `--diff-replay` wiring landed in this slice specifically to make this cheap.
**Acceptance:** `core/fuzz/fuzz_targets/manifest_body.rs` exists, `cargo fuzz run
manifest_body` starts from the 21 seeds already committed at
`core/fuzz/seeds/manifest_body/`, and `CLAUDE.md`'s "Seven targets" line becomes eight.

**(f) #586 / #587 stay open and untouched.** The encoder can still emit or sign a body its
own decoder would reject. The design spec's §6 constraint 1 avoids *tripping* #586; it does
not fix it. **Do not record these as addressed.**

### Issues this slice closes — verify against the code, not against this document

**#578, #583, #585, #592.** This repo cites fixes as `(#N)` and never `Closes #N`, so each
outlives its fix until a human closes it. Nothing in this slice closes **#589, #590, #586,
#587, #569** (path 3, `identity/card.rs`, untouched). **#593 and #594 were FILED by this
slice and are open by design** — #594 in particular is a live Rust/Python acceptance-set
divergence that this branch documents rather than fixes.

---

## (4) Open decisions and risks — the full record

### Rulings taken on the user's behalf

Thirteen decisions were recorded in the slice ledger
(`.superpowers/sdd/2026-08-31-manifest-canonicality-pin/progress.md`). Each carries a
"cost if wrong" in that file; the substance is here. **Ruling 9 is absent from this list on
purpose** — it survives in the ledger only as a correction against itself, and is the second
entry in the subsection below, so the 1-8 / 10-13 numbering here is not an omission.

1. **Ruling 1 (pre-flight, a defect in my own plan).** `py_decode_manifest` as planned did
   no re-encode-and-compare of its own, leaving a divergence *opposite* to #592: a duplicate
   key inside a nested **known** map is rejected by Rust (#573's guards) but would be
   silently collapsed and accepted by Python. Decided: the decoder ends with a §4.3 step-4
   re-encode against its input.
2. **Ruling 2 (T2, entered the fix loop).** `_check_canonical_item`'s definite-length string
   branch had no bounds check, so an oversized length claim on the last item returned a bogus
   out-of-bounds offset **silently**. Decided: fix — §4.4 binds ("an unrecognised shape is a
   raise, never a default") and the function is reached from a diff-replay target the fuzzer
   drives on adversarial input.
3. **Ruling 3 (T2).** A prescribed mutation crashed on the first rule-2 row, so three rows
   were never shown to be pinned. Decided: **do not** weaken `except ValueError` to
   `except Exception` — that would let a crash count as a rejection — and run a second,
   targeted mutation instead.
4. **Ruling 4 (T2, a Minor promoted into the same round).** `_decode_head` accepted `ai=31`
   for majors 0/1/6/7 where RFC 8949 permits it only for 2/3/4/5, so `_scan_item` mis-scanned
   `0x1F` as a valid one-byte item. Contained by a caller today — but containment by a caller
   is not a property of the primitive.
5. **Ruling 5 (T3 — a DESIGN defect, mine).** The design spec's §4 component table scoped
   byte retention to the **top-level** `unknown` bag only. `BlockEntry` and `TrashEntry` each
   carry their own, so a duplicate key one level deeper was rejected by Python and accepted by
   Rust — the exact #592 divergence, nested. The reviewer found it **by execution, not by
   reading**. Cost: two fix rounds. Corrected in the spec during this closeout.
6. **Ruling 6 (T3).** `py_decode_manifest` hard-required 3 of 9 known top-level keys where
   Rust's `Manifest` has no `Option` and requires all 9 — and the new re-encode does **not**
   catch it, because a body missing a key re-encodes to itself. Same divergence class,
   opposite direction.
7. **Ruling 7 (T3, fix round 2).** `kdf_params` and `vector_clock` / `vector_clock_summary`
   entries were still routed through blanket `cbor2.loads`/`dumps`. Those Rust parsers have
   **no** `unknown` bag and end in a catch-all `WrongType` arm, so Python silently accepted a
   forward-compat key Rust rejects. Verified independently by the re-reviewer against the Rust
   source, not taken from the implementer's claim. Not exercised by any fixture — which is
   exactly why it would otherwise have shipped invisible.
8. **Ruling 8 (T3, folded into the same round).** A block entry missing `block_uuid` surfaced
   as a raw `KeyError` from inside the encoder during the decoder's own re-encode, which the
   narrower `except ValueError` in the new guard sections would have turned into a **crash**
   rather than a clean FAIL for a T5/T6 corpus row.
9. **Ruling 10 (T5).** The new `manifest_body` differential-replay target passed
   **vacuously**: `corpus_dirs()` treats an absent seed directory as an empty list, and none
   existed. Decided: commit 21 seeds to `core/fuzz/seeds/manifest_body/`.
10. **Ruling 11 (T5).** The plan spliced each subtree at top level only — predating Ruling 5.
    A top-level-only corpus would have missed precisely the bug T3 spent two fix rounds
    closing, and T6's agreement assertion would have passed while blind to it. Decided:
    7 shapes x 3 levels = **21 rows**.
11. **Ruling 12 (T7 — Ruling 5's lesson applied PROSPECTIVELY).** `RecordField` carries its
    own `unknown` bag exactly like `BlockEntry`/`TrashEntry`. Decided: retain at **both**
    record and field level from the start. It worked — T7 landed first time, no fix rounds.
12. **Ruling 13 (T8 Low finding, folded into T9).** §4.2's new implementation note said "per
    the paragraph above" but the paragraph immediately above is the dict/HashMap one, not the
    "(1) but not (2)" one it meant. Fail-closed (the note restates the substance) but it is
    citation rot on a **frozen** spec. Fixed in this closeout.

### Two rulings the controller recorded AGAINST ITSELF

These are part of the honest record; a reader should not have to reconstruct them.

- **Ruling 3 CORRECTION.** My prescribed mutation (`ai == CBOR_AI_INDEFINITE and major == 5`)
  **still crashed** via `_shortest_ai(None)`, because the indefinite-tstr row's item is
  *nested inside a map* — the map passes the narrowed guard, recursion reaches the tstr, and
  `arg=None` flows on. The implementer verified this by execution, documented the traceback,
  and applied a corrected variant that delivered the three clean per-row failures the ruling
  actually intended. **My ruling was right about the goal and wrong about the mechanics.**
- **Ruling 9 CORRECTION.** My dispatch told the implementer the new Rust arm needed
  `.map(|b| b.expose().to_vec())` "unlike the neighbouring `manifest_file` arm". **Wrong
  twice**, verified by reading `differential_replay.rs` myself: the dispatch returns
  `Result<SecretBytes, String>`, so (a) `.expose().to_vec()` is a **type error** there, and
  (b) it would have copied decrypted manifest plaintext into a plain `Vec<u8>`, **defeating
  the zeroize-on-drop wrapper** — a memory-hygiene regression in a repo where that is a
  first-class concern. `manifest_file` needs `.map(SecretBytes::new)` because
  `encode_manifest_file` returns `Vec<u8>`; `manifest_body` needs no wrap because
  `encode_manifest` already returns `SecretBytes`. The implementer's correction is strictly
  better and its source comment explains why.

### Deferred minors — surfaced and consciously left (one since closed)

Every one of these was raised in review and left on purpose. **None is cosmetic-by-default;
read the reason before dismissing one.** Each row carries the **final review's triage
verdict**, so a reader can tell what was re-examined at the end from what was recorded once
and never revisited — and one row is no longer deferred at all, closed as a side effect of
finding B.

| # | Item | Why deferred | Final-review verdict |
|---|---|---|---|
| T1 | The brief's step-2 "watch it fail" was folded into step 6's mutation rather than run as a discrete step | Implementer disclosed it; reviewer judged it substantively harmless — three independent asserts over the same 256-sample loop, and the step-6 mutation is exactly what the brief specifies | **ship** |
| T2 | `_check_canonical_item`'s major-7 branch does not check that the one-byte simple-value form (`ai=24`) is used only for values ≥ 32, so a redundant encoding of an in-range simple value passes rule 3 | No live producer | **CLOSED by finding B** — restricting major 7 to `ai in (20, 21, 22)` rejects the extended form outright, which subsumes this. `F8 14` is now a pinned reject row |
| T2 | No recursion-depth guard — pathological nesting raises Python's `RecursionError`, not `ValueError` | Fail-closed (raises rather than hanging or mis-scanning); inconsistent error **typing** only | **ship** |
| T2 | Finding 2's `_decode_head` change makes `_scan_item`'s own major-6 indefinite-tag check (`raise ValueError(f"indefinite-length tag at offset {pos}")`, inside `_scan_item`) unreachable dead code | The item is still rejected, just via an earlier `ValueError` with a different message, and no test asserts on that message | **ship, now documented** — finding E marks it unreachable-and-kept-for-defence-in-depth. Deliberately **not** deleted |
| T3 | `encode_canonical_map_raw` omits the `n >= 2^32` map-header case (`0xBB` + 8-byte length) | Unreachable for any real manifest | **ship** |
| T3 | No unit row directly exercises `TrashEntry`'s own required-field rejection, nor the strict-subshape duplicate-key path | Correctness confirmed by the re-reviewer's direct execution, but the **corpus** has a coverage gap | **ship** — a coverage gap, not a divergence |
| T3 | `py_decode_manifest`'s docstring says duplicate-known-key in `kdf_params`/`vector_clock` is caught "via the re-encode collapse"; it is now caught explicitly and earlier, in `_decode_strict_entry_map` | Doc drift | **ship** |
| T8 | The note's "gets no enforcement from the §4.3 step 4 re-encode AND MUST check rules 2/3/4" reads as consequence, whereas `vault-format.md:344` says rule 4 is never the re-encode for **any** reader | The phrasing mirrors §4.3 step 4 verbatim, so it is consistent with the document as written. **Recorded so a later editor does not "correct" it into a divergence.** | **ship — do NOT "fix"** |
| T9 | The eight conformance sections added by this slice print **nothing** on success, unlike the older sections which print a `PASS` line per row | Not a defect — each returns `(ok, issues)` and every `ok` flag is in the final conjunction, verified by reading `main()`. But a reader of the output cannot tell the eight ran. Named as constraint 4 in **#593** | **ship** |
| fix wave | The 21-row cross-language corpus was **not** extended with the invalid-UTF-8 / major-7 rows | A new row means regenerating `manifest_canonicality_kat.json` from Rust ground truth, outside the fix wave's scope; the scanner-unit rows are the pin instead | **ship** — the narrower claim is stated in §(2) rather than papered over |

### Standing risks this slice does not remove

- **`conformance.py` is now 6849 lines** (from 4303; 6107 at `43b5a4d5`, 6187 after the
  first fix wave, the rest from the PR-review wave). The clean-room verifier's value is
  proportional to how credibly a human can read it, and this slice has now made it 59%
  longer than the issue that asked for it to be split. **#593**, and the final review's
  ship judgement is **conditional on it** — see §(3)(a).
- **A live Rust/Python acceptance-set divergence ships open**: the three manifest uniqueness
  invariants are enforced by Rust, stated nowhere in `docs/`, and accepted by the Python
  reader. **#594**, §(3)(b). Every other divergence this slice found was closed; this one is
  documented because closing it needs a frozen-spec edit that is its own review.
- **Five of the six PEP 723 deps stay unbounded** (`cryptography`, `pynacl`, `argon2-cffi`,
  `blake3`, `cbor2`), and `ed25519_verify` still has the "no exception means success" shape
  `ml_dsa_65_verify` had — with `cryptography`'s `Ed25519PublicKey.verify` the failure
  direction would be fail-**open**. **#544** / **#550**. Untouched here.
- **The `clean-room conformance` CI job is not in `main`'s `protect_main` ruleset**, so it
  runs without blocking. Unchanged by this slice.
- **The frozen-spec edits are reversible and change no byte on disk**, but they are edits to
  a frozen document: `docs/vault-format.md` §4.2 (this slice: `1674573b` plus T9's
  three-line anchor fix) and `docs/crypto-design.md` §6.2 (`1674573b`, one line).

---

## (5) How to resume — the exact commands

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-canonicality-pin
pwd && git branch --show-current && git worktree list   # expect feature/manifest-canonicality-pin

# --- the full gate set ---
cargo fmt --all --check
cargo build --release --workspace                       # separate from the test run ON PURPOSE
cargo test  --release --workspace
cargo clippy --release --workspace --tests -- -D warnings
touch core/src/lib.rs   # rustdoc caches; a ~5s run did nothing
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
uv run core/tests/python/conformance.py

# --- the two gates NO CI job covers ---
cargo check --release --features differential-replay --tests -p secretary-core
cargo test  --release --workspace --features differential-replay
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

# --- citation freshness: baseline is 90, member set identical to main's ---
uv run core/tests/python/spec_test_name_freshness.py

# --- format / fixture invariants ---
git diff main...HEAD --stat -- core/tests/data/                    # exactly ONE added path, zero modified
git diff main...HEAD -- ffi/secretary-ffi-uniffi/src/secretary.udl # EMPTY
```

Regenerating the corpus after an intentional protocol change (the diff is human-reviewed
before commit; it also rewrites `core/fuzz/seeds/manifest_body/`):

```bash
cargo test --release --workspace -- --ignored generate_manifest_canonicality_kat --nocapture
```

---

## (6) Where this document lives

`NEXT_SESSION.md` at the repo root is a **symlink**, retargeted at `43b5a4d5` to
`docs/handoffs/2026-08-31-manifest-canonicality-pin-shipped.md` and unchanged since. This
file is the single authored baton — do not create a second copy at the root, and do not sync
it to `main` during a pause window (that produces an add/add conflict). The slice's full
task-by-task record, including every review round and the "cost if wrong" for each ruling
above, is at `.superpowers/sdd/2026-08-31-manifest-canonicality-pin/progress.md`; the fix
wave's per-finding report, mutation transcripts included, is at
`final-fix-report.md` in the same directory. Both are untracked by design — this baton is
the part that rides inside the PR.
