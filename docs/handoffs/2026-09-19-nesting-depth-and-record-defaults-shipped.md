# NEXT_SESSION.md — the last two known acceptance divergences are closed (#667, #670)

Branch `feature/nesting-depth-and-record-defaults`, worktree
`.worktrees/nesting-depth-defaults`, base `db6b1f5b` (`main`, immediately after
PR #679 merged).

**STATUS: implementation, measurement and docs are done; the whole-branch
review is PENDING.** Task 9 of the plan (review → one-commit-per-finding fix
wave → PR) has not run yet. §(5b) is a placeholder the fix wave fills in. Until
it does, every claim below is the implementers' and the per-task reviewers',
not a whole-branch reviewer's.

**The headline:** `conformance.py` accepted two classes of body the Rust
decoders reject. The first was a `record` **or** `manifest_body` nested past
256 levels; #667 named only the record path. The second was a record optional
key present at its default value (#670). No committed or corpus input reached
either, which is why the differential replay reported full agreement
throughout. Both were **spec silences, not bugs**, so each was ruled in
`docs/` first:

- **crypto-design §6.2 rule 6:** nesting depth ≤ 256.
- **vault-format §6.3:** a default is written by omission.

Both rulings are what Rust already did, so **no Rust verdict moved**. Python
now agrees, and 10 committed seeds make CI compare both decoders on both rules.

**Issues this slice touched:**

- **Closed in code:** [#667](https://github.com/hherb/secretary/issues/667) and
  [#670](https://github.com/hherb/secretary/issues/670), each with a comment
  naming its seeds and sections. Per the `(#N)`-not-`Closes #N` convention,
  both stay open on the tracker until a human closes them.
- **Commented:** [#666](https://github.com/hherb/secretary/issues/666) (the
  manifest-path bignum edge, measured) and
  [#641](https://github.com/hherb/secretary/issues/641) (`contact_card` must
  put depth first).
- **Filed:**
  - [#681](https://github.com/hherb/secretary/issues/681): rule 6's writer half
    is unenforced.
  - [#682](https://github.com/hherb/secretary/issues/682): `main()` has no
    per-section exception guard.
  - [#683](https://github.com/hherb/secretary/issues/683): two Section VT
    modules are past 500 lines. Found while re-measuring CLAUDE.md, whose
    ranking was stale on `main`.

---

## (0) Starting state

- `origin/main` was at `db6b1f5b`; `main..origin/main` was empty (re-checked
  with `git fetch origin` while writing this baton). No open PRs.
- `.worktrees/` holds stale checkouts from merged branches (`bool-as-integer`,
  `npm-dev-advisories`, `setup-android-tools`, `token-compare-record-block`).
  There are also two detached `.claude/worktrees/*` belonging to other
  sessions. All were left alone.

---

## (1) What shipped

| SHA | What |
|---|---|
| `f501dac5` | design spec: the measurements, rulings D1–D5, and what the slice does not do |
| `8b006d6b` | implementation plan (9 tasks) |
| `084c8730` | **spec**: crypto-design §6.2 rule 6; vault-format §4.2 (depth in the well-formedness precondition) and §6.3 (default omission); rule-6 wording corrected in the design spec |
| `aa1fd34e` | #670 end to end: 3 seeds, `py_encode_record` omits defaults, Section **RDO** |
| `fcad10ea` | RDO reports an unexpected exception as an issue, not a traceback (review fix) |
| `c63b9489` | Rust: the record byte walk refuses the 257th level itself (`open_level`) |
| `08e6a1c9` | Python: one traversal `_walk`, two entry points (`walk_body`, `reject_excessive_nesting`); Section WF twin rows |
| `ff595aec` | every `conformance_lib` CBOR decoder refuses nesting past 256 before it recurses; Section **NDL** checks 1–5 |
| `c1d461de` | NDL's PASS lines count what RAN; checks 3/4 select decoders by name (review fix) |
| `0ed2ae27` | 7 `nesting__` seeds + `nesting_depth_seeds.rs` + the ciborium path pin; NDL check 6; floors |
| `d74e124a` | CLAUDE.md and ROADMAP |
| (this commit) | this baton + `NEXT_SESSION.md` retarget |

Seven of the ten commits before `d74e124a` carry a `Claude Sonnet 5` trailer
(the model that wrote them). That is accurate attribution, and the squash
merge normalises it.

### (1a) What was measured before anything was designed

A throwaway probe crate ran the real Rust decoders, and
`diff_replay.replay_bytes` ran the Python ones. Design spec §1 has the full
table. The two facts that shaped the design:

- **Rust's boundary is exactly 256 accepted / 257 rejected on both paths.**
  That is ciborium 0.2.2's default `recurse: 256`, which charges one level per
  array, map and tag. The exception is a bignum tag (2/3) over at most 16
  bytes, which it folds to an integer without recursing.
- **Python was wrong in two ways.**
  - `record`: it accepted through depth 995 and raised `RecursionError` at
    2000.
  - `manifest_body`: it accepted 257–993 and raised `RecursionError` from 995.
    That target is token-compared and CI-replayed, and #667 never named it.
  - Both `RecursionError`s came from the recursive `scanner._scan_item`.
    `walk_body` was already iterative.

### (1b) The rulings

| # | Decision | Chosen |
|---|---|---|
| D1 | #670 | **Absent is the only canonical spelling of a default**: writers MUST omit, readers MUST reject the present form. This is what Rust has done since v1. |
| D2 | #667 | **A normative v1 nesting limit of 256 for every canonical-CBOR document.** It narrows nothing a shipped reader accepts, and it bounds parser stack on attacker-writable input (contact cards). |
| D3 | shape | Depth checked inside both walks, plus a depth-only first pass for Python's other CBOR decoders. Not #666's full manifest walk, which would move tokens on a frozen decoder. |
| D4 | pins | Label-bound committed seeds with **both** verdicts at the boundary. A limit set too LOW is as wrong as none. |
| D5 | #670 mechanism | `py_encode_record` omits the defaults, and the existing re-encode comparison rejects. Rust's rejection IS its re-encode comparison. |

**The approved rule-6 wording was one level too strict, and was corrected
before any code took it** (`084c8730`). It counted the innermost item as a
level, which put a scalar inside 256 nested arrays at level 257, stricter than
every shipped reader and than the design's own measured accept at 256. The
normative text now says: "A scalar is not a level: an integer inside 256
nested arrays is within the limit, and a 257th array around it is not." A tag
IS a level although rule 4 forbids tags, so a body breaking both rules is
reported alike. Unlike rules 1 and 5, rule 6 binds inside forward-compat
unknown subtrees.

### (1c) Rust

- `pub const secretary_core::cbor::V1_MAX_NESTING_DEPTH: usize = 256`.
- **The record walk answers first.**
  - `cbor/well_formed.rs`'s `open_level` refuses to push a 257th frame,
    returning `CborDecode(CborFault { kind: RecursionLimit, offset: Some(pos)
    })`. Token `malformed_cbor`, unchanged.
  - Excess depth now outranks an earlier tag the walk would have reported as
    rule 4 (`excess_depth_outranks_an_earlier_tag_in_a_record`).
- **ciborium's equal limit is pinned.**
  `core/tests/nesting_depth_seeds.rs::ciborium_enforces_exactly_the_v1_limit_on_every_decode_path`
  requires depth 256 not to be refused for depth, and 257 to be refused with
  `RecursionLimit`. It covers `decode_manifest`, `block::decode_plaintext`,
  `ContactCard::from_canonical_cbor`, `IdentityBundle::from_canonical_cbor`
  and `record::decode`. It passed on its first run, before any seed existed:
  the live proof that ciborium's limit IS the spec's.
- No error enum, public signature, FFI mapping or rule token changed.

### (1d) Python

- **One traversal, two entry points.** `codec/well_formed.py`'s
  `_walk(buf, pos, *, check_content)` is reached through two functions:
  - `walk_body`, with content checks on, for the record;
  - `reject_excessive_nesting`, with content checks off.
- **`reject_excessive_nesting` is content-blind and silent at non-depth
  faults.** It re-raises only `NestingTooDeep` (a `MalformedCbor` subclass,
  token `malformed_cbor`). At a truncation or bad chunk it returns, leaving
  that fault to the decoder's own phases, which scan in byte order and so meet
  it first.
- **It is the first statement of `py_decode_manifest`, `py_decode_contact_card`
  and `py_decode_trash_entry`.** `py_decode_record` needs nothing new, since
  `walk_body` already enforces the limit.
- **#670:** `py_encode_record` omits `tags: []`, `tombstone: False` and
  `tombstoned_at_ms: 0`, mirroring `record_to_canonical`. `py_decode_record`'s
  existing re-encode comparison then rejects a present default as
  `RecordNonCanonical` (`non_canonical_unclassified`), at Rust's phase with
  Rust's token.
- **Section NDL** (`sections/nesting_depth.py`, 457 lines):
  1. boundary per decoder;
  2. a verdict at 257 / 1,000 / 10,000;
  3. tags are levels;
  4. depth outranks a shallow tag, plus the pass's silence control;
  5. a default-deny census of every top-level `codec/*.py` `py_decode_*`;
  6. the committed seeds, two-way.
- **Section RDO** (`sections/record_defaults.py`):
  1. each present default rejected;
  2. 4 controls accepted;
  3. 6 writer cases.
- **Both sections report what they RAN.** NDL's PASS lines append
  "`executed of N declared`" when a guard skipped cases.

### (1e) Committed seeds, and the corpus they moved

- **#670, 3 rows** in `rule_token_seeds.rs`, generated BEFORE the Python fix
  so the replay and RTS were red first:
  `record/non_canonical_unclassified__present_default_{tags,tombstone,tombstoned_at_ms}.bin`.
- **#667, 7 rows** from the new generator `core/tests/nesting_depth_seeds.rs`
  (helpers in `nesting_depth_seeds_helpers/`):
  - `record/nesting__{256_unknown,257_unknown,257_known_tags,2048_unknown}.bin`;
  - `manifest_body/nesting__{256_unknown,257_unknown,2048_unknown}.bin`.
- `rule_token_seeds`' census excludes the `nesting__` prefix through one shared
  constant: `nesting_depth_seeds_helpers/prefix.rs`, compiled into both test
  binaries via `#[path]`, and mirrored as `NESTING_SEED_PREFIX`.

| Figure | Before | After | Measured with |
|---|---|---|---|
| committed replay inputs | 121 | **131** | `ls core/fuzz/seeds/*/* core/tests/data/diff_regressions/*/* \| grep -v gitkeep \| wc -l` |
| `MIN_CORPUS_INPUTS` `record` | 37 | **44** | `targets.rs` |
| `MIN_CORPUS_INPUTS` `manifest_body` | 45 | **48** | `targets.rs` |
| `manifest_body` inputs reaching a STRICT token comparison | 13 of 45 | **15 of 48** | scratch probe: `decode_manifest(..).rule_token()` + `replay_bytes`, per seed |
| RTV `_CORPUS_TOKENS` | 8 | **9** (`malformed_cbor`) | RTV `PASS 3` |
| REG | 33/33 | **35/35** | `conformance.py` |
| `conformance_lib` files | 75 | **78** | `find … -name '*.py' \| wc -l` |

The strict count: of the 32 rejecting bodies in `core/fuzz/seeds/manifest_body/`,
**17** answer a phase-dependent token in Rust and are tolerated whatever Python
says: 7 `arraysort__*`, 4 `keyorder__*`, 3 rule-2 and 3 rule-3. The other
**15** are compared strictly: 3 `rule4_float`, 4 `uniq__*`, 6 `valuetype__*`
and the 2 new `nesting__` rejections, since `malformed_cbor` is never tolerated.

### (1f) Measured results (verbatim from Task 7's report)

**Full local corpus.** `core/fuzz/corpus` was symlinked to the main checkout's
runtime corpus, the replay was run, and the link was removed. All seven targets
compared with no disagreement:

```
[differential_replay] vault_toml: 60937 of 60937 input(s) compared, 9 committed, in 22.3s
[differential_replay] record: 7495 of 7495 input(s) compared, 44 committed, in 1.9s
[differential_replay] contact_card: 6398 of 6398 input(s) compared, 4 committed, in 1.7s
[differential_replay] bundle_file: 25 of 25 input(s) compared, 1 committed, in 0.0s
[differential_replay] manifest_file: 10 of 10 input(s) compared, 1 committed, in 0.0s
[differential_replay] manifest_body: 48 of 48 input(s) compared, 48 committed, in 0.0s
[differential_replay] block_file: 141 of 141 input(s) compared, 24 committed, in 0.0s
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 45 filtered out; finished in 27.52s
```

**75,054 inputs, all agreeing.** `git status --short` after `rm core/fuzz/corpus`
was empty.

**What Task 3 moved on the `record` path** (base `db6b1f5b` against the branch,
`record::decode`'s Debug verdict per file, over `core/fuzz/corpus/record` (7451)
plus the branch's `core/fuzz/seeds/record` (44)):

```
$ wc -l $S/variants-base.txt $S/variants-branch.txt
    7495 variants-base.txt
    7495 variants-branch.txt

$ diff variants-base.txt variants-branch.txt | grep -c '^>'
52

$ awk -F'\t' '{print ($2=="ACCEPT")}' variants-base.txt   | sort | uniq -c
7491 0
   4 1

$ awk -F'\t' '{print ($2=="ACCEPT")}' variants-branch.txt | sort | uniq -c
7491 0
   4 1
```

- **Accept counts: identical on both sides (4 ACCEPT / 7491 non-ACCEPT each). 0
  statuses moved.**
- **3** of the 52 diff lines are the committed `nesting__257_known_tags` /
  `nesting__257_unknown` / `nesting__2048_unknown` seeds. They keep
  `CborFault { kind: RecursionLimit, .. }` and move `offset: None` →
  `offset: Some(N)`.
- **49** are runtime corpus inputs whose nesting exceeds 256. They move from
  `CborDecode(CborFault { kind: Io | Syntax, offset: Some(N) })` to
  `CborDecode(CborFault { kind: RecursionLimit, offset: Some(N') })`, under the
  same token, `malformed_cbor`. None moved to or from `TagRejected` or
  `ACCEPT`.

### (1g) Mutation evidence (verbatim from Task 7's report)

`uv run scripts/mutate.py --self-test`: **20/20 checks passed**. The first run
had three rows that were not `RED_AS_EXPECTED`. Each was diagnosed and its ROW
fixed, never the code:

- **N3** (`WRONG_TESTS_RED`): it reds NDL, but Section WF's name never appears
  on a `FAIL:` line. WF's rows are built from the constant, so a +1 widening
  moves none of them. The WF claim was dropped from the row.
- **N4** (`WRONG_TESTS_RED`): the run crashes rather than naming a section; see
  §(2) and #682. The row now declares `expect_red = []`.
- **N8** (`NOT_LIVE`): the probe used `globals()`, but the harness passes the
  module namespace as `eval`'s LOCALS. Changed to `locals()`.

Second run, `MUTATE_EXIT=0`, `git status --short` empty after:

```
| # | Mutation | Gate | Live | Outcome | Reds |
|---|---|---|---|---|---|
| N1 | A limit one lower than ciborium's: the path pin and the 256 accept rows red | `cargo test --release --locked -p secretary-core --test nesting_depth_seeds` | yes (artifact) | RED_AS_EXPECTED | ciborium_enforces_exactly_the_v1_limit_on_every_decode_path, nesting_depth_seeds_are_committed_and_label_bound |
| N2 | The walk's own check is off by one; ciborium would still reject, so only the walk tests see it | `cargo test --release --locked -p secretary-core --lib cbor::well_formed` | yes (artifact) | RED_AS_EXPECTED | one_level_past_the_limit_is_malformed_at_that_level, a_tag_is_a_nesting_level |
| N3 | Python's limit one higher: NDL reds (its boundary/seed checks land exactly on 256/257/258); WF's own tests are not scoped to that exact boundary and stay green under a mere +1 widening -- measured, row edited to drop the WF claim | `uv run core/tests/python/conformance.py` | yes (interpreter) | RED_AS_EXPECTED | CBOR nesting depth: the v1 limit of 256, in every CBOR decoder |
| N4 | The shared traversal loses its container check entirely: conformance.py's main() has no try/except around section.run(), so the first section to walk an unbounded-depth body (rule_token_vocabulary's py_decode_manifest, which runs before NDL/WF in registry order) raises an uncaught RecursionError and crashes the whole script with a traceback -- no FAIL: line for any section is ever printed, including NDL and WF, which never get to run. The gate genuinely goes red (nonzero exit from the uncaught exception), so expect_red is left empty (checked-in behaviour per gate.py: an empty list only requires gate.is_red) rather than naming tests that structurally cannot appear in the output | `uv run core/tests/python/conformance.py` | yes (interpreter) | RED_AS_EXPECTED | — |
| N5 | The manifest pass removed: nesting__257_unknown is accepted by Python, refused by Rust -- the CI-visible catch | `cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay` | yes (interpreter) | RED_AS_EXPECTED | differential_replay_full_corpus |
| N6 | #670 reverted: RDO and RTS red | `uv run core/tests/python/conformance.py` | yes (interpreter) | RED_AS_EXPECTED | record optional keys: a default is written by omission, rule-token seeds are rejected with the rule their file names |
| N7 | #670 reverted, seen by the CI replay through the three committed seeds | `cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay` | yes (interpreter) | RED_AS_EXPECTED | differential_replay_full_corpus |
| N8 | A new codec decoder nobody classified: NDL check 5 reds | `uv run core/tests/python/conformance.py` | yes (interpreter) | RED_AS_EXPECTED | CBOR nesting depth: the v1 limit of 256, in every CBOR decoder |
| N9 | NDL left out of the table: it would run nowhere, and REG must notice | `uv run core/tests/python/conformance.py` | yes (interpreter) | RED_AS_EXPECTED | section registry completeness |
```

**Two corrections to those notes, found while writing this baton (by reading,
not by re-running):**

1. **N3's note** says NDL reds because "its boundary/seed checks land exactly
   on 256/257/258". NDL checks 1–4 are built from the constant exactly as WF's
   rows are, so they move with it. The only absolute check in NDL is **check
   6**, which compares the committed seed NAMES against names spelled from
   the constant. The absolute value 256 is pinned by the committed seeds, and
   in Rust by the path pin, never by a relative row.
2. **N4's note** says NDL **and WF** "never get to run". WF runs BEFORE RTV in
   registry order (measured from `conformance.py`'s section output order), so
   it does run. What is lost is its `FAIL:` line, because `main()` prints
   those only after the loop. The sections that never run are the ones after
   RTV: RC, DET, DRS, RTS, VT, NDL, RDO and REG. #682 states it that way.

### (1h) The gate set (verbatim from Task 7's report)

| Gate | Result |
|---|---|
| `cargo test --release --locked --workspace` | **2216 passed, 0 failed** (102 `test result:` lines, all `ok`, 0 failures anywhere in the log) |
| `cargo clippy --release --locked --workspace --tests -- -D warnings` | clean — `Finished \`release\` profile [optimized] target(s) in 5.13s`, exit 0 |
| `cargo clippy --release --locked -p secretary-core --features differential-replay --tests -- -D warnings` | clean — `Finished \`release\` profile [optimized] target(s) in 4.26s`, exit 0 |
| `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace` | clean — `Finished \`dev\` profile [unoptimized + debuginfo] target(s) in 2.64s`, exit 0 |
| `cargo fmt --all --check` | `FMT-OK`, exit 0 |
| `uv run core/tests/python/conformance.py` | `conformance exit 0` (35/35 sections PASS, incl. `PASS section registry: 35 drivers discovered, 35 registered, ids and banners unique`) |
| `uv run --with pytest python3 -m pytest scripts/mutation_harness -q -k "not C10 and not N4"` | `276 passed, 2 deselected in 14.77s`, exit 0 |
| `bash ffi/scripts/check-lean-binding.sh --self-test` | `self-test ok: matcher flags clap+notify in secretary-cli (positive control)`, exit 0 |
| `bash ffi/scripts/check-lean-binding.sh` | `All 3 binding crates are lean.`, exit 0 |
| `bash ios/scripts/check-public-log-hygiene.sh --self-test` | `self-test OK — 21 positive controls caught, 9 negative controls clean`, exit 0 |
| `bash ios/scripts/check-public-log-hygiene.sh` | `OK — .public renders are gated and no value is hand-rendered into a String`, exit 0 |
| `bash android/scripts/check-log-hygiene.sh --self-test` | `self-test OK — 27 positive controls caught, 14 negative controls clean`, exit 0 |
| `bash android/scripts/check-log-hygiene.sh` | `OK — android.util.Log is confined to the façade and no value is hand-rendered`, exit 0 |
| `bash scripts/check-secret-slot-hygiene.sh --self-test` | `OK (12 positive, 6 negative, 3 allowlist controls, 8 root probes, 7 entry-point controls)`, exit 0 |
| `bash scripts/check-secret-slot-hygiene.sh` | `OK (8 roots scanned, 2 rules, no findings)`, exit 0 |
| `uv run scripts/check-error-payload-hygiene.py --self-test` | `OK (41 positive / 18 negative / 55 bridge positive / 32 bridge negative / 11 wrapper positive / 3 wrapper negative)`, exit 0 |
| `uv run scripts/check-error-payload-hygiene.py` | `error-payload hygiene: OK`, exit 0 |
| `uv run scripts/check-test-support-placement.py --self-test` | `OK (34/34 controls: 26 positive, 8 negative; plus 1 zero-manifest, 1 missing-root, 1 overlapping-root, 3 feature-liveness, 2 empty-root, 3 wiring and 1 label-uniqueness check)`, exit 0 |
| `uv run scripts/check-test-support-placement.py` | `OK (11 manifests scanned)`, exit 0 |

Every gate: 0 failed / clean / exit 0. Task 8 (docs only) re-ran
`conformance.py`: exit 0, no `FAIL`, REG 35/35. It did not re-run the Rust
gates, because no source file changed.

---

## (2) What this slice does **not** claim — read this first

- **Rule 6's writer half is enforced by no encoder, in either language
  ([#681](https://github.com/hherb/secretary/issues/681)).**
  - No production path can emit a longer chain from decoded input: a decoded
    subtree has been limit-checked, and every re-emission puts it back at the
    same depth relative to the same root. That is an argument from reading,
    not a census.
  - An `UnknownValue` built in memory can still be deeper. That is the
    #586/#600 writer-half shape.
  - #681's acceptance names the trap to avoid: a NEW encode variant, so the
    writer check cannot backstop the reader's (#587's measured lesson).
- **The manifest-path bignum edge is open, and #666 owns it.** ciborium does
  not charge a level for a bignum tag over ≤16 bytes. Measured while writing
  this baton (scratch probe, both decoders, on `uniq__control__all_distinct.bin`
  plus one unknown key):
  - a short bignum at level **257** is `non_canonical_unclassified` in Rust
    and `malformed_cbor` (`NestingTooDeep`) in Python. That pair is never
    tolerated;
  - an ordinary tag at 257 is `malformed_cbor` in both;
  - no input reaches the bignum case. The path pin's all-array bodies cannot
    see it. Wiring the walk into `decode_manifest` closes it.
- **Removing the Python depth check crashes `conformance.py` instead of
  redding a section ([#682](https://github.com/hherb/secretary/issues/682)).**
  With N4 applied, Section RTV's `py_decode_manifest` over the committed
  `manifest_body/nesting__2048_unknown.bin` raises `RecursionError` through
  the recursive `_scan_item`. `main()` (`conformance.py:136-152`) has no
  per-section guard. The result is fail-closed (exit 1) but unnamed:
  - no `FAIL:` line is printed for any section;
  - every section after RTV, REG included, never runs.

  This is a pre-existing `main()` property, filed rather than widening this
  slice (ruling below).
- **The absolute value 256 is pinned by the committed seeds and the Rust path
  pin, NOT by Section WF.** Mutation N3 measured that WF's rows move with the
  constant. The same is true of NDL checks 1–4.
- **`contact_card` is still not token-compared (#641).** When it is, depth
  must come first. Rust gives `CborDecode(RecursionLimit)` and Python
  `NestingTooDeep`, both `malformed_cbor`, and Python's card decoder already
  opens with `reject_excessive_nesting`. No `contact_card` nesting seed is
  committed; the card's depth behaviour agrees by VERDICT only.
- **Python's block-plaintext reading stays inspection-only**
  (`wire/golden_vault_verify.py`): no strict decoder exists to guard. The four
  ciborium leniencies on the manifest and block paths (#666), and every report
  order §6.1/§6.3 leaves open (#668), are untouched.
- **Not a proof of absence.**
  - The #670 class was established **by reading every encoder**: `block.rs`'s
    plaintext encoder and `identity/card.rs` omit no default, and the
    manifest's two optional `TrashEntry` keys are `Option`-typed and pushed
    whenever `Some`.
  - The design spec (§1.2) promised the plan would confirm the manifest half
    by execution, and **the plan never did**. It was confirmed while writing
    this baton: a present `purged_at_ms: 0`, and separately a 32-zero-byte
    `fingerprint`, on every trash entry of `uniq__control__all_distinct.bin`
    are ACCEPTED by both decoders.
  - The depth measurements cover the three CBOR replay targets at the depths
    in design spec §1.1 only.
- **On the record path, 49 corpus inputs changed reported fault KIND**
  (`Io`/`Syntax` → `RecursionLimit`). Zero changed verdict or token. Anyone
  diffing `Debug` output across this merge will see those 49 move, and that is
  expected.

---

## (3) What is next — with acceptance criteria

### (3a) Acceptance and comparison coverage

- **[#677](https://github.com/hherb/secretary/issues/677): sweep `bundle_file`
  and `manifest_file`.** They are binary envelopes read by offset, so the
  value-substitution sweep does not apply. **Acceptance:** an offset-based
  corruption sweep, one body per (field, corruption) from each committed
  base, both decoders compared, and every divergence fixed or filed. Commit
  the sweep as a re-runnable generator; the #669 sweep was not.
- **[#641](https://github.com/hherb/secretary/issues/641): token-compare the
  remaining targets, `contact_card` FIRST.** It now has committed rejecting
  inputs (#669's `valuetype__` seeds) and a documented depth rule.
  **Acceptance for `contact_card`:**
  - a Python token per card rejection class;
  - `CardError` → `RuleToken` total, with `CborDecode(_)` → `malformed_cbor`;
  - depth first on both sides (the #641 comment);
  - a `contact_card/nesting__257_*` seed from `nesting_depth_seeds.rs`;
  - `PHASE_DEPENDENT_TOLERANCE_TARGETS` unchanged, so the comparison is strict
    with 0 tolerated pairs.

  Then `bundle_file`, `vault_toml` and `manifest_file` (blocked on #640).
- **[#666](https://github.com/hherb/secretary/issues/666): wire the
  well-formedness walk into `decode_manifest` and block-plaintext decode, in
  both languages.** **Acceptance:**
  - the issue's own criteria;
  - a `manifest_body` seed whose 257th level is a short bignum, answering
    `malformed_cbor` in both languages. That closes the edge measured in §(2).
- **[#678](https://github.com/hherb/secretary/issues/678): the required-key
  half of Section VT's check 4.** Solve the interleaving rather than flatten
  it. The issue carries the measurements.

### (3b) Spec decisions

- **[#668](https://github.com/hherb/secretary/issues/668): report-order text
  for vault-format §6.1 and §6.3.** On `record`, this slice's depth-first
  order is parity, not spec. **[#646](https://github.com/hherb/secretary/issues/646):**
  narrowing the per-token tolerance needs §4.2 to settle groups C and D first.

### (3c) New from this slice

- **[#681](https://github.com/hherb/secretary/issues/681): rule 6's writer
  half.** **Acceptance:**
  - an encode-side depth check at every canonical-CBOR writer rule 6 binds,
    walking `Borrowed` unknown subtrees (rule 6 is not scoped to interpreted
    material);
  - a NEW encode variant;
  - the Python twin with `ENCODER_REFUSAL_PREFIX`;
  - a 257-level in-memory value refused and a 256 one accepted;
  - mutation evidence that each reader check still reds with the writer check
    present.
- **[#682](https://github.com/hherb/secretary/issues/682): a per-section guard
  in `conformance.py`'s `main()`.** **Acceptance:**
  - re-run N4: a `FAIL:` line names RTV and `RecursionError`, and later
    sections and REG still run;
  - the N4 row can then name sections instead of `expect_red = []`;
  - a control that shows the guard is live.
- **[#683](https://github.com/hherb/secretary/issues/683): split
  `sections/value_type_discipline.py` (658) and `value_type_structure.py`
  (507).** **Acceptance:** Section VT's output is byte-identical before and
  after, and REG is unchanged.

### (3d) Standing polish

- **[#657](https://github.com/hherb/secretary/issues/657):** nothing pins that
  the CI replay step stays wired.
- **[#612](https://github.com/hherb/secretary/issues/612):**
  `manifest_uniqueness_kat.rs` is past 500 lines.
- **[#660](https://github.com/hherb/secretary/issues/660):** `conformance.py`
  silently ignores an unrecognised flag.
- **[#671](https://github.com/hherb/secretary/issues/671):** #641's residual
  nits.
- **[#672](https://github.com/hherb/secretary/issues/672):** session-process
  words in shipped source. **This slice adds more:** NDL's docstrings say
  "controller ruling".
- **[#676](https://github.com/hherb/secretary/issues/676):** type-level
  replay-target and seed-table invariants.

---

## (4) Open decisions and risks

- **The whole-branch review has NOT run.** The per-task reviews were scoped to
  one task each and cannot see cross-task interactions (memory: "differential
  review for guard changes"). Budget for findings.
- **Stale corpus figures in SOURCE comments.** This slice moved them, and
  Task 8 was scoped to docs, so they are left for the fix wave:

  | File | Says | Should say |
  |---|---|---|
  | `core/src/vault/manifest/token.rs:220-224` | 44 bodies, 30 rejected, 17 of those 30, 13 reach a real comparison | 47 bodies, 32 rejected, 17 of 32, 15 |
  | `core/tests/differential_replay_helpers/tolerance.rs:28-30` | 17 of the 30 | 17 of the 32 |
  | `core/tests/differential_replay_helpers/python_bridge.rs:20-22` | 30 of the 44 (20 + 4 + 6) | 32 of the 47 (20 + 4 + 6 + 2 nesting) |
  | `conformance_lib/diff_replay.py` docstring | 24 of the 38 | 32 of the 47 (already stale since #669) |

  The rejection breakdown was measured per seed while writing this baton.
- **`sections/nesting_depth.py` is 457 lines**, 91% of the split threshold.
  The next check added to it should split it.
- **RTV's `_CORPUS_TOKENS` and the seed set move together.** A new committed
  `manifest_body` seed reaching a new token needs that set edited; RTV's
  failure message asks for it by name.
- **`.gitignore`'s `corpus/` rule matches directories only**, so a
  `core/fuzz/corpus` symlink shows as untracked. Remove it after each run.

### (4a) Rulings made during the slice (from the ledger), each with its cost if wrong

1. **The nesting seed helpers carry their own ~25-line `entries` / `map` /
   `with_top_level_entry`** rather than sharing
   `rule_token_seeds_helpers/record/surgery.rs`. They are separate
   integration-test binaries, and the record surgery is record-specific.
   *Cost if wrong:* a small duplicated helper a reviewer may flag; the fix
   would be a `#[path]`-shared module.
2. **Model selection:** implementers on sonnet, task reviewers on sonnet, the
   final whole-branch review on opus. *Cost if wrong:* token spend.
3. **Task 2 review Important:** RDO's `_writer_issues` / `_base_round_trip_issue`
   could traceback out of `main()` and skip REG. This was plan-mandated code,
   and it was fixed anyway, because CLAUDE.md records this fail-open class as
   fixed elsewhere (`fcad10ea`). *Cost if wrong:* a few lines of defensive
   code.
4. **The same guard requirement was carried into Task 5**, since NDL loads
   fixtures outside a `try`. *Cost if wrong:* none.
5. **Task 6's check 6 adopts Task 5's `_CheckResult` / executed-count
   pattern** and guarded file reads instead of the brief's `(issues, count)`
   shape, because the section's own contract changed in Task 5's fix round.
   *Cost if wrong:* none.
6. **N4's measurement** (removing the Python depth check crashes
   `conformance.py` through Section RTV) **is a PRE-EXISTING `main()`
   property.** It is fail-closed, so it was filed as #682 rather than widening
   this slice. *Cost if wrong:* a regression in the depth pass shows as a
   crash without a named `FAIL:` line.

### (4b) Deferred minors from the ledger: NOT yet triaged by the final review

- **Task 1:** the design spec §3.1 blockquote's last sentence duplicates the
  "Note on scope" paragraph below it. The ledger said to fold it during the
  docs pass or the final review. Task 8's commit scope excluded the spec, so
  it is left for the final review.
- **Task 2:** RDO re-reads and re-parses `login.cbor` up to about 8 times per
  run; it could be hoisted once per section call.
- **Task 2:** RDO `_writer_issues`' whole-body `try` discards per-key issues
  already collected when an exception fires. Its `PASS 3` count is then not a
  per-case tally, although `ok` is still `False`.
- **Task 5:** NDL's census uses a NON-recursive `codec/*.py` glob, while
  Section VT uses `rglob` with a documented rationale. NDL's LIMITS block does
  not disclose the difference.
- **Task 5:** the census's file-parse guard (the `ast.parse` failure branch of
  `_census_line`) is verified by inspection only, never by a live
  demonstration.
- **Task 6:** `nesting_depth_seeds_helpers::with_top_level_entry` is `pub` but
  used only inside the helper.
- **Task 6:** `sections/nesting_depth.py` is 457 lines (above).
- **Closed, no action:**
  - Task 3's report lacked raw all-targets output; the reviewer ran it,
    53/53 binaries ok.
  - Task 4's docstring named callers before Task 5 wired them; they now exist.

---

## (5) How to resume — the exact commands

```bash
# FIRST — it has fired on two of the last four slices:
git fetch origin && git log --oneline main..origin/main

cd /Users/hherb/src/secretary/.worktrees/nesting-depth-defaults
pwd && git branch --show-current && git worktree list    # feature/nesting-depth-and-record-defaults

# --- the clean-room verifier (NDL and RDO are the new sections) ---
uv run core/tests/python/conformance.py
#   0 FAIL; NDL 8/8, 12/12, 4/4, 5/5, 8 censused, 7/7; RDO 3/3, 4/4, 6/6;
#   RTV "9 distinct tokens"; REG 35/35

# --- the replay, CI shape ---
cargo test --release --locked -p secretary-core \
  --features differential-replay --test differential_replay      # 46 passed; record 44 of 44, manifest_body 48 of 48

# --- the replay over the real fuzz corpus; REMOVE the link afterwards ---
test ! -e core/fuzz/corpus && ln -s /Users/hherb/src/secretary/core/fuzz/corpus core/fuzz/corpus
cargo test --release --locked -p secretary-core \
  --features differential-replay --test differential_replay -- differential_replay_full_corpus
rm core/fuzz/corpus && git status --short                        # no corpus entry

# --- the two seed generators (each asserts every row BEFORE writing any file) ---
cargo test --release --locked -p secretary-core --test nesting_depth_seeds -- --ignored generate_nesting_depth_seeds
cargo test --release --locked -p secretary-core --test nesting_depth_seeds       # 6 passed, 1 ignored
cargo test --release --locked -p secretary-core --test rule_token_seeds -- --ignored generate_rule_token_seeds
cargo test --release --locked -p secretary-core --test rule_token_seeds          # 3 passed, 1 ignored
git status --short                                                               # regenerated seeds must be byte-identical

# --- prove the new gates are not decorative (spec to the SCRATCHPAD, never the tree) ---
uv run scripts/mutate.py --self-test                                 # 20/20
uv run --with cryptography --with pynacl --with "pqcrypto<1" \
  --with argon2-cffi --with blake3 --with cbor2 scripts/mutate.py "$SCRATCH/ndl.toml"
git status --short                                                    # MUST be empty

# --- the rest of the gate set ---
cargo test --release --locked --workspace                             # 2216 passed
cargo clippy --release --locked --workspace --tests -- -D warnings
cargo clippy --release --locked -p secretary-core --features differential-replay --tests -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
cargo fmt --all --check
uv run --with pytest python3 -m pytest scripts/mutation_harness -q -k "not C10 and not N4"   # 276 passed, 2 deselected

# --- six hygiene guards, --self-test FIRST, as LITERAL commands ---
bash ffi/scripts/check-lean-binding.sh --self-test         && bash ffi/scripts/check-lean-binding.sh
bash ios/scripts/check-public-log-hygiene.sh --self-test   && bash ios/scripts/check-public-log-hygiene.sh
bash android/scripts/check-log-hygiene.sh --self-test      && bash android/scripts/check-log-hygiene.sh
bash scripts/check-secret-slot-hygiene.sh --self-test      && bash scripts/check-secret-slot-hygiene.sh
uv run scripts/check-error-payload-hygiene.py --self-test  && uv run scripts/check-error-payload-hygiene.py
uv run scripts/check-test-support-placement.py --self-test && uv run scripts/check-test-support-placement.py
```

**Then Task 9 of the plan:**

1. Re-check `main..origin/main`, and merge if it moved. The branch's copy of
   this document wins a conflict.
2. Run the whole-branch review, verifying every finding by execution in a
   scratch copy, never in this worktree.
3. Fix each finding, one commit per finding.
4. Fill in §(5b).
5. Push and open the PR titled `Normative CBOR nesting limit (#667) and
   record default omission (#670)`.
6. Read the `cargo test (ubuntu-latest)` job's replay finish lines, not just
   the tick: `record: 44 of 44` and `manifest_body: 48 of 48` must appear.

---

## (5b) The whole-branch review — PENDING

*Not yet run. The fix wave appends here:*

- the findings;
- each fix's commit;
- before → after mutation evidence per fix;
- anything filed rather than fixed.

---

## (6) Where this document lives

`NEXT_SESSION.md` at the repo root is a **symlink**. This session retargeted
it to `docs/handoffs/2026-09-19-nesting-depth-and-record-defaults-shipped.md`.
This file is the single authored baton: do not create a second copy, and do
not sync it to `main` during a pause window.
