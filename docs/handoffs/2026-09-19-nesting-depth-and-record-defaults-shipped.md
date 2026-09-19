# NEXT_SESSION.md — the last two known acceptance divergences are closed (#667, #670)

Branch `feature/nesting-depth-and-record-defaults`, worktree
`.worktrees/nesting-depth-defaults`, base `db6b1f5b` (`main`, immediately after
PR #679 merged).

**STATUS: implementation, measurement, docs, the whole-branch review and its
fix wave are done; push and PR remain.** The review found 0 Critical and 3
Important findings; all three and the triaged minors are fixed, and §(5b)
records each with its commit and its evidence.

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
  manifest-path bignum edge, measured; a second comment corrects the Rust
  token for 9-16-byte bignums, §(2)) and
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
| `e2b96a15` | this baton + `NEXT_SESSION.md` retarget |
| `053e22bd` … this commit | the review fix wave, plus a second re-review pass across `38427086` and this commit; §(5b) lists them |

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
  bytes, which it reads without recursing: as an integer when the value fits
  64 bits, otherwise as a `Value::Tag` (§(2)).
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
IS a level although rule 4 forbids tags, so that a body breaking both rules is
reported alike by every conformant reader; the reference manifest path does
not yet do so for a short bignum (§(2), #666). Unlike rules 1 and 5, rule 6
binds inside forward-compat unknown subtrees.

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
- **Section NDL** (`sections/nesting_depth.py`, 446 lines after the fix wave,
  457 before):
  1. boundary per decoder;
  2. a verdict at 257 / 1,000 / 10,000;
  3. tags are levels;
  4. depth outranks a shallow tag, plus the pass's silence control;
  5. a default-deny census of every top-level `py_decode_*` in
     `codec/**/*.py` (recursive since the fix wave; `codec/*.py` before);
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
  `ACCEPT`. The base-side faults were the pre-#667 WALK's own (a truncation
  or bad head later in byte order than the 257th level), not ciborium's, as
  Task 7's report said: ciborium's `Io` always carries `offset: None`
  (`classify_de`), and these carried `Some(N)`, so ciborium never ran on
  them (the whole-branch review's correction).

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
  this baton, and corrected by the whole-branch review, which measured a
  9-byte bignum (scratch probe, both decoders, on
  `uniq__control__all_distinct.bin` plus one unknown key):
  - a bignum at level **257** whose value fits 64 bits (every one of up to 8
    bytes) is `non_canonical_unclassified` in Rust: ciborium folds it to an
    integer and the re-encode differs;
  - a 9-16-byte bignum at level 257, positive or negative, is
    `rule4_tag_or_float` (`Canonical(TagRejected)`) in Rust: ciborium keeps
    a `Value::Tag`. That is a rule-4 report where §4.2 now requires depth.
    This bullet first named `non_canonical_unclassified` for every width;
  - Python says `malformed_cbor` (`NestingTooDeep`) at every width, and a
    pair naming `malformed_cbor` is never tolerated;
  - a 16-byte negative with its top bit set overflows ciborium's `i128`
    (`Semantic`, `malformed_cbor` on both sides); from 17 bytes ciborium
    charges the level; an ordinary tag at 257 is `malformed_cbor` in both;
  - no input reaches the bignum case. The path pin's all-array bodies cannot
    see it. Wiring the walk into `decode_manifest` closes it. The full width
    table is in the second #666 comment.
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
  - `manifest_body` seeds whose 257th level is a short bignum, at **both
    widths**, because they take different ciborium paths: one whose value
    fits 64 bits (e.g. `c2 41 01`, today `non_canonical_unclassified`) and
    one 9-16 bytes wide (e.g. `c2 49 01..01`, today `rule4_tag_or_float`),
    each answering `malformed_cbor` in both languages. That closes the edge
    measured in §(2).
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
  words in shipped source. This slice added some to NDL's docstrings
  ("controller ruling", "Task 4/5", "review finding, fix round 1"); the fix
  wave removed them (`f94e4da1`), so the class is back to #672's own list.
- **[#676](https://github.com/hherb/secretary/issues/676):** type-level
  replay-target and seed-table invariants.

---

## (4) Open decisions and risks

- **The whole-branch review has run** (§(5b)). What it cannot see is what
  no one measured: the depth measurements cover the three CBOR replay targets
  at the depths in design spec §1.1, and the bignum widths in §(2).
- **Stale corpus figures in SOURCE comments were fixed in the fix wave**
  (`8d9510b2`), re-measured per seed with both decoders: 47 bodies, 32
  rejected by both, 17 tolerated, 15 strict. The same commit also corrected
  `docs/manual/contributors/differential-replay-protocol.md`'s "17 of the
  24", stale since #669 and not in this baton's original list.
- **`sections/nesting_depth.py` is 446 lines** after the fix wave, 89% of the
  split threshold. The next check added to it should split it.
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

### (4b) Deferred minors from the ledger, as the final review triaged them

The review's triage: FIX the census glob and NDL's session-process text and
"recursive `walk_body`" error (done, `f94e4da1`); SHIP the rest. The items
below are therefore shipped as they stand unless marked otherwise.

- **Task 1:** the design spec §3.1 blockquote's last sentence duplicates the
  "Note on scope" paragraph below it. Shipped: a redundant sentence in a
  design record, not a normative doc.
- **Task 2:** RDO re-reads and re-parses `login.cbor` up to about 8 times per
  run; it could be hoisted once per section call.
- **Task 2:** RDO `_writer_issues`' whole-body `try` discards per-key issues
  already collected when an exception fires. Its `PASS 3` count is then not a
  per-case tally, although `ok` is still `False`.
- **Task 5, FIXED (`f94e4da1`):** NDL's census used a NON-recursive
  `codec/*.py` glob, while Section VT uses `rglob`. It is recursive now,
  skipping `__pycache__`, and its LIMITS block states the scope.
- **Task 5, DEMONSTRATED (not committed):** the census's file-parse guard
  was verified by inspection only. The fix wave ran it live against scratch
  copies of `codec/`: an unparseable file yields an ISSUE line and
  "(19/20 codec/ files read)", and no traceback.
- **Task 6:** `nesting_depth_seeds_helpers::with_top_level_entry` is `pub` but
  used only inside the helper.
- **Task 6:** `sections/nesting_depth.py` was 457 lines; 446 now (above).
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

**What remains of Task 9 of the plan** (the review and its fix wave are done,
§(5b)):

1. Re-check `main..origin/main`, and merge if it moved. The branch's copy of
   this document wins a conflict.
2. Push and open the PR titled `Normative CBOR nesting limit (#667) and
   record default omission (#670)`.
3. Read the `cargo test (ubuntu-latest)` job's replay finish lines, not just
   the tick: `record: 44 of 44` and `manifest_body: 48 of 48` must appear.

---

## (5b) The whole-branch review and its fix wave

**Result: 0 Critical, 3 Important, minors triaged.** Reviewed on opus over
`db6b1f5b..e2b96a15`. Every Important and every triaged minor is fixed; the
fix wave changed no code behaviour, only normative docs, comments and
docstrings, one census line and its PASS wording.

**Important 1: rule 6 was missing from the §4.2 places that enumerate the
other rules.** Fixed in `053e22bd`.

- vault-format §4.2 ordering 1 scoped "every rule below" to §6.2's numbered
  rules, so read literally rule 4 outranked rule 6, contradicting the
  precondition six lines up. Now "§6.2 rules 1–5 …; rule 6 belongs to this
  precondition, not below it".
- The unknown-subtree table gains a rule-6 row ("yes", by the parse or walk
  that finds item boundaries, subtrees included); the unopenability
  paragraph, part (2) of the two-part requirement, the byte-retention
  paragraph, the implementation note and §6.3.2 name rule 6 beside 2-4. A
  byte-retaining reader that followed the old text skipped depth, which is
  the defect #667 fixed. A normalising parse applies the limit as it builds
  the tree; nothing gets it from the re-encode.
- crypto-design §6.2 rule 5's "vault-format §4.2 states the per-rule split …
  in full" is true again with the rule-6 row; unchanged.
- `spec_test_name_freshness.py`: 99 unresolved on `main` and on the branch,
  the same citation set (pre-existing; this slice adds none).

**Important 2: the bignum edge was wrong for 9-16 bytes.** Fixed in this
commit (CLAUDE.md, ROADMAP, this baton §(1a)/(1b)/(2)/(3a), the design spec
and the plan) and in a second #666 comment
(<https://github.com/hherb/secretary/issues/666#issuecomment-5740367972>).
Re-measured with the real decoders over 9 widths at level 257: value fits
64 bits → `non_canonical_unclassified`; 9-16 bytes, positive or negative →
`rule4_tag_or_float`; a 16-byte negative with its top bit set →
`malformed_cbor` (`Semantic`); 17 bytes → `malformed_cbor`
(`RecursionLimit`). Python: `malformed_cbor` at every width. §(3a)'s #666
acceptance now seeds both widths.

**Important 3: four source comments carried stale corpus figures.** Fixed in
`8d9510b2`, re-measured per seed: 47 bodies, 32 rejected by both, 17
tolerated (7 arraysort, 4 keyorder, 3 rule-2, 3 rule-3), 15 strict (3
rule4_float, 4 uniq, 6 valuetype, 2 nesting). RTV's own `PASS 3` agrees
("32/47 bodies rejected"). `diff_replay.py` also said "the other six
targets" are scored on rejection alone, stale since #641 (it is four). A
fifth copy, the replay protocol memo's "17 of the 24", was corrected in the
same commit.

**Minors fixed:**

| Commit | What |
|---|---|
| `f94e4da1` | NDL: `walk_body` is iterative, not recursive; session-process text removed; census `rglob` minus `__pycache__` (a decoder in `codec/sub/` read "0 unclassified" at HEAD, "1" now; measured on scratch copies); PASS 5 counts classification issues only and names an unread file as "(x/y codec/ files read)"; docstring states the title's "every CBOR decoder" means `codec/`; 457 → 446 lines; real-tree output byte-identical |
| `b5b7c7de` | `well_formed.rs`: depth is its own list item; the Python twin's list names `NestingTooDeep`; `V1_MAX_NESTING_DEPTH`'s "exactly" is about acceptance, with the #666 exception named |
| `053e22bd` | crypto-design rule 6: "enforced exactly this limit since v1, as to which bodies they accept"; vault-format §6.3 schema comments say false and 0 are written by omission |
| this commit | CLAUDE.md: the 49 record inputs' `Io`/`Syntax` faults were the pre-#667 walk's, never ciborium's; "reported alike by every reader" is a requirement the manifest path does not yet meet (#666); NDL's file size and census scope re-measured |

**Filed rather than fixed:** nothing new. The review's other minors were
triaged SHIP (§(4b)).

**A second re-review pass, over this section's own fix wave, found a further
batch of residual minors — all stale quotes or imprecise wording, none
Important.** Fixed across `38427086` and this commit. Every remaining
verbatim quote of the two §4.2/§6.3.2 sentences `053e22bd` changed
(`CLAUDE.md` at three more sites, `manifest_canonicality_cause.py`,
`token.rs`'s group-C bullet) is now current, and the same grep turned up two
the first pass's own scope didn't cover — `ROADMAP.md`'s #604 entry and
`manifest_canonicality_kat.rs`'s corpus doc comment, both still quoting the
pre-#667 wording outside Important 1's four listed sites.
`manifest_decode.py`'s `ArraySortOrderViolation` docstring had the same
stale rule count (five, now six). `vault-format.md`'s "a normalising parse
must apply the limit as it builds the tree" (§4.3, FROZEN NORMATIVE text)
was narrower than its own table-row-6 wording and than the record path's
mechanism, so it is now "must apply the limit itself, in its parse or in a
walk of its own" — nothing else in that paragraph moved. This section's own
Important 2 (and `ROADMAP.md`'s #667 entry) named the 9-16-byte bignum case
as `rule4_tag_or_float` without its second exception: a direct ciborium
0.2.2 probe found that a 9-byte bignum whose leading byte is `0x00` still
decodes to `Value::Integer`, not `Value::Tag`, so byte width alone was not
sufficient. This section's own record-corpus bullet, above, said the 49
moved `Io`/`Syntax`-to-`RecursionLimit` inputs were "not ciborium's" on the
strength of the offset-field observation alone, which covers only the `Io`
ones; it now gives the conclusive reason — `record::decode` runs
`walk_first_item` before the ciborium parse, so ciborium never ran on those
49 inputs at all — and keeps the offset observation as corroboration for
the `Io` subset. `nesting_depth.py`'s census scoped its `__pycache__` filter
to paths relative to `_CODEC_DIR` (it was reading the path's absolute
parts) and reworded its LIMITS citation of `#510`, which is scoped to
`scripts/payload_guard`, not this census. `manifest_decode.py`'s
`py_decode_manifest` docstring now names rule 6 (enforced by
`reject_excessive_nesting`, its first statement) alongside rules 2/3/4 as
what an unknown subtree is checked for. No code behaviour changed except
the census's path-scoping fix, which `conformance.py`'s own NDL PASS 5
(8 censused) shows unaffected on this tree.

**Verification after the fix wave** (the code changes are comments and one
census line, so no mutation row moved; the census change's before → after
evidence is the scratch-copy probe above):

| Gate | Result |
|---|---|
| `uv run core/tests/python/conformance.py` | exit 0, 0 `FAIL`; NDL 8/8, 12/12, 4/4, 5/5, 8 censused, 7/7; RDO 3/3, 4/4, 6/6; RTV 9 distinct tokens; REG 35/35 |
| `cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay` | 46 passed; `record: 44 of 44`, `manifest_body: 48 of 48` |
| `cargo test --release --locked -p secretary-core --lib` | 662 passed, 0 failed |
| `cargo clippy --release --locked --workspace --tests -- -D warnings` | exit 0 |
| `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace` | exit 0 |
| `cargo fmt --all --check` | exit 0 |
| `uv run core/tests/python/spec_test_name_freshness.py` | 99 on `main`, 99 on the branch, same set |

---

## (6) Where this document lives

`NEXT_SESSION.md` at the repo root is a **symlink**. This session retargeted
it to `docs/handoffs/2026-09-19-nesting-depth-and-record-defaults-shipped.md`.
This file is the single authored baton: do not create a second copy, and do
not sync it to `main` during a pause window.
