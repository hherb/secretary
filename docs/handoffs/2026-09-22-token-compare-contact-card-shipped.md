# NEXT_SESSION.md — `contact_card` is token-compared, the fourth differential-replay target (#641, #691)

Branch `feature/token-compare-contact-card`, worktree
`.worktrees/token-compare-card`, base `c98e932d` (`main`).

**STATUS: implementation, docs, mutation evidence and the full gate set are
done. Not pushed and no PR opened — this session was told not to; the
controller runs the whole-branch review first.**

**The headline:** `contact_card` is now the fourth differential-replay
target compared on WHICH rule the Rust and Python decoders name, not just
whether they reject (joining `record`, `block_file`, `manifest_body` from
#634/#641). `#691` had named `codec/card.py` as the last decoder still
running a content-blind depth pass ahead of `cbor2.loads`, deferred because
nothing would measure whether a converted answer agreed with Rust's — this
closes that deferral. `ContactCard::from_canonical_cbor` now runs the same
byte-level well-formedness walk the manifest, block-plaintext and record
decoders already use, ahead of ciborium; `IdentityBundle::from_canonical_cbor`
is now the *sole* remaining ciborium-only recursion-limit path.
`reject_excessive_nesting` — the content-blind pass this replaced — lost its
last caller and was deleted outright.

**Issues this slice touched:**

- **Closed in code:** part of [#641](https://github.com/hherb/secretary/issues/641)
  (contact_card's share; bundle_file and vault_toml remain open under it) and
  [#691](https://github.com/hherb/secretary/issues/691) in full. Per the
  `(#N)`-not-`Closes #N` convention, both stay open on the tracker until a
  human closes them.
- **Filed:**
  - [#692](https://github.com/hherb/secretary/issues/692): Section RTS's
    per-class token check (`_identity_issues`) is silently deletable — the
    PASS-1 count is tied to the declared table's length, not to the
    comparison's execution. Same family as #687 (Section VT's version of
    this shape).
  - [#693](https://github.com/hherb/secretary/issues/693): spec question —
    does `docs/crypto-design.md` §6 fix (or decline to fix) a report order
    among the contact card's rules, the way vault-format §4.2 does for the
    manifest body? The card has no forward-compat `unknown` bag, so a
    single-fault depth or rule-4 seed cannot be constructed for it.
  - [#694](https://github.com/hherb/secretary/issues/694):
    `rule_token_seeds_helpers/mod.rs`'s header prose still names only
    `record`/`block_file` despite declaring `pub mod contact_card;` and
    three `contact_card` match arms.
  - [#695](https://github.com/hherb/secretary/issues/695):
    `card_order_tests.rs`'s depth-257 precedence row's doc comment credits
    the byte-level walk alone, but disabling the walk does not red it —
    `ciborium` 0.2.2's own built-in recursion limit happens to equal the v1
    spec limit (256), so the row is doubly-covered and cannot on its own
    distinguish the two mechanisms. The other three precedence rows in the
    same file DID red when the walk was disabled.

---

## (0) Starting state

`main` was at `c98e932d` at branch creation. Re-check `git fetch origin &&
git log --oneline main..origin/main` before any further edit; if `main`
moved, merge it first, per the fixup-time merge discipline, so this handoff
lands 3-way-mergeable.

---

## (1) What shipped

18 commits from the merge-base (`git log --oneline c98e932d..HEAD`); 15 are
implementation, 3 are the design spec / plan / pre-flight ruling. This
handoff's own commit is a 19th, on top.

| SHA | What |
|---|---|
| `477d7e57` | design spec: the eleven-shape-style analysis for the card, decisions, what the slice does not do |
| `1c65f1ae` | implementation plan (12 tasks) |
| `38fb4919` | pre-flight ruling: split Task 9's negative control across Tasks 9 and 10 (CONFLICT-1 — the committed corpus at Task 9 time cannot reach `unknown_field`) |
| `d4b6fc29` | spec: `docs/crypto-design.md` §6 states the `display_name` 4096-byte bound normatively |
| `439a946b` | core: `CardError` gains `FloatRejected`/`TagRejected` rule-4 arms |
| `1e3bfd9f` | core: scope `canonical_error_to_card_error`'s unreachable-doc claim (fix round) |
| `91e6ff31` | core: `ContactCard::from_canonical_cbor` walks the body for well-formedness before parsing |
| `631f4224` | docs: fix stale caller-count claims in `walk.rs`/`nesting_depth_seeds.rs` after wiring the card onto the shared walk (Task 3 review finding) |
| `cebadfbe` | core+conformance: delete `reject_excessive_nesting`, now callerless |
| `30b0838c` | core: `RuleToken::UnknownField`, the 18th token |
| `27abc381` | core: exhaustive `CardError::rule_token()` |
| `7830d40c` | core: fix the `CborEncode`-unreachable doc claim in `CardError::rule_token()` (fix round — the plan's worked example was wrong; `to_canonical_cbor()`'s re-encode makes it reachable) |
| `c5f44e95` | conformance: typed contact-card rejections carrying a rule token |
| `dc42c1d6` | conformance: `codec/card.py` decoder rewritten onto `from_canonical_cbor`'s own phase order |
| `96b5c467` | conformance: fix contact-card duplicate-vs-value and `created_at` token precedence (fix round — the #589 shape inverted: Rust's `set_once` is eager, so a duplicate whose second copy is malformed is `wrong_type` in Rust, not `duplicate_map_key`; also deleted the producerless `CardIntegerOutOfRange` class) |
| `2327a744` | replay: `contact_card` added to `TOKEN_COMPARED_TARGETS`, negative control |
| `1b66d0d7` | seeds: 21 committed single-fault contact_card seeds across 8 tokens |
| `28a227bc` | seeds: fix round — moved 4 two-fault precedence rows off the committed corpus into Section RTS check 5 + a Rust twin (the CRITICAL finding: no per-seed Python CLASS table existed, so `CardDisplayNameTooLong`↔`CardWrongType` could collapse invisibly) |

### Measurements, re-derived at this session rather than quoted from any task report

- **Committed replay corpus: 141 → 158** (`ls core/fuzz/seeds/*/*
  core/tests/data/diff_regressions/*/* | grep -v gitkeep | wc -l`) — 17
  committed `contact_card` seeds net (21 committed files minus 4 that are
  pre-existing `valuetype__`/`pre_sig.cbor`/`with_sigs.cbor` fixtures
  already counted before this slice; the four two-fault precedence bodies
  built during Task 10 were moved to Section RTS check 5 rather than
  committed, so they do not appear in this count at all).
- **`RuleToken` vocabulary: 17 → 18** (`RuleToken::ALL`,
  `core/src/vault/manifest/token.rs`), the new variant `UnknownField`. Not
  phase-dependent.
- **Tolerance breadth: 54/136 → 58/153** (`tolerance_admits_only_phase_dependent_pairs`,
  `core/tests/differential_replay.rs`) — C(18,2) = 153 unequal pairs, 4
  phase-dependent tokens give 62 pairs with a phase-dependent member, less
  4 pairing with `malformed_cbor` (never tolerated) = 58. The four
  newly-tolerated `UnknownField`-paired pairs are measured INERT:
  `PHASE_DEPENDENT_TOLERANCE_TARGETS` still holds only `manifest_body`, and
  `manifest_body`'s Rust decoder has zero arms producing `unknown_field`
  (grepped).
- **Token-compared targets: 3 → 4** (`TOKEN_COMPARED_TARGETS`,
  `core/tests/differential_replay_helpers/targets.rs`) — `record`,
  `manifest_body`, `block_file`, `contact_card`. `NOT_TOKEN_COMPARED_TARGETS`
  = `vault_toml`, `bundle_file`, `manifest_file` (4 → 3: `contact_card` moved
  out of this list into the one above).
  `contact_card` is **not** in `PHASE_DEPENDENT_TOLERANCE_TARGETS` — §4.2's
  licence is manifest-body-specific and has no §6 analogue, so every
  compared `contact_card` pair is strictly equal.
- **`contact_card` committed seeds: 21 files, 20 reach a strict token
  comparison, 1 (`with_sigs.cbor`, the accepting base) is compared on
  re-encoded bytes.** `MIN_CORPUS_INPUTS` pins `("contact_card", 21)`.
- **Section RTS PASS 1: 17 → 24 typed classes** (measured via
  `uv run core/tests/python/conformance.py`; moved 17→25 in Task 7, then
  25→24 in Task 8's fix round, which deleted `CardIntegerOutOfRange` —
  Rust maps every `Malformed(_)` to `WrongType`, so nothing could ever
  produce that token and it failed the vocabulary's own admission test: "a
  token may only draw a distinction BOTH implementations can make").
- **Section RTS PASS 5: 9/9 record + 1/1 block_file + 7/7 contact_card
  parity-order cases** (up from 9/9 + 1/1, the pre-existing pair).
- **`conformance_lib` file count: 78 → 80** (`find
  core/tests/python/conformance_lib -name '*.py' | wc -l`) — two new files,
  `codec/card_rules.py` and `sections/rule_token_seeds_ordering.py`.
- **`conformance_lib` top-module ranking moved**: `sections/nesting_depth.py`
  shrank 522 → 492 (net -30: `reject_excessive_nesting`'s NDL check-4
  sub-case and the content-blind traversal it drove were deleted), dropping
  it out of the "past the 500-line split threshold" set entirely (now 2 past
  threshold, not 3) and from second place to a near-tie for fourth against
  `manifest_canonicality_cause.py` (492 vs 491, one line apart). Full
  current top six: `value_type_discipline.py` 834,
  `value_type_structure.py` 507, `manifest_decode.py` 498,
  `nesting_depth.py` 492, `manifest_canonicality_cause.py` 491,
  `scanner.py` 479.
- **REG unchanged: 35/35** — no new section; the extension reused Section
  RTS.
- **`core/src/vault/manifest/` file count: unchanged at 34** — this slice
  touched only `token.rs` and its `tests/vocabulary.rs`, no files
  added/removed.

All of the above were re-measured live in this worktree, not copied from
any task report — several task-report figures (e.g. the 6,398-input corpus
measured in Task 8, before Task 10's 17 seeds landed) are now stale by
design; see §3 below.

---

## (2) Mutation evidence (task-11-report.md §2)

Self-test first: `uv run scripts/mutate.py --self-test` → **20/20**, run
twice, `git status --short` empty both times. Spec written to the session
scratchpad, never the tree.

Six rows, drawn from the shipped code rather than transcribed from the
design doc's pre-implementation sketch:

| # | Mutation | Gate | Outcome |
|---|---|---|---|
| C1 | `from_canonical_cbor`'s well-formedness walk call deleted | `cargo test --lib identity::card::tests::a_malformed_body_outranks_the_shape_check` | RED_AS_EXPECTED |
| C2 | `CardError::rule_token()`'s `UnknownField` arm repointed at `WrongType` | `cargo test --lib vault::rule_tokens::tests::card::every_card_error_variant_carries_its_declared_token` | RED_AS_EXPECTED |
| C3 | Python's non-text-key check deleted from the entry loop | `differential_replay_full_corpus` (seed `wrong_type__non_text_key.bin`) | RED_AS_EXPECTED |
| C4 | Python's `card_version` type/value split collapsed back into one inline check | `uv run core/tests/python/conformance.py` (Section RTS check 5) | RED_AS_EXPECTED |
| C5 | Python's `display_name` cap check deleted | `differential_replay_full_corpus` (seed `wrong_type__display_name_over_cap.bin`) | RED_AS_EXPECTED |
| C6 | `contact_card` removed from `TOKEN_COMPARED_TARGETS`, left unclassified | full `differential_replay` binary | RED_AS_EXPECTED (via `every_target_is_classified`) |

Harness exit code **0**. `git status --short` empty before and after —
every mutated file restored. C4 is worth noting: it is the only row no
committed corpus input can reach (crypto-design §6 fixes no order between a
wrong-value `card_version` and a later wrong-typed field), so Section RTS's
own local ordering case is the *only* gate that can see it.

**C6 does not test what its earlier "negative control" label implied, and
that mislabelling is this branch's most important finding (final
whole-branch review, I6) — say so plainly rather than soften it.** The row's
own `expect_red` names `every_target_is_classified`, a PARTITION check: it
requires `TOKEN_COMPARED_TARGETS` and `NOT_TOKEN_COMPARED_TARGETS` to cover
`TARGETS` exactly, and it fires because C6's edit *deletes* `contact_card`
from `TOKEN_COMPARED_TARGETS` without adding it anywhere else, leaving it
unclassified. That is not the edit a future author loosening the comparison
would actually make. Reproduced for this fix wave: moving `contact_card`
from `TOKEN_COMPARED_TARGETS` into `NOT_TOKEN_COMPARED_TARGETS` — a
complete, well-formed reclassification, still fully partitioning `TARGETS`
— leaves the entire `differential_replay` binary GREEN, 46/46, exit 0,
still logging `contact_card: 21 of 21 input(s) compared`. So **nothing in
this branch pins `contact_card`'s membership in the strict-comparison set**;
a future edit that silently downgrades it to loose (fact-of-rejection-only)
comparison passes every gate here. What DOES still hold, so the risk is
sized rather than inflated: Section RTS and
`rule_token_seeds_are_committed_and_label_bound` independently pin each
side's rule token per committed seed in CI, so a downgrade would not make a
wrong token invisible everywhere — only the cross-language AGREEMENT
comparison on `contact_card` would go unpinned.

---

## (3) Full-corpus replay — and the scope caveat that must not be read past

Symlinked in the main checkout's gitignored runtime corpus, replayed,
removed, `git status --short` confirmed empty before and after:

```
[differential_replay] contact_card: 6415 of 6415 input(s) compared, 21 committed, in 1.5s
```

**6,415 of 6,415 `contact_card` inputs agree, 0 disagreements** (6,394
runtime-corpus + 21 committed). All seven targets agreed in the same run
(`vault_toml` 60,937; `record` 7,495; `bundle_file` 25; `manifest_file` 10;
`manifest_body` 58; `block_file` 141 — all fully agreeing).

**State this plainly, because it is the branch's real residual and the
number that is easiest to misquote: CI replays the COMMITTED corpus only —
158 inputs (`core/fuzz/seeds/` + `core/tests/data/diff_regressions/`), not
6,415.** The 6,415-input figure requires the gitignored runtime corpus at
`/Users/hherb/src/secretary/core/fuzz/corpus`, which exists only on a
checkout that has been fuzzed; CI never sees it and never will unless
`MIN_CORPUS_INPUTS`-style machinery changes. Do not write "6,415, full
agreement" in a context that could be read as "CI checks this" — it does
not. This is the identical scope caveat CLAUDE.md already states for every
other differential-replay target's full-corpus number.

---

## (4) The rest of the gate set

Every gate, exit 0 (each run standalone, output to a log file, never piped
through `tail`, to avoid the zsh `${PIPESTATUS[0]}` trap):

```
cargo test --release --locked --workspace                                   — 0 (2,249 passed)
cargo clippy --release --locked --workspace --tests -- -D warnings          — 0
cargo clippy --release --locked -p secretary-core --features differential-replay --tests -- -D warnings — 0
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace                  — 0
cargo fmt --all --check                                                     — 0
uv run --with pytest python3 -m pytest scripts/mutation_harness -q -k "not C10 and not N4" — 0 (276 passed, 2 deselected)
bash ffi/scripts/check-lean-binding.sh --self-test / check                  — 0 / 0
bash ios/scripts/check-public-log-hygiene.sh --self-test / check            — 0 / 0
bash android/scripts/check-log-hygiene.sh --self-test / check               — 0 / 0
bash scripts/check-secret-slot-hygiene.sh --self-test / check               — 0 / 0
uv run scripts/check-error-payload-hygiene.py --self-test / check           — 0 / 0
uv run scripts/check-test-support-placement.py --self-test / check          — 0 / 0
```

All 18 commands: exit 0. `git status --short` empty after the whole set.

---

## (5) Rulings and corrections made along the way (ledger summary — read the full ledger for detail)

`.superpowers/sdd/2026-09-22-token-compare-contact-card/progress.md` is the
authoritative record. The load-bearing ones, condensed:

- **CONFLICT-1 (pre-flight):** Task 9's brief-specified negative control
  (`UnknownField` → `WrongType`) is vacuous against the corpus committed at
  Task 9 time — no seed reaches `unknown_field` until Task 10. Split: Task 9
  used a control the corpus CAN see (`Malformed(_)` → `MalformedCbor`);
  Task 10 gained the intended control once its seed existed.
- **Task 8 review, Important 1 (the #589 shape, inverted):** Rust's
  `set_once` is eager, so a duplicate key whose second copy is malformed is
  `wrong_type` in Rust and was `duplicate_map_key` in Python — Python's
  precedence was backwards relative to how #589 fixed the manifest. Fixed
  in Python to match Rust's eager precedence.
- **Task 8 review, Important 2:** `CardIntegerOutOfRange` had no Rust
  producer (every `Malformed(_)` maps to `WrongType`). Ruling: delete the
  Python class rather than add a Rust variant to serve one token — "a token
  may only draw a distinction BOTH implementations can make" is the
  vocabulary's own admission test, and it failed it.
- **Task 10 review, CRITICAL:** no per-seed Python CLASS table existed for
  `contact_card` — `_seed_issues` only reached its class check under `elif
  target == "block_file"`. Measured: collapsing `CardDisplayNameTooLong`
  onto `CardWrongType` (deleting crypto-design §6's 4096-byte bound as a
  named check) left both blocking CI gates green. Same defect #673's review
  closed for `block_file`, reopened for a target added after it. Fixed by
  adding the class table.
- **Task 10 review, Important, and the controller's central ruling:** four
  committed rows were two-fault bodies pinning an order §6 does not fix.
  Ruling: move them to Section RTS check 5 + a Rust twin
  (`card_order_tests.rs`) rather than making the precedence normative for
  §6 under review pressure. Filed the spec question as #693 rather than
  deciding it inline.
- **Task 3 review:** wiring the card onto the shared walk falsified four
  stale "N callers" claims in `walk.rs`/`nesting_depth_seeds.rs` that no
  later task's brief covered — fixed in the same PR rather than left for a
  future slice to trip over, and this session found and fixed the matching
  CLAUDE.md staleness (the "only ContactCard and IdentityBundle pin
  ciborium's limit" sentences at what were CLAUDE.md's old lines 773/848).

---

## (6) What is next

- **[#641](https://github.com/hherb/secretary/issues/641)**: `bundle_file`
  and `vault_toml` remain open — the value-substitution / token-comparison
  method contact_card and record used does not directly apply to an
  offset-based binary envelope reader (the same limitation #677 already
  named for the value-type sweep). Acceptance criteria for a future slice:
  a `RuleToken` mapping for each, addition to `TOKEN_COMPARED_TARGETS`, and
  committed single-fault seeds with a strict (or explicitly, spec-licensed,
  tolerant) comparison.
- **[#640](https://github.com/hherb/secretary/issues/640)**: `manifest_file`
  stays BLOCKED — sharing an error enum is not sharing a granularity
  (`UnsupportedFormatVersion` and the body sentinel check raise the same
  Rust variant, so no per-variant token can separate them). Needs a
  Rust-side refactor before a token vocabulary is even possible; not a
  documentation gap.
- **[#693](https://github.com/hherb/secretary/issues/693)**: the filed spec
  question. If `docs/crypto-design.md` §6 gains a precedence ruling, the
  four Section RTS check-5 `contact_card` cases become the corpus to
  validate a real fixed order against, and — if a ruling is made — the
  four bodies could then be promoted to committed corpus rows the way
  #618/#621's manifest-body rulings promoted theirs.
- **[#692](https://github.com/hherb/secretary/issues/692) /
  [#694](https://github.com/hherb/secretary/issues/694) /
  [#695](https://github.com/hherb/secretary/issues/695)**: small, all
  filed this session, none blocking. #692 in particular is worth folding
  into whatever eventually fixes #687 (the identical shape one section
  over) rather than fixed in isolation.
- **Standing, unrelated to this slice but visible while working in this
  area:** #646 (narrowing the per-token tolerance predicate), #668
  (report-order spec text for §6.1/§6.3 — the `record`/`block_file`
  analogue of #693), #657 (nothing pins the CI replay step stays wired),
  #686/#688 (two pre-existing 500-line-threshold file splits, untouched by
  this slice).

---

## (7) Open decisions and risks

- **Nothing pins `contact_card`'s membership in the strict-comparison set —
  the branch's primary residual, found in the final whole-branch review
  (I6), and the mutation table's C6 row must not be read as covering it.**
  See "(2) Mutation evidence", C6, for the full reproduction: moving
  `contact_card` from `TOKEN_COMPARED_TARGETS` into
  `NOT_TOKEN_COMPARED_TARGETS` is a complete, well-formed edit that still
  partitions `TARGETS` exactly, and it leaves the whole `differential_replay`
  binary green. The only gate that ever reds on a `TOKEN_COMPARED_TARGETS`
  edit for `contact_card` is `every_target_is_classified`, which proves
  classification completeness, not comparison strictness. Sized against what
  still holds: Section RTS and `rule_token_seeds_are_committed_and_label_bound`
  independently pin each side's rule token per committed seed in CI, so this
  is a gap in the AGREEMENT comparison specifically, not a silent loss of all
  token coverage. No issue currently tracks closing it.
- **All seven order-sensitive card behaviours are pinned by in-crate and
  in-section tests, NOT by CI's cross-language replay — state this
  plainly, it is the second real residual.** Measured:
  `_ORDERING_CASES["contact_card"] == 7`
  (`sections/rule_token_seeds_ordering.py`) and `card_order_tests.rs` has
  seven `#[test]`s, not four — an earlier ledger entry carried "four", from
  before fix round 1 folded a fourth shape (`created_at_negative`) into a
  committed seed and added three MORE two-fault ordering cases on top of
  it; nobody re-counted after. The three original shapes (task 10) mirror
  `card.rs::from_canonical_cbor`'s own precedence — the `card_version != 1`
  comparison deferred until after the whole entry loop, a repeated key's
  SECOND copy checked for its own type before the duplicate is reported,
  and trailing bytes judged only by the final canonical-form re-encode,
  after every entry fault. The four added in fix round 1 each pin a
  competing, order-dependent verdict on a value that also fails a per-field
  type check: an undefined `created_at`, an excessively deep `created_at`,
  a float `created_at`, and a narrow-bignum `created_at` — each reports
  `wrong_type` or `non_canonical_unclassified` rather than the walk's own
  verdict, because the card's per-field type check runs first. None of the
  seven is committed: crypto-design §6 fixes no report order between them
  (#618's lesson, restated for the card). This is structural, not a
  shortcut: the card has no forward-compat `unknown` bag
  (`CardError::UnknownField` rejects every unrecognised key outright), so
  there is nowhere to plant an isolated single-fault depth or rule-4 body
  the way the manifest body and record can — every candidate body for
  these seven shapes is inherently two-fault, and #618 says a
  cross-language row must not pin an order the spec leaves open. `record`
  and `block_file` already accept this exact posture for their own check-5
  cases; this is not a new exception.
- **Committed-corpus vs full-corpus, restated because it bears repeating
  for a number this easy to misquote:** 158 committed, 6,415 full local
  (this session's own measurement). CI checks the 158 only.
- **The four newly-tolerated `UnknownField`-paired pairs are inert today,
  but that is a property of today's producers, not a structural
  guarantee.** If a future manifest-body change ever gives Python or Rust
  a reachable `unknown_field` producer, those four pairs would start being
  silently tolerated on `manifest_body` even though §4.2 says nothing
  about `UnknownField` at all. Nothing currently pins this against
  regressing; #646 is the closest tracked issue.
- **`IdentityBundle::from_canonical_cbor` is now the sole remaining
  ciborium-only recursion-limit path.** A future slice extending token
  comparison or the well-formedness walk to identity bundles would need
  the same wiring this slice gave the card. Not urgent — bundles are not a
  differential-replay target at all today — but worth knowing before
  someone assumes the walk already reaches everywhere.

---

## (8) How to resume — the exact commands

```bash
git fetch origin && git log --oneline main..origin/main

cd /Users/hherb/src/secretary/.worktrees/token-compare-card
pwd && git branch --show-current && git worktree list   # feature/token-compare-contact-card

# --- the clean-room verifier ---
uv run core/tests/python/conformance.py
#   0 FAIL; Section RTS "24 typed classes... 7/7 contact_card parity-order
#   cases"; Section REG "35 drivers discovered, 35 registered"

# --- the replay, CI shape ---
cargo test --release --locked -p secretary-core \
  --features differential-replay --test differential_replay
#   contact_card 21 of 21 committed compared, strict, 0 disagreements

# --- the replay over the real fuzz corpus; REMOVE the link afterwards ---
test ! -e core/fuzz/corpus && ln -s /Users/hherb/src/secretary/core/fuzz/corpus core/fuzz/corpus
cargo test --release --locked -p secretary-core \
  --features differential-replay --test differential_replay -- differential_replay_full_corpus --nocapture
rm core/fuzz/corpus && git status --short                # no corpus entry

# --- committed corpus count ---
ls core/fuzz/seeds/*/* core/tests/data/diff_regressions/*/* | grep -v gitkeep | wc -l   # 158

# --- prove the mutation gates are not decorative (spec to the SCRATCHPAD, never the tree) ---
uv run scripts/mutate.py --self-test                                  # 20/20
uv run --with cryptography --with pynacl --with "pqcrypto<1" \
  --with argon2-cffi --with blake3 --with cbor2 scripts/mutate.py "$SCRATCH/card.toml"
git status --short                                                     # MUST be empty

# --- the rest of the gate set ---
cargo test --release --locked --workspace
cargo clippy --release --locked --workspace --tests -- -D warnings
cargo clippy --release --locked -p secretary-core --features differential-replay --tests -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
cargo fmt --all --check
uv run --with pytest python3 -m pytest scripts/mutation_harness -q -k "not C10 and not N4"

# --- six hygiene guards, --self-test FIRST, as LITERAL commands ---
bash ffi/scripts/check-lean-binding.sh --self-test         && bash ffi/scripts/check-lean-binding.sh
bash ios/scripts/check-public-log-hygiene.sh --self-test   && bash ios/scripts/check-public-log-hygiene.sh
bash android/scripts/check-log-hygiene.sh --self-test      && bash android/scripts/check-log-hygiene.sh
bash scripts/check-secret-slot-hygiene.sh --self-test      && bash scripts/check-secret-slot-hygiene.sh
uv run scripts/check-error-payload-hygiene.py --self-test  && uv run scripts/check-error-payload-hygiene.py
uv run scripts/check-test-support-placement.py --self-test && uv run scripts/check-test-support-placement.py
```

**What remains before merge:**

1. Re-check `main..origin/main`, merge if it moved.
2. The controller runs the whole-branch review (this session was told not
   to push or open a PR).
3. Push and open the PR after the review's fix wave, titled to match this
   file's H1.

---

## (9) Where this document lives

This file. `NEXT_SESSION.md` at the repo root is a symlink to it,
retargeted in the same commit as this file's creation.
