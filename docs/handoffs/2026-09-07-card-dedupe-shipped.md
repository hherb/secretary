# NEXT_SESSION.md — the hybrid-signed contact card comes behind the duplicate-key choke point (#602)

Branch `feature/card-dedupe`, worktree `.worktrees/card-dedupe`,
base `d6756980` (`main`, i.e. immediately after PR #622 merged).

This slice is **(c)** from the previous baton's §(3) queue, chosen over the
other three because it is the only item in it with a **security** stake. The
choice was put to the user options-plus-recommendation and the
recommendation was taken; a second such question settled the one real design
decision inside it (§(1)).

**Two issues filed:** [#625](https://github.com/hherb/secretary/issues/625),
[#626](https://github.com/hherb/secretary/issues/626) — both found by
measuring file sizes rather than by reading code. The slice closes **#602**.

---

## (0) The starting-state check fired clean again — keep running it first

`git fetch origin && git log --oneline main..origin/main` returned empty and
`main` was at `d6756980`, so the previous slice (#613 / #612-half) had
merged as PR #622. Cost: one command. Keep it as the first thing you do,
**before reading this file** — the baton is a symlink into `docs/handoffs/`,
so a stale checkout resolves it silently to an old file with no marker of
any kind.

Housekeeping done at the same time: `.worktrees/cause-coverage` removed and
`feature/cause-coverage` deleted (merged as PR #622). **Three older local
branches were deliberately left alone**, unchanged from the last baton's
ruling — `feature/manifest-uniqueness-parity` and
`feature/noncanonical-cause` are squash-merged (their diffs against `main`
are net *deletions*, so `git branch -d` will not take them and `-D` is a
destructive op not worth running unasked), and
`backup-pre-reword-1787543234` is a deliberate backup.

---

## (1) What shipped

### Commits

| SHA | What |
|---|---|
| `944a3320` | **#602** — `canonical/dedupe.rs`, both `legacy` entry points wired, `card.rs::encode_map` reduced to a delegation, two hostile fixtures re-based |
| `b7a0ac73` | CLAUDE.md + ROADMAP, including the claims #602 falsified |
| *(this)* | the baton — a commit cannot cite its own SHA, so this row stays symbolic |

### The defect

#586 made a repeated CBOR map key a rejection at `to_canonical_vec`, the
choke point the four **vault-body** encoders (manifest, record, block,
bundle) funnel through — and disclosed, rather than hid, that three paths
sat outside it. **One of them is hybrid-signed.**

- `ContactCard::signed_bytes` — the byte string the §8 hybrid
  self-signature commits to
- `ContactCard::to_canonical_cbor` — the §6.1 fingerprint input and the §6
  wire form on disk
- `ContactCard::pk_bundle_bytes` — §7's `sender_pk_bundle` /
  `recipient_pk_bundle` HKDF input

The first two reached `card.rs`'s own private `encode_map`, the third
`legacy::encode_canonical_map`. **Neither deduplicated.** So a caller could
build an *ambiguous signed document* — one two conformant readers may
resolve differently while both accepting the signature.

Nothing was exposed, because every key on those paths is a fixed `KEY_*`
literal. But that is a property of today's call sites rather than of the
encoder, which is exactly the posture #586 exists to replace.

### The two rulings put to the user before implementation

1. **Take #602** rather than #612's other half (mechanical debt, no
   correctness stake), #621 (a spec-precedence question, cheaply answerable
   by declaring it unspecified) or #623/#624 (test-corpus depth). Ranked by
   blast radius, per standing feedback.
2. **Delete `card.rs::encode_map`'s body rather than add a third copy of the
   check to it.** It was a near-duplicate of `encode_canonical_map` —
   identical sort, identical `classify_ser` mapping, differing only by
   cloning instead of borrowing and by lacking the pre-reservation. The
   alternative considered and rejected was "check in place now, consolidate
   later", which would have left three near-identical encoders and the
   `DuplicateKey` arm structurally dead.

### What landed

- **`core/src/vault/canonical/dedupe.rs`** (299 lines) holds the rule
  **once**. `encode_canonical_map` and `canonical_sort_entries` each call it
  as their **first statement** — #600's pattern, and for #600's reason:
  seven hand-copies of one sentence from a frozen spec is how two directions
  drift.
- **`card.rs::encode_map` is now a one-line delegation**, and
  `pk_bundle_bytes` joins its two siblings on it. So all three card paths
  funnel through one function, `canonical_error_to_card_error` is applied
  once rather than per call site, and its `CanonicalError::DuplicateKey` arm
  is **live code on a live path**.
- **Two hostile fixtures re-based onto one shared `#[cfg(test)]` permissive
  encoder**, `dedupe::encode_map_allowing_duplicates` — which is the
  pre-#602 `encode_map` body preserved verbatim, so it doubles as the
  byte-identity oracle.
- **15 tests added, none renamed or removed** (2101 → 2116).

### Non-vacuity, by mutation

Every restore **sha256-verified** by the harness, which asserts the hash
rather than reporting it.

| # | Mutation | Result |
|---|---|---|
| M1 | drop the check from `encode_canonical_map` | RED — 2 tests |
| M2 | drop the check from `canonical_sort_entries` | RED — 1 test |
| M3 | make the walk non-recursive | RED — 3 tests |
| M4 | drop the `Array` arm from the walk | RED — 1 test, the `SyncState`-shaped one |
| M5 | ordinal names the FIRST of a pair, not the second | RED — 8 tests |
| M6 | do not sort before the adjacent sweep | RED — 3 tests |
| M7 | **revert `encode_map` to the pre-#602 body** | RED — **only** `card_encode_path_rejects_a_duplicate_key`; all three byte-identity tests stay GREEN |
| M8 | reverse `encode_canonical_map`'s sort | RED — all three byte-identity tests **plus** the pre-existing `pk_bundle_bytes_is_byte_pinned` |

**M7 and M8 are the pair that matters, and they run in opposite
directions.** M7 says the bytes genuinely did not move (swapping the old
body back in changes nothing but the rejection); M8 says the byte-identity
tests are not vacuous (they red on real drift). Either alone would be weak
evidence.

### The measured result

- **`cargo test --release --workspace`: 99 binaries, 2116 passed, 0 failed,
  21 ignored**, exit 0.
- **Test NAME SET is additive-only, proven without a baseline build**: the
  diff removes **zero** functions and adds exactly **15** `#[test]`
  attributes, which is precisely the 2101 → 2116 delta. A rename or removal
  cannot hide inside a count that reconciles that way.
- **`--features differential-replay` exit 0** — 99 binaries, 2117 passed, 0
  failed (one more than the default run; the feature adds a test). No CI job
  covers this, so it is the only place the cross-language decoder-agreement
  contract is exercised.
- **`core/fuzz` checks clean under the pinned nightly** (7m07s — it is a
  genuine cold build, and it sits at 0% CPU behind a concurrent workspace
  cargo run because they share cargo's package-cache lock. Not wedged; just
  serialized. Run them in sequence.)
- `cargo fmt --all --check`, `cargo build --release --workspace`,
  `cargo clippy --release --workspace --tests -- -D warnings`,
  `RUSTDOCFLAGS="-D warnings" cargo doc` (forced non-cached with
  `touch core/src/lib.rs`) all exit 0.
- **`conformance.py` exit 0**, 26 sections, REG `26 drivers, 26 registered`,
  **0 `FAIL` lines** — checked by exit code AND by grep, per the last
  baton's process note that a `SyntaxError` once produced 0 FAIL lines and
  exit 1.
- **All six hygiene guards pass, each `--self-test` first.** No probe
  residue (`git status` clean of stray `.rs`).
- **`spec_test_name_freshness.py` = 90**, identical to main's recorded
  baseline. This slice removed no test name and touched no `docs/`, so the
  citation set cannot have moved.
- **Format invariants — all four diffs EMPTY**: `core/tests/data/`,
  `core/fuzz/seeds/`, the UDL, and normative `docs/`.
- File sizes: `dedupe.rs` 299, `legacy.rs` 410, `canonical/mod.rs` 319 — all
  under 500.

### README was deliberately not touched

Checked, not assumed. README cites `canonical` in exactly four places, all
FFI/CRDT status-table prose; it names none of these encoders, no KAT
internals and no test count. This slice changes no user-visible behaviour,
no on-disk format and no FFI surface. `ROADMAP.md` and `CLAUDE.md` both
changed.

---

## (2) What this slice does **not** claim

- **It is a SECOND implementation, not one shared walk.** `to_canonical_vec`
  operates on `CanonicalMap` (borrowed `&str` keys, **no key buffer ever
  materialised** — load-bearing, because record field names are decrypted
  plaintext); `dedupe` operates on `ciborium::Value` and encodes keys to
  sort them. They agree on the **rule** and on `DuplicateKey`'s ordinal
  contract, **not** on a mechanism. Do not "unify" them.
- **§6.2 does NOT bind `sync::state`.** §6.2's opening sentence enumerates
  the `canonical_cbor(...)` byte strings it governs and OS-keystore state is
  not among them. `SyncState` gains the check by *sharing a helper*, and it
  is **defence in depth** there anyway — `SyncState::new` already rejects a
  duplicate `device_uuid`, so no such `SyncState` is constructible. The
  source says both; do not cite the spec for that path.
- **"Live on a live path" is not "reachable from the public API".** The
  `DuplicateKey` arm in `canonical_error_to_card_error` is now raised by the
  encoder the card actually uses, but `push_pre_sig_entries` and
  `pk_bundle_bytes` build every key from a fixed `KEY_*` literal, so
  `ContactCard`'s public API still cannot produce one. That distinction is
  the whole point of the change and the arm's doc draws it explicitly.
- **#586's `Borrowed` carve-out is absent here for a STRUCTURAL reason, not
  a judgement call.** Neither production caller can carry a forward-compat
  `unknown` subtree: `ContactCard` rejects unknown fields outright
  (`CardError::UnknownField`) and `SyncState` has two typed fields and no
  `unknown` bag. If either ever gains one, this walk must gain the
  carve-out — walking into it would narrow a frozen decoder.
- **The `unknown`-subtree residual is untouched and deliberate.** The three
  remaining production `ciborium::ser::into_writer` calls re-emit those
  subtrees verbatim, which is the one place a repeated key must stay
  ACCEPTED.
- **No spec edit, no new error variant, no on-disk format change.**
  `CanonicalError` is byte-identical to main's.
- **#621 / #623 / #624 / #612-half / #596 / #587 / #603 / #610 / #611 /
  #618 / #619 / #620 stay open and untouched.**

---

## (3) What is next — with acceptance criteria

**(a) #612's other half — `manifest_uniqueness_kat.rs` (848 lines).** The
`_helpers/` pattern is demonstrated once in `core/tests/` (`80c3c488`) and
the two corpora are read as a pair. **Acceptance:** under 500, sharing its
`Case` / `Verdict` / surgery helpers through a
`manifest_uniqueness_kat_helpers/` rather than a second test binary, and
committed as a behaviour-preserving move with the test name set diffed.

**(b) #621 — the multi-violation precedence divergence.** A body violating
two §6.2 rules gets a different reported cause from each implementation
(Rust `ArraySortOrder`, Python rule 2 — same bytes, same offset 929). Both
reject, so nothing is unsafe. **Acceptance:** `docs/vault-format.md` §4.2
either fixes a precedence — in which case corpus rows violating two rules
assert the declared winner in both languages — or states that the reported
rule is unspecified when several apply, in which case MCC's docstring and
`classify.rs` say so. **Declaring it unspecified is legitimate and much
cheaper**; this needs a ruling from the user before implementation.

**(c) #623 — `base_manifest`'s five §4.2 arrays hold 2 elements**, so a
first-pair sort check and a full adjacent scan are the same function
(measured: a first-pair Python reader leaves all 26 sections green).
**Acceptance:** all five arrays ≥ 3, at least one row whose disorder is a
**middle/tail swap** (a 3-element reversal also disturbs the first pair),
the MAS guard in `manifest_body_canonicality_guards.py` mirrored, and the
first-pair mutation reds. Note this regenerates all 32 bodies and 38 seeds,
spending the additivity evidence #613 rests on — which is why it is its own
slice.

**(d) #625 — `card.rs` is 1254 lines.** Filed by this slice. Same class as
#556 / #563 / #603. **Acceptance:** directory module split by ROLE
(`mod`/`encode`/`decode`/`error` + sibling `tests.rs`), every file under
500, committed as a behaviour-preserving move with the name set diffed, and
`golden_vault_001` / `conformance.py` / the byte-identity tests green
throughout — they are what pin the signed byte form.

**(e) #596 — a `manifest_body` cargo-fuzz target, the natural eighth.** The
`--diff-replay` wiring exists and the seed corpus is 38 bodies.
**Acceptance:** `core/fuzz/fuzz_targets/manifest_body.rs` exists,
`cargo fuzz run manifest_body` starts from the committed seeds, and
CLAUDE.md's "Seven targets" line becomes eight.

**(f) #624 / #626 / #587 / #603 / #610 / #611 / #618 / #619 / #620 stay open
and untouched.**

### Issues this slice closes — verify against the code, not this document

**#602.** Per this repo's `(#N)`-not-`Closes #N` convention it stays open
until a human closes it. Its acceptance is checkable in three commands:

```bash
# 1. The card's own encoder refuses an ambiguous map.
cargo test --release -p secretary-core --lib card_encode_path_rejects_a_duplicate_key
# 2. ...and the migration moved no byte.
cargo test --release -p secretary-core --lib is_byte_identical_to_the_previous_encoder
# 3. The rule lives in ONE place, called by both entry points.
grep -c "check_no_duplicate_keys(entries)" core/src/vault/canonical/legacy.rs   # expect 2
```

---

## (4) Open decisions and risks

### The generalisable finding: a checked encoder cannot build a hostile fixture

Adding the check broke **exactly two** tests, and both broke for the same
good reason: they were using a *sanctioned encoder* to build deliberately
ambiguous bytes. `card.rs`'s
`duplicate_field_names_the_spec_key_as_a_static_str` and
`manifest/decode/tests.rs`'s `manifest_bytes_with_duplicate_nested_key`
(whose repeat is nested in a map inside an array — which is how the
recursive walk found it) now share one `#[cfg(test)]` permissive encoder,
following the pattern `core/tests/identity.rs::card_parse_rejects_duplicate_keys`
had always used.

**Generalise it:** when you tighten an encoder, the tests that break are a
census of everywhere a test was relying on it being permissive — and each
one is a decision about whether that reliance was legitimate. Both were. But
note the second was *nested two levels down*, and would have been invisible
to a top-level-only check; the shared helper exists so a third such fixture
does not become a third hand-copied permissive encoder, which is the drift
#602 was.

### #600's lesson, applied prospectively rather than re-learned

CLAUDE.md records from #608's review: *"whenever a check is added to one
direction of a round-trip, ask what the OTHER direction's tests would still
catch."* That was checked here **before** the tests were written, and the
answer is that this slice has no round-trip exposure — `from_canonical_cbor`
does not re-encode-and-compare (its own doc says it tolerates non-§6 key
order on input), so tightening the encoder cannot backstop the decoder's
duplicate-field test. The decoder's `set_once` guard is still the only thing
rejecting a duplicate on read, and
`duplicate_field_names_the_spec_key_as_a_static_str` still proves it,
against bytes no sanctioned encoder can now produce.

### The claim in this document most likely to rot

**"Every production canonical-MAP encoder in `core/src` is now behind one of
the two checks."** It is measured, not inferred — the census is
`grep -rn "ciborium::ser::into_writer" core/src`, splitting production from
`#[cfg(test)]` by hand — and the three survivors (`block.rs`'s and
`manifest/decode/extract.rs`'s `value_to_unknown`, `record.rs`'s
`UnknownValue::to_canonical_cbor`) all re-emit forward-compat subtrees,
where a repeated key must stay ACCEPTED.

The sentence it **replaced** in CLAUDE.md was true when written and false
for two slices after. Re-run the census before widening it. This is the
same class as the last two batons' findings, and the reason CLAUDE.md's new
paragraph ends with the command rather than the conclusion.

### Standing risks this slice does not remove

- **#602's siblings are closed, but the ordinal contract is now asserted in
  two places.** `to_canonical_vec` and `dedupe` both promise "second
  occurrence, canonical order, scoped to its own map". Nothing mechanically
  ties them; M5 pins `dedupe`'s half and #586's tests pin the other. A
  future change to one must change both.
- **Five of the six PEP 723 deps remain unbounded** (`cryptography`,
  `pynacl`, `argon2-cffi`, `blake3`, `cbor2`), and `ed25519_verify` still
  has the "no exception means success" shape whose failure direction is
  fail-**open** (#544 / #550).
- **`encode_manifest` validates no v1 sentinel** (#587).
- **Multi-violation precedence is unspecified and divergent** (#621), and
  `differential_replay.rs` scores reject-vs-reject as agreement without
  comparing `detail` (#618) — which is why #621 is invisible to it, and
  will stay invisible after #621 is fixed.
- **`card.rs` (1254) and `sync/state.rs` (549) are past the 500-line
  guideline** — #625 / #626, filed by this slice, deliberately not fixed in
  it.

---

## (5) How to resume — the exact commands

```bash
# FIRST, before reading the baton — costs nothing when it is actually run:
git fetch origin && git log --oneline main..origin/main

cd /Users/hherb/src/secretary/.worktrees/card-dedupe
pwd && git branch --show-current && git worktree list   # expect feature/card-dedupe

# --- the gates this slice is actually about ---
cargo test --release -p secretary-core --lib canonical::dedupe   # expect 7 passed
cargo test --release -p secretary-core --lib identity::card      # expect 17 passed
uv run core/tests/python/conformance.py                          # 26 sections; REG 26/26

# --- the rest of the gate set ---
cargo fmt --all --check
cargo build --release --workspace          # separate from the test run ON PURPOSE
# Redirect, then echo $? — a `| grep` pipeline reports GREP's exit code:
cargo test --release --workspace > /tmp/suite.txt 2>&1; echo "CARGO EXIT: $?"
grep -E "^test result" /tmp/suite.txt | \
  awk '{p+=$4; f+=$6; i+=$8} END {print NR, p, f, i}'   # expect 99 2116 0 21
# NOT redundant with the above — `--tests` catches unused imports the full
# suite compiles green:
cargo clippy --release --workspace --tests -- -D warnings
touch core/src/lib.rs   # rustdoc caches; a ~5s run did nothing
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace

# The cross-language contract (no CI job covers this one). SLOW — it spawns a
# Python subprocess per fuzz input, and it holds cargo's package-cache lock,
# so a concurrent `cargo check` in core/fuzz sits at 0% CPU behind it. Run
# them in sequence, not in parallel.
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

# --- format invariants. ALL FOUR must be EMPTY this slice. ---
git diff origin/main...HEAD --stat -- core/tests/data/
git diff origin/main...HEAD --stat -- core/fuzz/seeds/
git diff origin/main...HEAD -- ffi/secretary-ffi-uniffi/src/secretary.udl
# NORMATIVE docs only. A git pathspec glob CROSSES `/`, so `docs/*.md` would
# also match docs/manual/**; exclude the two non-normative trees by name.
git diff origin/main...HEAD --stat -- docs/ ':!docs/handoffs/' ':!docs/manual/'
```

Re-running this slice's mutation harness (it asserts each restore's sha256
rather than reporting it, so a failed restore aborts rather than silently
poisoning the next mutation):

```bash
python3 /tmp/mutate.py    # M1-M6, the rule and its two call sites
python3 /tmp/mutate2.py   # M7/M8, the card migration in both directions
```

Re-proving the defect by execution, which is the fastest way to see what
#602 was — revert `encode_map` to its pre-#602 body and watch the encoder
emit a 9-entry map with `display_name` twice:

```bash
git show 944a3320^:core/src/identity/card.rs > /tmp/card-before.rs
diff <(sed -n '/^fn encode_map/,/^}/p' /tmp/card-before.rs) \
     <(sed -n '/^fn encode_map/,/^}/p' core/src/identity/card.rs)
```

---

## (6) Where this document lives

`NEXT_SESSION.md` at the repo root is a **symlink**, retargeted this session
to `docs/handoffs/2026-09-07-card-dedupe-shipped.md`. This file is the
single authored baton — do not create a second copy at the root, and do not
sync it to `main` during a pause window (that produces an add/add conflict).
