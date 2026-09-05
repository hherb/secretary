# NEXT_SESSION.md — the manifest decoder's duplicate-key rejection becomes a type invariant (#589)

Branch `feature/decoder-slot-invariant`, worktree `.worktrees/decoder-slot-invariant`,
base `f6be2830` (`main`, i.e. immediately after PR #614 merged).

This slice is **(a)** from the previous baton's queue, taken with its scope
**widened** — see §(1) "The ruling put to the user". It is Rust only: all four
format invariants (`core/tests/data/`, `core/fuzz/seeds/`, the UDL, normative
`docs/`) are empty.

**No issue filed.** Nothing was found that is not closed here or already
tracked. The slice closes **#589** and, as a measured side effect, **#582**.

---

## (0) The starting-state check fired clean again — keep running it first

`git fetch origin && git log --oneline main..origin/main` returned empty, and
`main` was already at `f6be2830`, so the previous slice (#604/#614) had merged.
Total cost: one command. Two sessions running now. Keep it as the first thing
you do, **before reading this file** — the baton is a symlink into
`docs/handoffs/`, so a stale checkout resolves it silently to an old file with
no marker of any kind.

Housekeeping done at the same time: `.worktrees/canonicality-cause` removed and
`feature/canonicality-cause` deleted (merged as PR #614).

---

## (1) What shipped

### Commits

| SHA | What |
|---|---|
| `b80f5c9a` | the slice — `decode/slot.rs` + `slot/tests.rs`; all 57 sites converted; 2 ordering regressions; CLAUDE.md + ROADMAP |
| *(this)* | the baton — a commit cannot cite its own SHA, so this row stays symbolic |

### The defect

RFC 8949 §5.4 forbids a repeated map key, and vault-format §4.2 lists each
manifest map's required keys. Both were enforced as **hand-copied runtime
idioms** across the five maps:

- **31** `if slot.is_some() { return Err(DuplicateKey { field, index }) }` guards
- **26** `.ok_or(ManifestError::MissingField { field })?` unwraps

(#568 wrote the top-level 10; #573 wrote the nested 21.) Nothing about
`Option<T>` forced either — a new arm writing `slot = Some(take_u64(..)?)`
compiled cleanly and silently last-won.

**Be precise about what was and was not backstopped**, because the honest
answer is not "it would silently pass": #572's re-encode-and-compare *is* a
structural backstop for any structurally parsed map — a forgotten check keeps
one value and drops the other, so the re-encode emits the key once and the byte
comparison diverges. A fifth parser that forgot would **degrade the diagnostic,
not the rejection** (`duplicate_key_wins_over_non_canonical_encoding` pins
this). Two things keep that from being a substitute: the backstop lives in
`decode_manifest`, not in the parsers, so a future entry point that calls a
parser without re-encoding loses it with **no compile-time signal**; and the
`unknown`-subtree residual is unaffected either way.

### What landed

- **`core/src/vault/manifest/decode/slot.rs`** (184 lines) + `slot/tests.rs`
  (187). `Once<T>` and `UnknownBag` hold **private** fields, so a parser cannot
  fill a slot except through `Once::set`.
- **`ManifestError::DuplicateKey` and `MissingField` are each constructed
  EXACTLY ONCE** in the whole decoder. `DuplicateKey` needed a shared private
  `duplicate_key(field, index)` helper to get there, because both slot types
  reject a repeat — without it the count would be two, and the stated property
  would have been an approximation.
- **All 57 sites converted**: 28 `Once::set` arms (19 in `entries.rs`, 9 in
  `mod.rs`), 26 `require`, 2 `into_option` (`TrashEntry::{fingerprint,
  purged_at_ms}`), 3 `UnknownBag::insert`, 3 `into_map`.
- **`UNKNOWN_FIELD`** — the `"<unknown>"` literal was written 3 times; now one
  named const beside the constructor it feeds.
- **Two new ordering regressions**, at both levels (see §(2)).
- `decode/entries.rs`: **524 → 362 lines**, which is what **#582** asked for.

### The ruling put to the user before implementation

Two questions, options-plus-recommendation, both answered with the
recommendation:

1. **Scope: all five parsers, both error kinds (57 sites)**, not the 21 the
   issue is titled for. #589's title counts only #573's four nested parsers;
   the identical idiom sits in the top-level `parse_manifest_map` (10 more,
   from #568) and the 26 `MissingField` unwraps are interleaved with them in
   the same match arms. Converting a subset would have left a copied idiom
   sitting beside the invariant one, in the map every vault open parses first.
2. **Closure form, so behaviour is byte-identical**, not the eager form. See
   §(2) — this was the one real behaviour risk in the slice, and it was
   invisible to the entire suite.

### Non-vacuity, by execution

The module was written **non-enforcing first** (a faithful "naive"
implementation — exactly what a new arm looks like today), the tests run against
it, and enforcement added only after a genuine behavioural red: **4 enforcement
tests failed, 7 projection tests passed.** That red is the up-front form of the
acceptance criterion; the mutations below are its confirmation on the finished
code.

Every mutation asserted `count(old) == 1` before patching and verified the
restore by **sha256**.

| # | Mutation | Result |
|---|---|---|
| M1 | delete `Once::set`'s `is_some()` guard | **11 tests red** — all four nested parsers, the top level, and `slot::tests` |
| M2 | **eager fill** (evaluate `f()` before the vacancy check) | **exactly 3 red** — the unit test plus both ordering regressions. **All eight pre-existing `rejects_every_duplicate_key` tests stayed GREEN**, which is the measurement that justifies the closure form |
| M3 | delete `UnknownBag::insert`'s guard | **4 red**, both nested unknown arms + top level + unit |
| M4 | `require` never reports a missing field | **3 red** |
| M5 | one arm passes the **wrong `KEY_*` constant** to `set` | **1 red** (`a_manifest_with_a_repeated_key_is_rejected`) — run to *verify a claim written into that test's own comment*, that the nine-key sweep still pins per-arm key correctness now that the nine arms share one implementation |

### The measured result

- **`cargo test --release --workspace`: 99 binaries, 2097 passed, 0 failed, 21
  ignored**, exit 0.
- **Test NAME SET measured against an `origin/main` baseline** built in a
  throwaway detached worktree: **zero removed, exactly 13 added** — the 11
  `slot::tests` plus the 2 ordering regressions. Nothing else moved.
- **The previous baton's "main = 2104" was stale by one.** Measured here,
  `main` enumerates **2105** entries and this branch **2118**. The baton had
  warned about exactly this and still carried a stale figure; the name-set diff
  is what makes the delta checkable rather than assertable.
- `cargo fmt --all --check`, `cargo build --release --workspace` and
  `cargo clippy --release --workspace --tests -- -D warnings` all clean.
  **Clippy earned its keep here** — see §(4).
- `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace` clean, forced
  non-cached with `touch core/src/lib.rs` first.
- **`conformance.py` exit 0**, 26 sections, REG `26 drivers, 26 registered`.
  Unchanged — this slice is Rust-only, and the clean-room verifier has no
  equivalent construct to converge on.
- **Both gates no CI job covers:** `--features differential-replay` clean (99
  binaries, 2098 passed, 0 failed) and `core/fuzz` checks under the pinned
  nightly. `manifest_body` still holds **27** seeds.
- **All six hygiene guards pass, each `--self-test` first.** No probe residue.
- **`spec_test_name_freshness.py` = 90, byte-identical to `origin/main`** —
  `diff`ed in full against a baseline worktree, with an explicit `cd` **inside
  each subshell** and `pwd` echoed from each (the trap the last baton recorded).
- **All FOUR format invariants empty**: `core/tests/data/`, `core/fuzz/seeds/`,
  the UDL, and normative `docs/`. Unlike the last slice, this one touches no
  fixture at all.

### README was deliberately not touched

Checked rather than assumed. `README.md` is a status/roadmap table; nothing in
it cites the manifest decoder's internals, a line count, or a test count, and
this slice changes no user-visible behaviour and no on-disk format.
`ROADMAP.md` and `CLAUDE.md` both changed.

---

## (2) What this slice does **not** claim

- **The privacy guarantee is against SIBLINGS, not descendants.** Rust privacy
  is module-**subtree** scoped, so a descendant of `slot` could write
  `Once(Some(v))` and bypass `set`. Only `#[cfg(test)] mod tests` is declared
  there. The parsers the type constrains — `decode/mod.rs`, `decode/entries.rs`
  — are siblings, and for them the invariant is absolute. #515 had to make this
  exact distinction about `Detail`'s private field and gave it guard rule E6;
  that field is a security boundary, this one is a correctness invariant on an
  already-trusted decoder, so a source note is the control rather than a guard
  rule. Do not write this up as "cannot be bypassed" without the qualifier.
- **`Once::set`'s closure is an observable contract, not a style choice.** The
  hand-copied guards checked `slot.is_some()` *before* parsing the second copy,
  so a duplicate key whose second copy is **malformed** reported `DuplicateKey`,
  not `WrongType`. An eager `set(field, index, take_u64(v, KEY)?)` reverses that
  for a v1-frozen decoder — and **no test in the tree could see it**, because
  every duplicate fixture repeats a well-typed pair. The two new regressions
  (`a_duplicate_key_outranks_a_malformed_second_copy` and its `top_level_` twin)
  were written and confirmed **passing against the unconverted code** before the
  conversion began, so they pin pre-existing behaviour rather than describing
  the new code. M2 measures that they are the only things that catch it.
- **`UnknownBag::insert` is deliberately EAGER**, and that asymmetry with
  `Once::set` is the point rather than an inconsistency: there the pre-existing
  ordering runs `value_to_unknown` first, and `decode/mod.rs` documents that as
  unobservable. Converting it to a closure would have been the silent behaviour
  change this slice exists to avoid, in the opposite direction.
- **The macro objection was satisfied, not overruled.** #575 declined to factor
  these guards into a `macro_rules!` because every hygiene guard in this repo
  reads TEXT, not expanded macros, so an error construction inside a macro body
  is invisible to any future rule that inspects one. That reasoning is intact
  and a helper *type* honours it: a function body is ordinary text, so the
  greppable-construction property is strictly better at 1 site than at 31.
- **The `unknown`-subtree residual is untouched.** No duplicate-key check looks
  *inside* an `UnknownValue`, at any level, and that is deliberate
  (crypto-design §6.2 rules 1 and 5 are scoped to material the reader
  interprets). `UnknownBag` rejects a repeat of the bag's **own** key and says
  nothing about the subtree hanging off it.
- **No spec change**, no fixture change, no new error variant. The
  `ManifestError` enum is byte-identical to `main`'s.
- **#602 / #603 / #587 / #596 / #610 / #611 / #612 / #613 stay open and
  untouched.**

---

## (3) What is next — with acceptance criteria

**(a) #613 — `ArraySortOrder` and `Unclassified` have no cross-language pin.**
Filed by the previous slice and its natural continuation; promoted here because
it is the only item in the queue whose absence a peer could *exploit*
(`Unclassified` is the arm #590's first implementation got wrong in the
direction a peer could choose). Note the shape change the issue spells out:
those rows are not `unknown`-subtree splices, so "7 shapes × 3 levels" and the
exact label-set assertion both have to move, and `_CAUSE_TO_RULE` needs a third
KIND of entry — those causes map to no §6.2 numbered rule at all.
**Acceptance:** both variants carry corpus rows, both languages replay them, and
the `causes_seen` assertion in `manifest_canonicality_kat_replays` is updated
rather than deleted.

**(b) #602 — `identity::card` and `sync::state` are outside #586's choke
point**, including the hybrid-signed `ContactCard::signed_bytes`. No live
exposure (all three build keys from fixed literals) but that is a property of
today's call sites, not of the encoder. **Acceptance:** those paths reject a
duplicate key too, or `card.rs`'s deliberately-permissive `encode_map` is
documented as a reviewed exception with the hostile-peer fixtures that need it
named.

**(c) #596 — a `manifest_body` cargo-fuzz target, the natural eighth.** The
`--diff-replay` wiring exists and the seed corpus is 27 bodies.
**Acceptance:** `core/fuzz/fuzz_targets/manifest_body.rs` exists,
`cargo fuzz run manifest_body` starts from the committed seeds, and
`CLAUDE.md`'s "Seven targets" line becomes eight.

**(d) #612 — two `core/tests/` KAT files past the 500-line threshold.**
`manifest_uniqueness_kat.rs` (848) and `manifest_canonicality_kat.rs` (788).
The previous baton widened the issue to cover both by comment. `core/tests/`
already holds six shared-helper directories, so the pattern exists.
**Acceptance:** both under 500, sharing their `SHAPES` / `cause_name` /
`Verdict` / `body_for` helpers through a `tests/<dir>/mod.rs` rather than a
second test binary.

**(e) #610 / #611 / #587 / #603 stay open and untouched.**

### Issues this slice closes — verify against the code, not this document

**#589** and **#582**. Per this repo's `(#N)`-not-`Closes #N` convention both
stay open until a human closes them; #582's acceptance is a line count, so
`wc -l core/src/vault/manifest/decode/entries.rs` settles it (362).

---

## (4) Open decisions and risks

### Two verification traps hit this session, both caught, both worth carrying

- **`cargo test` compiles unused imports that `clippy -D warnings` rejects.**
  Removing `BTreeMap` / `UnknownValue` from the two parser modules broke the
  `use super::*` inheritance their sibling `tests.rs` files relied on. I added
  both imports to both files; the full 99-binary suite passed **green**, and
  `cargo clippy --release --workspace --tests -- -D warnings` then failed on
  two unused imports — `entries/tests.rs` needed only `BTreeMap`,
  `decode/tests.rs` only `UnknownValue`. A green `cargo test` is not a green
  gate set, and the failing gate here was the one a contributor is least likely
  to run before pushing. Same family as the memory's "judge by EXIT CODE, not
  filtered output".
- **A comment can assert a property nobody measured.** Updating the top-level
  sweep's comment, I wrote that "a per-arm mutation is no longer expressible"
  now that the nine arms share one implementation — plausible, and it would have
  shipped unchecked. M5 (one arm passing the wrong `KEY_*` constant) exists
  because of that sentence, and it reds. The habit is the one #608's review
  named: grep — or mutate — for what the sentence claims, before the sentence
  ships.

### A scope decision worth recording

**The issue's own title undercounts its subject by a third.** #589 is titled
"21 hand-copied runtime guards" and its body says "21 construction sites across
~30 match arms". Measured, the tree held **31** `DuplicateKey` guards and **26**
`MissingField` unwraps; the 21 is #573's four nested parsers only, and the
top-level `parse_manifest_map` (#568) holds ten more of the identical idiom. An
implementation that took the title literally would have left the copied idiom in
the map every vault open parses first, while the commit message claimed the
invariant was established. Census before scoping, even when the issue looks
precise.

### Standing risks this slice does not remove

- **Five of the six PEP 723 deps remain unbounded** (`cryptography`, `pynacl`,
  `argon2-cffi`, `blake3`, `cbor2`), and `ed25519_verify` still has the "no
  exception means success" shape whose failure direction would be fail-**open**
  (#544 / #550).
- **`encode_manifest` validates no v1 sentinel** (#587).
- **`identity::card` and `sync::state` remain outside the duplicate-key choke
  point** (#602), including a hybrid-signed path.
- **`Unclassified` has no cross-language pin** (#613).
- **`record.rs` / `block.rs` do NOT carry this idiom — measured, not assumed.**
  The question came up while scoping, so it was censused rather than left open:
  `grep -c "is_some() {"` returns **0** in both, because they use a different
  shape entirely — one `BTreeSet<String> seen_keys` per map, checked once at the
  top of the key loop (`record.rs:792`/`:926`, `block.rs:1126`). There is
  nothing there to convert, so no follow-up is filed. Worth knowing that this is
  the shape the manifest's top-level parser *started* with and #575's review
  moved away from, for reasons that still apply there (a `key.clone()` per entry
  — an unwiped heap copy of decrypted plaintext — and a constant `"<record>"`
  placeholder instead of naming the repeated key). Both are pre-existing,
  data-free by construction, and explicitly reasoned about in `record.rs`'s own
  memory-hygiene comment at `:768-776`. Not a defect; recorded so the next
  person does not re-derive it.

### Housekeeping

**Done, not pending.** `.worktrees/canonicality-cause` removed and
`feature/canonicality-cause` deleted (merged as PR #614); the throwaway detached
baseline worktree at `/tmp/base-589`, used for the name-set and freshness diffs,
was removed. `git worktree list` shows the repo, two `.claude/worktrees/`
checkouts this session did not create, and this slice's.

---

## (5) How to resume — the exact commands

```bash
# FIRST, before reading the baton — cost four consecutive sessions once, costs
# nothing when it is actually run:
git fetch origin && git log --oneline main..origin/main

cd /Users/hherb/src/secretary/.worktrees/decoder-slot-invariant
pwd && git branch --show-current && git worktree list   # expect feature/decoder-slot-invariant

# --- the gates this slice is actually about ---
cargo test --release -p secretary-core --lib manifest        # expect 162 passed
cargo test --release -p secretary-core --lib manifest::decode::slot   # expect 11

# --- the cross-language contract (no CI job covers this one) ---
cargo test --release --workspace --features differential-replay

# --- the rest of the gate set ---
cargo fmt --all --check
cargo build --release --workspace                # separate from the test run ON PURPOSE
# Redirect, then echo $? — a `| grep` pipeline reports GREP's exit code:
cargo test --release --workspace > /tmp/suite.txt 2>&1; echo "CARGO EXIT: $?"
grep -E "^test result" /tmp/suite.txt | \
  awk '{p+=$4; f+=$6; i+=$8} END {print NR, p, f, i}'   # expect 99 2097 0 21
# NOT redundant with the above — `--tests` caught two unused imports this
# session that the full suite compiled green:
cargo clippy --release --workspace --tests -- -D warnings
touch core/src/lib.rs   # rustdoc caches; a ~5s run did nothing
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
cd core/fuzz && PATH="$HOME/.rustup/toolchains/nightly-2026-04-29-aarch64-apple-darwin/bin:$PATH" cargo check
cd -

uv run core/tests/python/conformance.py          # 26 sections; REG 26/26
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

# --- citation freshness: 90, and byte-identical to main. Note the explicit cd
#     INSIDE each subshell — a leading `cd` measured the wrong tree last session.
uv run core/tests/python/spec_test_name_freshness.py

# --- format / fixture invariants. ALL FOUR must be empty this slice. ---
git diff origin/main...HEAD --stat -- core/tests/data/
git diff origin/main...HEAD --stat -- core/fuzz/seeds/
git diff origin/main...HEAD -- ffi/secretary-ffi-uniffi/src/secretary.udl
# NORMATIVE docs only. A git pathspec glob CROSSES `/`, so `docs/*.md` would
# also match docs/manual/**; exclude the two non-normative trees by name.
git diff origin/main...HEAD --stat -- docs/ ':!docs/handoffs/' ':!docs/manual/'
```

Re-proving the slice's central property (deleting the one implementation reds
more than one test):

```bash
# Delete the `if self.0.is_some() { return Err(duplicate_key(field, index)); }`
# guard in core/src/vault/manifest/decode/slot.rs, then:
cargo test --release -p secretary-core --lib manifest
# Expect 11 failures across entries::tests, decode::tests and slot::tests.
# Restore and verify by sha256 — `git checkout` on a file is silent if the
# file was never committed, which is how a mutation gets left in place.
```

---

## (6) Where this document lives

`NEXT_SESSION.md` at the repo root is a **symlink**, retargeted this session to
`docs/handoffs/2026-09-05-decoder-slot-invariant-shipped.md`. This file is the
single authored baton — do not create a second copy at the root, and do not
sync it to `main` during a pause window (that produces an add/add conflict).
