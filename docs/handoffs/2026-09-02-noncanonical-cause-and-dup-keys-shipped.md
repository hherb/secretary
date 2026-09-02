# NEXT_SESSION.md — a cause and a locator for the every-open rejection (#590), and the encoder's duplicate-key hole (#586)

Branch `feature/noncanonical-cause`, worktree `.worktrees/noncanonical-cause`,
base `19297111` (`main`, i.e. immediately after PR #599 merged).

This slice is **(b)** from the previous baton's queue, taken ahead of **(a)** on
blast radius: #590 is on the path every vault open takes, #597 is a diagnostic
nondeterminism in a test script. **#586 was folded in on the user's explicit
instruction** after this session found it closed-as-COMPLETED on the tracker with
the code unfixed — see §(4).

**No issue was filed this session.** Nothing was found that is not closed here.

---

## (1) What shipped

### Commits

| SHA | What |
|---|---|
| `c7b8a68d` | the slice: cause enum, classifier, duplicate-key check, four error folds, tests, ROADMAP + CLAUDE.md |
| *(this)* | the baton — a commit cannot cite its own SHA, so this row stays symbolic |

`19 files changed, 1393 insertions(+), 30 deletions(-)` at `c7b8a68d` — quoted at the code-bearing commit so this
baton does not falsify it.


### The starting-state correction — read this before citing the tracker

The baton this session opened pointed at the **#593** handoff, and named **#594**
as the next slice. Both were stale: PR #599 had merged `19297111` while that
document was being read, so #594 was already done and local `main` was behind.

More importantly, **#586 was CLOSED as COMPLETED on 2026-09-02 with no comment,
and `CanonicalMap::push` still rejected nothing.** That is the *inverse* of this
repo's usual `(#N)`-not-`Closes #N` drift (done-but-open): here the tracker said
done and the code said otherwise. The previous baton, written the same day, also
listed #586 as "open and untouched" — so two records disagreed with the tracker
and agreed with each other. The liveness check that catches this is reading the
**code**, not the issue state, in either direction.

### The two defects

**#590 — the rejection said nothing useful, on the every-open path.**
`ManifestError::NonCanonicalEncoding` was a single fieldless variant whose
`#[error]` text named four candidate causes with "e.g." and carried no position.
#572 had just *narrowed* the accepted-manifest set for anything this codebase did
not write, so the reader most likely to hit it is a peer or clean-room client
with an encoder bug — handed four candidates and no locator.

**#586 — the encoder could emit, and sign, an ambiguous body.** `CanonicalMap`
sorts its keys at serialise time and did not reject a duplicate, so
`encode_manifest` could produce a body carrying one key twice and `sign_manifest`
would sign it. Two conformant readers may resolve such a body differently while
both accepting the signature.

### What landed

- **`NonCanonicalCause`** (`core/src/vault/manifest/cause.rs`) — a fieldless enum
  with four arms (`ArraySortOrder` / `IndefiniteLength` / `NonShortestForm` /
  `Unclassified`), plus a private `OffsetSuffix` `Display` adapter so the byte
  locator renders as prose and never as a `Some(41)` debug form.
- **`ManifestError::NonCanonicalEncoding { cause, at }`** — `at` is the offset of
  the first differing byte, `None` only when one buffer is a strict prefix of the
  other.
- **`classify_non_canonical`** (`manifest/decode/classify.rs`, 185 lines) — a pure
  function over the parsed `Manifest` and the two buffers the check already holds.
- **`CanonicalError::DuplicateKey { index }`** and
  `CanonicalMap::check_no_duplicate_keys`, called once from `to_canonical_vec`.
- **`canonical_order` extracted** from `Serialize` so the check and the serialiser
  cannot drift onto two different orderings — the check's whole claim is that
  adjacency in *that* order means equality.
- **`RecordError::CanonicalDuplicateKey` / `BlockError::CanonicalDuplicateKey`**,
  new variants mirroring the existing `CanonicalSizeBoundExceeded` precedent;
  `card.rs` and `bundle.rs` fold to their `Malformed(&'static str)` arms as they
  already do for `CapacityBoundExceeded`.

### Three design points that are load-bearing, not incidental

1. **The cause is advisory; the byte comparison is the verdict.** `classify_non_canonical`
   runs *only after* the comparison has decided to reject, so a misclassification
   changes a diagnostic and never an acceptance. That is the entire reason a
   positional heuristic — "read the CBOR head at the first differing byte" — is
   acceptable on a security path. Do not promote it into the decision.
2. **`ArraySortOrder` is the only decisive arm, and runs first.** It is read off
   the parsed `Manifest`, not off a byte position: `encode_manifest` sorts all
   five arrays, so an unsorted input always diverges and a sorted one can never
   diverge *because of* order. It is also the cause a clean-room implementer is
   likeliest to hit, since #572's narrowing is exactly about array order.
3. **`Unclassified` is a real outcome, not a gap to close.** Known-key map
   disorder leaves an ordinary text head at the divergence, and no cause can be
   proven from the bytes. `decode_manifest_rejects_a_non_canonical_body` asserts
   the honest answer, so a future "improvement" that guesses reds.

### Two things that did NOT need doing, both measured rather than assumed

- **No allowlist row, and no `DATA_FREE_TYPES` registration.** The `thiserror`
  derive on `NonCanonicalCause` is load-bearing, not cosmetic: the payload guard
  credits an enum carrying `#[error(...)]` in its body as data-free by recursion
  (tier 2 of `is_data_free`). A plain fieldless enum would have needed a config
  entry — which is what `CborFault`, a plain struct, has at
  `payload_guard/config.py:35`. Proven non-vacuous by mutation — see "Non-vacuity, by execution" below.
- **No frozen-spec edit.** crypto-design §6.2 rule 5 already forbids duplicate map
  keys flatly, and says outright that the reader-side scoping is "not a licence
  for an encoder". So #586 makes the encoder conformant with an **already
  normative** rule. This is the opposite of #600, the array-**element** twin,
  where §4.2's writer half genuinely had to be raised to MUST NOT. `git diff
  main...HEAD -- docs/` is empty.

### Non-vacuity, by execution

- **Payload guard.** `NonCanonicalCause::Unclassified` mutated to carry a
  `String`: the guard fires with `cause.rs:75 / variant Unclassified interpolates
  0: String`. Restored and **verified by sha256**
  (`1aced4e4…dc4b50`), not by `git diff` — `cause.rs` is untracked, which is
  precisely the vacuous-check trap the #593 baton recorded.
- **The corpus now pins its own split.** `manifest_canonicality_kat_replays`
  asserts a cause per row *and* the 6/3 count: exactly six of the 21 rows reach
  the re-encode (rules 2 and 3, three levels each), and the three `rule4_float`
  rows are caught earlier by `reject_floats_and_tags`. **That fact was carried by
  three consecutive handoffs in prose and by nothing in code.** Its shape match is
  fail-closed: an unrecognised rejecting shape panics rather than passing.
- **`expect_rejected` is the broadest pin.** Every caller reverses exactly one
  §4.2 array, so one assertion covers all five sort disciplines; a classifier that
  fell through to the byte head would report `Unclassified` and red every case.
- **Three code mutations, every restore verified by sha256.**

  | # | Mutation | Result |
  |---|---|---|
  | M1 | `classify_non_canonical` neutered to always return `Unclassified` | **6 red** — 2 classifier unit tests, 3 decode tests, and `manifest_canonicality_kat_replays` |
  | M2 | `check_no_duplicate_keys` short-circuited to `Ok(())` (the pre-#586 behaviour) | **6 red** — 4 `canonical::value` tests and *both* end-to-end `encode_manifest` tests |
  | M3 | the `Borrowed` exclusion "tidied up" so the walk recurses into forward-compat subtrees | **4 red** — the new negative control fails *first*, alongside the two pre-existing forward-compat tolerance tests (manifest **and** record) and the corpus replay |

  M3 is the one that matters most: it is the plausible future "cleanup", and the
  guardrail names itself before the corpus does. **M3 also caught a trap in its
  own first attempt** — `cargo fmt` had reformatted the match arms, so the
  patch silently did not apply and the suite reported 508 passed. A mutation
  that fails to apply looks exactly like a mutation nothing catches; assert the
  patch applied before believing a green result.

### The measured result

- **`cargo test --release --workspace`: 99 binaries, 2038 passed, 0
  failed, 21 ignored**, against a `main` baseline **measured this session** (not
  taken from the previous baton) of **99 / 2004 / 0 / 21** in a throwaway detached
  worktree. Test-name sets diffed: **34 added, 0 removed.**
- `cargo fmt --all --check`, `cargo build --release --workspace` (run separately
  from the test run on purpose), `cargo clippy --release --workspace --tests --
  -D warnings` all clean.
- `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace` clean, forced
  non-cached with `touch core/src/lib.rs` first.
- **`conformance.py` PASS**, 24/24 sections, REG reporting `24 drivers discovered,
  24 registered`. The clean-room verifier needed **no change**: #590 alters Rust
  diagnostic text only, and `differential_replay.rs` scores reject-vs-reject as
  agreement without comparing `detail`.
- **Both gates no CI job covers**: `cargo test --release --workspace --features
  differential-replay` clean; `core/fuzz` checks under the pinned nightly.
- **All six hygiene guards pass, each `--self-test` first.**
- **`spec_test_name_freshness.py` = 90, and its output is byte-identical to
  `main`'s** — diffed in full against a detached `main` worktree, not inferred
  from the count (a count is preserved when one citation resolves and another
  breaks).
- **Format / fixture invariants — all four empty:** `core/tests/data/`,
  `core/fuzz/seeds/`, the UDL, and `docs/`.

---

## (2) What this slice does **not** claim

- **The cause is a classification, not a proof.** Only `ArraySortOrder` is
  decisive. `IndefiniteLength` and `NonShortestForm` are read from the CBOR head
  at the first divergence, which is sound for every shape in the corpus and for
  every shape anyone has written down — but it is a positional heuristic, and a
  body whose divergence lands on an unrelated head reports `Unclassified`. That is
  by design and costs nothing, because the verdict never depends on it.
- **#586 is closed for map KEYS only.** Duplicate array **elements** are #600 and
  remain open — and the uniqueness KAT generator still **depends** on that gap to
  produce its ground-truth bytes. The two were measured independent: the whole
  uniqueness corpus is green across this change. Do not record #600 as addressed.
- **`Borrowed` subtrees are not walked, deliberately.** A duplicate key inside a
  forward-compat `unknown` subtree still encodes. That is the documented v1
  residual, not an oversight.
- **The reachable producer is narrow.** `Record.fields` and every `unknown` bag are
  `BTreeMap`s, so the only way to build a duplicate is an `unknown` key colliding
  with a known §4.2 key — which `decode_manifest` never produces (it parses such a
  key as the known one). The producer is always a caller building a value in
  memory: merge, repair, block-CRUD.
- **The duplicate check adds a second sort per map.** `Serialize` already sorts;
  the check sorts again. Maps here carry ~9 keys, so the cost is negligible, but
  it is a real duplicate of work on a hot path and is disclosed rather than
  hidden. Folding the check into `Serialize` would lose the typed variant
  (`S::Error` collapses it to a generic serialisation fault), which is why it was
  not done.
- **#587 stays open and untouched.** `encode_manifest` still validates no v1
  sentinel.

---

## (3) What is next — with acceptance criteria

**(a) #597 — the nondeterministic rejection detail.** Now the top of the queue,
unchanged from the last baton and re-verified this session: `KNOWN_CARD_KEYS` is a
**set literal** at `conformance_lib/codec/card.py:48`, aliased to
`REQUIRED_CARD_FIELDS` and iterated at `:58`, so CPython's per-process string-hash
salt decides which missing key is reported. (The last baton corrected `frozenset`
→ set; that correction holds.) **Acceptance:** the same input under two different
`PYTHONHASHSEED` values yields an identical `detail`; verdicts (`status` /
`error_class`) unchanged; sort the required-key set before iterating and pin it
with the two-seed comparison. The issue's scope line is worth honouring — *every*
`*_REQUIRED_KEYS` membership check, not just the card decoder.

**(b) #600 — `encode_manifest` can emit array-element repeats its own decoder
rejects.** Promoted by this slice, because #586's map-key twin is now closed and
the asymmetry is visible: the encoder is a documented non-conformant writer
against §4.2's writer half. **Acceptance:** the encoder rejects a repeat in each
of the four constrained arrays (`recipients` explicitly excepted);
`generate_manifest_uniqueness_kat` starts failing at its `encode_manifest` call,
which is the tripwire its module doc describes, so the generator must move to
building bodies by ciborium surgery the way
`array_sort_disciplines_are_enforced_and_not_vacuous` already does. **Do not
regenerate the corpus to make it pass.**

**(c) #589 — the 21 duplicate-key guards are hand-copied, not a type invariant.**
**Acceptance:** expressed once; all 21 sites route through it; deleting the single
implementation reds more than one test.

**(d) #596 — a `manifest_body` cargo-fuzz target, the natural eighth.** The
`--diff-replay` wiring exists and the seed corpus is 27 bodies. **Acceptance:**
`core/fuzz/fuzz_targets/manifest_body.rs` exists, `cargo fuzz run manifest_body`
starts from the committed seeds, and `CLAUDE.md`'s "Seven targets" line becomes
eight.

**(e) #587 stays open and untouched.**

### Issues this slice closes — verify against the code, not this document

**#590**, and **#586 in code** (its GitHub issue was already closed, incorrectly,
before the fix existed). Nothing here closes **#597, #600, #589, #596, #587**.

---

## (4) Open decisions and risks

### Rulings taken

1. **#586 folded into this PR**, on the user's explicit instruction after the
   closed-but-unfixed state was put to them with three options. The alternative
   offered — scoping the fix to `encode_manifest` alone — was declined in favour
   of the shared choke point, which is why `record`, `block` and `bundle` encode
   paths gained the check too.
2. **The check at `to_canonical_vec`, not on `push`.** `push` stays infallible:
   making it fallible puts a `?` on ~30 call sites whose keys are provably-unique
   `KEY_*` literals, to catch a condition only the two forward-compat `unknown`
   loops can create. The choke point also covers construction paths nobody has
   written yet.
3. **A dedicated `CanonicalDuplicateKey` variant per layer**, rather than reusing
   each layer's existing decode-side `DuplicateKey`. The two conditions are
   different — "the bytes you gave me repeat a key" versus "the value you asked me
   to encode repeats one" — and the `CanonicalSizeBoundExceeded` precedent already
   establishes the mirror-variant pattern. Cost: one extra arm in
   `record_error_to_cbor_fault`, which the compiler demanded.
4. **`at` is reported for every cause, including `ArraySortOrder`.** The design
   presented to the user said `None` there; carrying the real offset is strictly
   more informative and makes the contract uniform (`at` locates, `cause`
   explains). Recorded because it differs from what was approved.

### Four verification traps worth carrying forward — all one root cause

The root cause in every case below is the same: **judging a command by its
filtered output instead of its exit status.** Three of the four produced a
confident green that was wrong, and the fourth was caught only by CI.

- **ANSI colour defeats an anchored `^error` filter — this one reached CI.**
  `RUSTDOCFLAGS="-D warnings" cargo doc ... 2>&1 | grep -E "^(error|warning)"`
  matched nothing and the trailing `echo "RUSTDOC EXIT DONE"` printed
  unconditionally, so the gate read as clean. Cargo colourises when it thinks a
  terminal is attached, so the line is `\e[1m\e[91merror\e[0m: ...` and does not
  start with `error`. CI has no TTY, hence no colour, hence a real failure:
  `unresolved link to \`super::decode::classify\`` — a **public** item's
  intra-doc link into a **private** module, exactly the #92 gate's job. Fixed by
  demoting the link to plain code formatting. Re-run the gate by capturing to a
  file and echoing `$?`.
- **A `cargo test | grep` pipeline reports GREP's exit code, not cargo's.** The
  first suite run this session appeared to pass at "exit 0" while reporting 40
  binaries against a 99-binary baseline. Redirect to a file and echo `$?`
  immediately; never let a filter stand between you and the exit code.
- **A mutation that fails to APPLY looks exactly like a mutation nothing
  catches.** M3's first patch missed because `cargo fmt` had reformatted the
  match arms; the suite reported 508 passed and 0 failed, which reads as "the
  guardrail is vacuous" when it actually means "you tested the unmutated tree".
  Assert the substitution succeeded (`assert s.count(old) == 1`) before drawing
  any conclusion from a green run.
- **A suite launched before your last edit does not contain it.** The second run
  reported 2034 with 30 added tests when 33 had been written — the three newest
  had landed while cargo was still compiling. The tell was a name-set diff, not
  the total. **Diff the test NAME SET against a measured baseline**; a total alone
  cannot distinguish "3 not yet compiled" from "3 deleted".

### Standing risks this slice does not remove

- **Five of the six PEP 723 deps remain unbounded** (`cryptography`, `pynacl`,
  `argon2-cffi`, `blake3`, `cbor2`), and `ed25519_verify` still has the "no
  exception means success" shape whose failure direction would be fail-**open**
  (#544 / #550).
- **`encode_manifest` remains a non-conformant writer** for §4.2's repeated-array-
  value rules (#600) and validates no v1 sentinel (#587).
- **`NonCanonicalCause` is a public enum on a not-`#[non_exhaustive]` error type.**
  Adding an arm is a compiler-checked surface change. Nothing outside `core/src`
  matches `NonCanonicalEncoding` today — every bridge fold binds
  `VaultError::Manifest(_)` with a wildcard — but that is a property of the current
  fold shape, not a guarantee; `cargo build --release --workspace` is what confirms
  it.

---

## (5) How to resume — the exact commands

```bash
cd /Users/hherb/src/secretary/.worktrees/noncanonical-cause
pwd && git branch --show-current && git worktree list   # expect feature/noncanonical-cause

# --- the gates this slice is actually about ---
cargo test --release --workspace --lib manifest         # cause + classify + encode
cargo test --release -p secretary-core --test manifest_canonicality_kat

# --- the cross-language contract (no CI job covers this one) ---
cargo test  --release --workspace --features differential-replay
cargo check --release --features differential-replay --tests -p secretary-core

# --- the rest of the gate set ---
cargo fmt --all --check
cargo build --release --workspace                       # separate from the test run ON PURPOSE
# Redirect, then echo $? — a `| grep` pipeline reports GREP's exit code:
cargo test --release --workspace > /tmp/suite.txt 2>&1; echo "CARGO EXIT: $?"
grep -E "^test result" /tmp/suite.txt | \
  awk '{p+=$4; f+=$6; i+=$8} END {print NR, p, f, i}'   # expect 99 2038 0 21
cargo clippy --release --workspace --tests -- -D warnings
touch core/src/lib.rs   # rustdoc caches; a ~5s run did nothing
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
cd core/fuzz && PATH="$HOME/.rustup/toolchains/nightly-2026-04-29-aarch64-apple-darwin/bin:$PATH" cargo check
cd -

# --- the clean-room verifier (unchanged by this slice, but it gates merges) ---
uv run core/tests/python/conformance.py                 # expect exit 0, "PASS", 24/24
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

# --- citation freshness: 90, and byte-identical to main (no docs/ edit here) ---
uv run core/tests/python/spec_test_name_freshness.py

# --- format / fixture invariants: all FOUR must be EMPTY ---
git diff main...HEAD --stat -- core/tests/data/
git diff main...HEAD --stat -- core/fuzz/seeds/
git diff main...HEAD -- ffi/secretary-ffi-uniffi/src/secretary.udl
git diff main...HEAD --stat -- docs/
```

Re-proving the payload guard is not vacuous (the mutation this slice used):

```bash
# Make the cause enum carry a String; the guard must fire on cause.rs.
# Restore by sha256 — `git diff` is VACUOUS for cause.rs, which is untracked.
shasum -a 256 core/src/vault/manifest/cause.rs   # 1aced4e4…dc4b50 before and after
```

---

## (6) Where this document lives

`NEXT_SESSION.md` at the repo root is a **symlink**, retargeted this session to
`docs/handoffs/2026-09-02-noncanonical-cause-and-dup-keys-shipped.md`. This file
is the single authored baton — do not create a second copy at the root, and do not
sync it to `main` during a pause window (that produces an add/add conflict).
