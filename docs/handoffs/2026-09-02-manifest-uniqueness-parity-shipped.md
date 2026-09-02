# NEXT_SESSION.md — close the manifest uniqueness-rule divergence (#594)

Branch `feature/manifest-uniqueness-parity`, worktree `.worktrees/manifest-uniqueness-parity`,
base `ceb163af` (`main`, i.e. immediately after PR #598 merged).

This slice is **(a)** from the previous baton's queue. It is smaller than that baton
predicted, for a reason that is the most important thing in this document: **#594's
central claim was already false when the issue was filed**, and half the work it asks
for had shipped two PRs earlier. See §(1) "The premise correction".

**No issue was filed this session.** Nothing new was found that is not closed here.

---

## (1) What shipped

### Commits

| SHA | What |
|---|---|
| `a9b0349b` | the slice: verifier fix, cross-language corpus, seeds, Rust pin, two spec edits |
| `ffb15feb` | ROADMAP + CLAUDE.md; the `conformance_lib` file count 52 → 53 |
| *(this)* | the baton |

`16 files changed, 712 insertions(+), 14 deletions(-)` at `a9b0349b` — quoted at the
code-bearing commit so this baton does not falsify it.

### The premise correction — read this before citing #594

#594 says the manifest's uniqueness invariants are "enforced by Rust and stated
**NOWHERE** in `docs/`", and measures it as `grep -c "uniq" docs/vault-format.md` → 0.

**That grep is for the wrong word.** `docs/vault-format.md` §4.2 has stated all four
normatively since **`e29cb216` (PR #584, 2026-08-30)** — *before* #594 was filed during
PR #595's review — under the phrasing **"Repeated values are forbidden"**, and it names
the `recipients` exception explicitly. `CLAUDE.md` records it too ("plus the
repeated-array-value rules"). Verified by `git show 7fa4ddb3:docs/vault-format.md`, i.e.
the tree as it stood when the issue was written.

So the issue's "two halves that must land together" framing does not apply: half 1 was
done. Both prior batons carried the wrong premise forward, and the liveness check that
would have caught it is *reading the section*, not re-running the issue's own grep — which
is exactly what a first pass at this slice did before catching itself.

A comment recording all of this is on
[#594](https://github.com/hherb/secretary/issues/594#issuecomment-5502272785).

### Half 2 — the verifier — was entirely real

Measured by execution before the fix, splicing each shape into a hand-built body:

| position | Rust | Python (before) | §4.2 |
|---|---|---|---|
| `blocks[].block_uuid` | rejects (`DuplicateBlockUuid`) | **accepted** | forbidden |
| `trash[].block_uuid` | rejects (`DuplicateTrashUuid`) | **accepted** | forbidden |
| `vector_clock[].device_uuid` | rejects (`VectorClockDuplicateDevice`) | **accepted** | forbidden |
| `blocks[].vector_clock_summary[].device_uuid` | rejects (same variant, via `parse_vector_clock`) | **accepted** | forbidden |
| `blocks[].recipients[]` | **accepts** (no check in `parse_recipients`) | accepted | explicitly excepted |

**Why nothing in the tree could see it.** Sortedness and distinctness are independent —
`[x, x]` **is** sorted — and the §4.3 step-4 re-encode cannot see a repeat either: a body
carrying one re-encodes to itself byte for byte. The 21-row canonicality corpus is scoped
to §4.2's per-**item** table and mutates only `unknown` subtrees, so it never expressed an
array-level rule. That is not a defect in that corpus; it is a category it never claimed.

### What landed

- **`_check_sorted` → `_check_sorted_and_distinct`** (`conformance_lib/codec/manifest_decode.py`):
  the sortedness compare plus an adjacent-pair scan naming the repeated id in hex. Its
  four call sites are exactly §4.2's four constrained positions — putting both rules in
  the **name** is what stops that from being an accident a caller list must preserve.
  `recipients` keeps its sortedness-only inline check, with a comment saying why.
- **`core/tests/data/manifest_uniqueness_kat.json`** — a **separate** 6-row corpus
  (4 reject / 2 accept), generated from Rust ground truth by
  `core/tests/manifest_uniqueness_kat.rs` and replayed by both languages in CI
  (`manifest_uniqueness_kat_replays` + Section **MUQ**). Separate rather than folded into
  the canonicality corpus, whose `7 shapes × 3 levels = 21` assertion is itself a pin
  against a fixture of 21 identical rows.
- **Six `manifest_body` seeds**, so `differential_replay.rs` covers the same bodies as a
  third path — **21 → 27 inputs**, no wiring change (its per-target floor is `seen > 0`,
  and neither generator clears the shared seeds directory).
- **`accepts_duplicate_contact_uuid_in_recipients`** (`manifest/decode/entries/tests.rs`)
  pins §4.2's exception on the Rust side. **Nothing pinned it before.**
- **Two frozen-spec edits, no byte on disk changes.** §4.3 step 4 enumerated what the
  re-encode enforces and omitted that the repeated-value rules are **not** among them —
  the exact false inference `py_decode_manifest` made; it now says so, citing the rule-4
  (tags/floats) precedent for the same standing-apart arrangement. §4.2's repeated-value
  paragraph was raised to **MUST NOT / MUST**, matching the sort-discipline paragraph
  directly above it.

### Non-vacuity, by execution

Six mutation rounds. **Every restore verified by sha256**, never by `git diff` — which is
vacuous for untracked files, and most of this slice's files were untracked at the time
(the trap the #593 baton recorded, applied).

| # | Mutation | Result |
|---|---|---|
| M1 | distinctness scan no-opped (the pre-#594 behaviour) | exactly the 4 reject rows red; **MAS / MCK / MSH unmoved** |
| M2 | `recipients` "tidied up" to forbid repeats | exactly that one row reds |
| M3 | `_has_repeat` pinned `False` | all 5 repeat-bearing rows' control assertions fire |
| M4 | `_has_repeat` pinned `True` | the control row's all-distinct assertion fires |
| R1 | Rust `parse_blocks` dup check no-opped | the KAT reds on `blocks__duplicate_block_uuid` |
| R2 | Rust `parse_recipients` "tidied up" | the KAT **and** the new unit test red |

M1's isolation is the load-bearing half: the fix is not silently doing MAS's job or
MCK's.

### The measured result

- **2004 passed / 0 failed / 21 ignored across 99 binaries** (`cargo test --release
  --workspace`), from 2002 / 0 / 20 across 98 — exactly +2 tests, +1 binary, +1 ignored
  (the new generator).
- `cargo fmt --all --check`, `cargo build --release --workspace` (run **separately** from
  the test run on purpose), `cargo clippy --release --workspace --tests -- -D warnings` all clean.
- `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace` clean, **forced
  non-cached** (`touch core/src/lib.rs` first; the run took **6m12s** — a ~5 s run has
  done nothing, which is the trap #575 caught once).
- **`conformance.py` PASS**, 24/24 sections, REG reporting `24 drivers discovered, 24
  registered`.
- **Both gates no CI job covers**: `cargo check --release --features differential-replay
  --tests -p secretary-core` clean; `cargo test --release --workspace --features
  differential-replay` clean with `[manifest_body] replayed 27 input(s)`. `core/fuzz`
  checks under the pinned nightly.
- **All six hygiene guards pass, each `--self-test` first.**
- **`spec_test_name_freshness.py` = 90**, the baseline, with a **member set identical to
  `main`'s** — `comm` empty in both directions over the citation text (not the line
  numbers, which shifted because this slice edits `docs/vault-format.md`), verified
  against a throwaway detached worktree of `main` rather than assumed from the count.
- `pyflakes` clean over the entrypoint and the whole package.
- **Format / fixture invariants:** `core/tests/data/` gains **exactly one** path and
  modifies **zero**; the UDL diff is **empty**; `core/src/` changes are one file, +60
  lines, entirely inside a `#[cfg(test)] mod tests` (`entries.rs:525`).
- `core/fuzz/seeds/` gains six files and modifies zero — **unlike the previous two
  slices, this one is deliberately non-empty there.** Don't copy the old baton's
  "must be EMPTY" line forward.

---

## (2) What this slice does **not** claim

- **The corpus proves agreement on 6 specific bodies, not on all inputs.** It is a
  known-answer test. The randomised and seed-bounded coverage around it (Property F,
  differential replay) widen the input space; nothing here establishes agreement on an
  arbitrary manifest body.
- **It does not close #586.** The fixture bodies are built by handing `encode_manifest` a
  `Manifest` with duplicate entries — the encoder does not deduplicate, so it emits bodies
  its own decoder rejects. That is #586, used deliberately as the cheapest correct source
  of ground-truth bytes and **documented in the generator's module doc**, not overlooked.
  If #586 is ever closed by validating on the encode side, `generate_manifest_uniqueness_kat`
  starts failing at the `encode_manifest` call, and the fix is ciborium surgery — the way
  `array_sort_disciplines_are_enforced_and_not_vacuous` already builds its bodies.
- **`recipients` remains an accepted repeat, on both sides, by design.** Four positions
  are constrained; the fifth is not. Do not read "the manifest forbids repeats" without
  the exception.
- **Section MUQ's control is a property of the fixture bytes, not a second decoder.** It
  asserts each rejecting row is sorted **and** carries a repeat — so only a distinctness
  check can reject it. That is narrower than MCK's naive-reader control and is the honest
  description of it.
- **The `clean-room conformance` job still does not block.** It is not in `main`'s
  `protect_main` ruleset by name (unchanged since #546). MUQ runs there; it gates nothing.

---

## (3) What is next — with acceptance criteria

**(a) #597 — the nondeterministic rejection detail.** Small, pre-existing on `main`, and
worth doing before anyone else takes a byte-exact `--diff-replay` baseline.
`py_decode_contact_card` reports whichever required key it reaches first while iterating a
`frozenset`, and CPython salts string hashing per process, so `pre_sig.cbor` alternates
between `self_sig_ed` and `self_sig_pq` across runs. **Acceptance:** the same input under
two different `PYTHONHASHSEED` values yields an identical `detail`; verdicts (`status` /
`error_class`) unchanged. Sorting the required-key set before iterating is the whole fix;
the pin is the two-seed comparison.

**(b) #590 — `ManifestError::NonCanonicalEncoding` collapses causes with no locator, on
the every-open path.** Unchanged from the last two batons, including its correction: **six
of the 21** canonicality-corpus rows land on that one undifferentiated variant, not all of
them — `*__rule4_float` is caught earlier by `reject_floats_and_tags` as
`CanonicalError::FloatRejected`, which already carries a field hint. Do not write "fires
five ways". **Acceptance:** the variant carries a fieldless cause discriminant plus a byte
offset (the `CborFault` shape, so it stays data-free by construction); each of those six
rows names its own cause; the payload-hygiene guard passes with **no new allowlist entry**.

**(c) #589 — the 21 duplicate-key guards are hand-copied, not a type invariant.**
**Acceptance:** expressed once; all 21 sites route through it; deleting the single
implementation reds more than one test.

**(d) #596 — a `manifest_body` cargo-fuzz target, the natural eighth.** The `--diff-replay`
wiring exists and the seed corpus is now **27** bodies rather than 21. **Acceptance:**
`core/fuzz/fuzz_targets/manifest_body.rs` exists, `cargo fuzz run manifest_body` starts
from the committed seeds, and `CLAUDE.md`'s "Seven targets" line becomes eight.

**(e) #586 / #587 stay open and untouched.** The encoder can still emit or sign a body its
own decoder would reject — and this slice **relies** on that, see §(2). **Do not record
these as addressed.**

### Issues this slice closes — verify against the code, not this document

**#594.** Per this repo's `(#N)`-not-`Closes #N` convention it stays open until a human
closes it. Nothing here closes **#597, #590, #589, #596, #586, #587**.

---

## (4) Open decisions and risks

### Rulings taken (all four put to the user and confirmed before implementation)

1. **A cross-language KAT fixture, not a Python-only guard section.** The weaker option
   would have pinned agreement by reading both sides against the same spec paragraph —
   which is precisely the reasoning that produced #594. Cost: a generator + fixture +
   section instead of one section.
2. **A separate corpus, not five more rows on `manifest_canonicality_kat.json`.** That
   fixture's `7 shapes × 3 levels = 21` assertion is a pin in its own right, and its
   module doc scopes it to §4.2's per-item table; extending it would have required
   loosening both.
3. **#597 kept out of scope.** Orthogonal, and the previous session deferred it for a
   reason that still holds.
4. **Rust `parse_recipients` deliberately NOT given a uniqueness check.** Adding one would
   narrow a v1-frozen decoder for no security gain: a repeated `contact_uuid` is
   idempotent, unlike a duplicate `block_uuid` (two entries claiming one block, which two
   conformant readers could resolve differently). Pinned on both sides instead — R2 proves
   the pin fires.

### A verification trap worth carrying forward

`spec_test_name_freshness.py` was compared to `main` on **citation text**, not on the
printed `L<n>` lines. This slice edits `docs/vault-format.md`, so every citation below the
edit shifts line number; a naive `comm` on the raw output would have shown dozens of
spurious differences and buried a real one. The count (90) alone is also insufficient —
one citation resolving while another breaks keeps it at 90.

### Standing risks this slice does not remove

- **Five of the six PEP 723 deps remain unbounded** (`cryptography`, `pynacl`,
  `argon2-cffi`, `blake3`, `cbor2`), and `ed25519_verify` still has the "no exception
  means success" shape whose failure direction would be fail-**open** (#544 / #550).
- **The `clean-room conformance` job is not a required check.**
- **The frozen-spec edits are reversible and change no byte on disk**, but they are edits
  to a frozen document: `docs/vault-format.md` §4.2 (one paragraph, RFC 2119 keywords) and
  §4.3 step 4 (one clause).

### Housekeeping left undone

Two merged worktrees are still on disk — `.worktrees/conformance-split` and
`.worktrees/manifest-canonicality-pin`, both on `[gone]` branches with clean trees.
`git worktree remove` + `git branch -D` was declined by the permission classifier this
session. Harmless, but `git worktree list` is noisier than it should be.

---

## (5) How to resume — the exact commands

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-uniqueness-parity
pwd && git branch --show-current && git worktree list   # expect feature/manifest-uniqueness-parity

# --- the gate this slice is actually about ---
uv run core/tests/python/conformance.py                 # expect exit 0, "PASS", 24/24 sections
uv run --with pyflakes python -m pyflakes core/tests/python/conformance.py \
                                          core/tests/python/conformance_lib

# --- the cross-language contract (no CI job covers this one) ---
cargo test  --release --workspace --features differential-replay
cargo check --release --features differential-replay --tests -p secretary-core
# expect [manifest_body] replayed 27 input(s) — 21 canonicality + 6 uniqueness

# --- the rest of the gate set ---
cargo fmt --all --check
cargo build --release --workspace                       # separate from the test run ON PURPOSE
cargo test  --release --workspace                       # expect 2004 passed / 0 failed / 21 ignored
cargo clippy --release --workspace --tests -- -D warnings
touch core/src/lib.rs   # rustdoc caches; a ~5s run did nothing (this one takes ~6 min)
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

# --- citation freshness: baseline is 90; compare the MEMBER SET, not the L<n> lines ---
uv run core/tests/python/spec_test_name_freshness.py

# --- format / fixture invariants ---
git diff main...HEAD --stat -- core/tests/data/                    # exactly ONE added path, zero modified
git diff main...HEAD --stat -- core/fuzz/seeds/                    # SIX added, zero modified (not empty!)
git diff main...HEAD -- ffi/secretary-ffi-uniffi/src/secretary.udl # EMPTY
```

Regenerating the uniqueness corpus after an intentional protocol change (human-reviewed
before commit; it also rewrites the six `core/fuzz/seeds/manifest_body/uniq__*.bin`):

```bash
cargo test --release --workspace -- --ignored generate_manifest_uniqueness_kat --nocapture
```

The generator **asserts** each verdict against `decode_manifest` rather than recording it.
If it panics, the fix is either the decoder (a regression) or the `CASES` table (a
reviewed §4.2 change) — never regenerating until it is quiet.

---

## (6) Where this document lives

`NEXT_SESSION.md` at the repo root is a **symlink**, retargeted this session to
`docs/handoffs/2026-09-02-manifest-uniqueness-parity-shipped.md`. This file is the single
authored baton — do not create a second copy at the root, and do not sync it to `main`
during a pause window (that produces an add/add conflict).
