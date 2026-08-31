# NEXT_SESSION.md — pin the #572 manifest canonicality contract (#578, #583, #585, #592)

Branch `feature/manifest-canonicality-pin`, worktree `.worktrees/manifest-canonicality-pin`,
base `e29cb216` (`main`, i.e. immediately after PR #584).
**Fourteen commits** — `git rev-list --count main..HEAD` = 14, from `2f260a34` (the design
spec) through this baton. Thirteen landed before it; this baton's commit is the fourteenth.
The tip SHA is deliberately not quoted: this document *is* the tip commit, so any SHA
written for it is falsified by its own amendment.
**Not pushed at time of writing; no PR yet. A whole-branch review runs before the push.**

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
| *(this)* | **T9** — closeout: full gate set, three doc corrections, this baton |

`31 files changed, 4300 insertions(+), 149 deletions(-)` before this commit.

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
- **The two gates no CI job covers**, both clean at HEAD:
  `cargo check --release --features differential-replay --tests -p secretary-core`, and
  `core/fuzz` under the pinned nightly. `--workspace` builds **neither** (`core/fuzz` is
  workspace-`exclude`d; `differential_replay.rs` is `#![cfg(feature = …)]`), which is
  exactly how they have broken undetected before.
- **`spec_test_name_freshness.py` = 90**, the baseline, with a **member set identical to
  `main`'s** — `comm` empty in both directions on a file-qualified comparison, verified
  against a throwaway detached worktree of `main` rather than assumed from the count.
- **No on-disk format change.** `git diff main...HEAD --stat -- core/tests/data/` shows
  **exactly one added path** (`manifest_canonicality_kat.json`, +109) and **zero modified**.
  The uniffi `.udl` diff is **empty**. The only `core/src/` change is +131 lines **inside
  `mod tests`** in `core/src/vault/record.rs` — no public API, no shipped behaviour.

---

## (2) What this slice does **not** claim — read this before citing it

Two boundaries, both stated as boundaries rather than caveats, because the wider reading
is the one a summary naturally reaches for.

**The corpus proves agreement on 21 specific rows, not on all inputs.** Seven subtree
shapes (five §6.2 rule violations plus two accepting controls) x three nesting levels
(manifest body, `blocks[i]`, `trash[i]`). It is a **known-answer test**, not a proof: the
two readers agree on those 21 inputs at those three levels. Nothing here establishes that
they agree on an arbitrary manifest body. The randomized coverage (#578's Property F) and
the `manifest_body` differential-replay target are what widen the input space, and both are
single-language or seed-bounded respectively.

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

---

## (3) What is next — with acceptance criteria

### Immediate: whole-branch review, then push and open the PR

CI has **never run on this branch**. The controller drives the push after the review.

### Then, in the order the slice's own findings argue for

**(a) #590 — "`ManifestError::NonCanonicalEncoding` collapses five causes with no
locator, on the every-open path".** This slice makes #590 *more visible*, which is the
argument for doing it next. Be exact about how far, because the obvious overstatement is
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

**(b) #589 — the 21 duplicate-key guards are hand-copied, not a type invariant.**
**Acceptance:** the duplicate-key check is expressed once (a helper or a type that cannot
be constructed with a repeat), all 21 hand-copied sites route through it, and deleting the
single implementation reds more than one test.

**(c) A `manifest_body` cargo-fuzz target — the natural eighth.**
The `--diff-replay` wiring landed in this slice specifically to make this cheap.
**Acceptance:** `core/fuzz/fuzz_targets/manifest_body.rs` exists, `cargo fuzz run
manifest_body` starts from the 21 seeds already committed at
`core/fuzz/seeds/manifest_body/`, and `CLAUDE.md`'s "Seven targets" line becomes eight.

**(d) #593 — split `conformance.py`.** Filed during this closeout, per the design spec's
own §10 mitigation. It went 4303 → **6107** lines in one slice. **Acceptance:** a
`core/tests/python/conformance/` package behind a thin entrypoint, with the PEP 723 header
still the sole dependency declaration, `uv run core/tests/python/conformance.py` working
verbatim, and the `--diff-replay` CLI contract byte-identical. The issue lists all four
constraints.

**(e) #586 / #587 stay open and untouched.** The encoder can still emit or sign a body its
own decoder would reject. The design spec's §6 constraint 1 avoids *tripping* #586; it does
not fix it. **Do not record these as addressed.**

### Issues this slice closes — verify against the code, not against this document

**#578, #583, #585, #592.** This repo cites fixes as `(#N)` and never `Closes #N`, so each
outlives its fix until a human closes it. Nothing in this slice closes **#589, #590, #586,
#587, #569** (path 3, `identity/card.rs`, untouched).

---

## (4) Open decisions and risks — the full record

### Rulings taken on the user's behalf

Thirteen decisions were recorded in the slice ledger
(`.superpowers/sdd/2026-08-31-manifest-canonicality-pin/progress.md`). Each carries a
"cost if wrong" in that file; the substance is here.

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

### Deferred minors — surfaced, not fixed, and each is a real known gap

Every one of these was raised in review and consciously left. **None is cosmetic-by-default;
read the reason before dismissing one.**

| # | Item | Why deferred |
|---|---|---|
| T1 | The brief's step-2 "watch it fail" was folded into step 6's mutation rather than run as a discrete step | Implementer disclosed it; reviewer judged it substantively harmless — three independent asserts over the same 256-sample loop, and the step-6 mutation is exactly what the brief specifies |
| T2 | `_check_canonical_item`'s major-7 branch does not check that the one-byte simple-value form (`ai=24`) is used only for values ≥ 32, so a redundant encoding of an in-range simple value passes rule 3 | No live producer |
| T2 | No recursion-depth guard — pathological nesting raises Python's `RecursionError`, not `ValueError` | Fail-closed (raises rather than hanging or mis-scanning); inconsistent error **typing** only |
| T2 | Finding 2's `_decode_head` change makes `_scan_item`'s own major-6 indefinite-tag check (`raise ValueError(f"indefinite-length tag at offset {pos}")`, inside `_scan_item`) unreachable dead code | The item is still rejected, just via an earlier `ValueError` with a different message, and no test asserts on that message |
| T3 | `encode_canonical_map_raw` omits the `n >= 2^32` map-header case (`0xBB` + 8-byte length) | Unreachable for any real manifest |
| T3 | No unit row directly exercises `TrashEntry`'s own required-field rejection, nor the strict-subshape duplicate-key path | Correctness confirmed by the re-reviewer's direct execution, but the **corpus** has a coverage gap |
| T3 | `py_decode_manifest`'s docstring says duplicate-known-key in `kdf_params`/`vector_clock` is caught "via the re-encode collapse"; it is now caught explicitly and earlier, in `_decode_strict_entry_map` | Doc drift |
| T8 | The note's "gets no enforcement from the §4.3 step 4 re-encode AND MUST check rules 2/3/4" reads as consequence, whereas `vault-format.md:344` says rule 4 is never the re-encode for **any** reader | The phrasing mirrors §4.3 step 4 verbatim, so it is consistent with the document as written. **Recorded so a later editor does not "correct" it into a divergence.** |
| T9 | The eight conformance sections added by this slice print **nothing** on success, unlike the older sections which print a `PASS` line per row | Not a defect — each returns `(ok, issues)` and every `ok` flag is in the final conjunction, verified by reading `main()`. But a reader of the output cannot tell the eight ran. Named as constraint 4 in **#593** |

### Standing risks this slice does not remove

- **`conformance.py` is now 6107 lines** (from 4303). The clean-room verifier's value is
  proportional to how credibly a human can read it. **#593**.
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

`NEXT_SESSION.md` at the repo root is a **symlink**, retargeted by this commit to
`docs/handoffs/2026-08-31-manifest-canonicality-pin-shipped.md`. This file is the single
authored baton — do not create a second copy at the root, and do not sync it to `main`
during a pause window (that produces an add/add conflict). The slice's full task-by-task
record, including every review round and the "cost if wrong" for each ruling above, is at
`.superpowers/sdd/2026-08-31-manifest-canonicality-pin/progress.md`.
