# NEXT_SESSION.md — manifest split + decoder/encoder closeout (#564, #571, #573, #572, #577, #569 path 2)

Branch `feature/manifest-closeout`, worktree `.worktrees/manifest-closeout`, base `51b3bf5c` (`main`).
**Ten commits**, `40757e4e..HEAD` (`git rev-list --count main..HEAD` = 10).
The tip SHA is deliberately not written here: this baton IS the tip commit, so
any SHA quoted for it is falsified by its own amendment.
**Not pushed at time of writing; no PR yet.**

> Counted, not inherited: the Task 8 brief's table header said "7 commits" and
> the slice ledger's own pre-flight said "all 8 commits OK", while the brief's
> table listed 9 rows. Nine landed before Task 8; this baton's commit is the
> tenth. Three different figures for a `git rev-list --count`, which is the
> cheapest thing in this document to check — the same subtotal-as-total class
> the slice kept finding in its own reports.

---

## (1) What we shipped

### The slice — commits

| SHA | What |
|---|---|
| `40757e4e` | design spec |
| `5f2e54b5` | eight-task implementation plan |
| `a7f21baa` | **T1 (#564)** — split `core/src/vault/manifest.rs` (4273 lines) into a directory module |
| `c8959cad` | **T2 (#564)** — distribute the 61 tests into sibling `tests.rs` files + a shared `test_support.rs` |
| `7a4997ab` | **T3 (#571)** — `IdentityBundle::to_canonical_cbor` returns `SecretBytes` |
| `0f1a8384` | **T4 (#569 path 2)** — the manifest encode path borrows instead of copying |
| `a95bf58d` | **T5 (#573)** — duplicate-key rejection in the four nested manifest parsers |
| `a2da3d24` | **T6 (#572)** — `decode_manifest` re-encodes and compares |
| `aa0f8232` | **T7 (#577)** — persist the key-order proptest's counterexamples |
| *(this)* | **T8** — docs, slice-level gates, this baton |

### The measured result

- **1997 tests green across 97 binaries.** `cargo clippy --release --workspace --tests -- -D warnings` clean; `cargo fmt --all --check` clean; `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace` clean (forced non-cached — the first run finished in 5s off cache, which is the trap #575's T1 review already caught once).
- **All six hygiene guards pass**, each `--self-test` first.
- **`conformance.py` PASS** — the clean-room verifier still decrypts `golden_vault_001` from `docs/` alone.
- **No on-disk format change.** `git diff main...HEAD --stat -- core/tests/data/` is **empty**; the uniffi `.udl` diff is **empty**.
- **The two gates no CI job covers** — re-run at HEAD, both clean: `cargo check --release --features differential-replay --tests -p secretary-core`, and `core/fuzz` under the pinned nightly. `cargo test --release --workspace --features differential-replay` also passes, including `differential_replay_full_corpus`. These matter because `--workspace` builds *neither* (`core/fuzz` is workspace-`exclude`d; `differential_replay.rs` is feature-gated), which is exactly how they broke undetected on #575's branch.
- **`spec_test_name_freshness.py` is back to 90 with a member set identical to `main`'s** — `comm` empty in both directions. It hit 99 mid-slice; all 9 were references in the memory-hygiene memo to `unknown_value_inner` / `block_entry_to_value`, both deleted by #569 path 2. Resolved with two allowlist entries rather than by rewriting the prose, because the memo cites them in deliberately *historical* narrative.

### The two memory-hygiene items, and what they do **not** claim

Read `docs/manual/contributors/memory-hygiene-audit-internal.md`, section **"Resolved: manifest-closeout (#571, #569 path 2)"** before citing either. Both are narrower than "the manifest save path is now clean", and they are narrow in *different* ways:

- **#571 pins a TYPE; it adds no wipe.** The bundle plaintext was already wrapped — a caller was already applying `SecretBytes::new`. What changed is that deleting the wrap is now a compile error rather than a green test run. **Runtime behaviour is unchanged.**
- **#569 path 2 ELIMINATES a copy** (strictly stronger — a copy that never exists needs no wipe and has no window), removing the two heap copies every manifest save made of every user-visible `block_name`. **But it is ENCODE-side only.** Manifest *decode* still `take_text`s each `block_name` out of the borrowed tree into `BlockEntry::block_name`, **a plain, non-zeroizing `String`**, once per open. No issue tracks that yet.

---

## (2) What's next — concrete acceptance criteria

### Immediate: push, open the PR, let CI run

CI has **never run on this branch**. Do that before anything else.

### Issues to CLOSE after merge — each verified against the code, not against this document

The repo cites fixes as `(#N)` and never `Closes #N`, so these outlive their fixes and need closing by hand.

| Issue | Verify by |
|---|---|
| **#564** | `core/src/vault/manifest.rs` gone (it is); **10** production files under `manifest/` (plus 7 sibling `tests.rs` and one `#[cfg(test)]` `test_support.rs` = 18 tracked). **Caveat below.** |
| **#571** | `to_canonical_cbor` returns `SecretBytes` (`unlock/bundle.rs:327`); no `SecretBytes::new` at the `unlock/mod.rs` bundle site (confirmed — it now reads `let bundle_plaintext = identity.to_canonical_cbor()?;`) |
| **#573** | all four nested parsers return `DuplicateKey` on a repeat — 21 construction sites in `decode/entries.rs` (2 vector-clock-entry, 9 block-entry, 6 trash-entry, 4 kdf-params) |
| **#572** | `decode_manifest` re-encodes and compares (`decode/mod.rs:120-160`) |
| **#577** | `git check-ignore -q core/proptest-regressions/vault/canonical/value.txt` → rc=1 (not ignored); a sibling and another subdir → rc=0 (ignored). The file itself is correctly **absent**: the proptest passes, so there is no counterexample to persist; the carve-out only permits one. |

**#564 caveat — do not report its stated criterion as met.** #564's acceptance was *"no production file in `manifest/` over 500 lines"*. That held when the split landed (largest 361) and **does not hold now**: `decode/entries.rs` is **523 lines**, pushed there by #573's 21 longhand duplicate-key sites at `a95bf58d`. Filed as **#582**. #564 is still fine to close — it delivered the split — but the criterion is not met.

### **#569 does NOT close**

Three paths. Path 1 (`bundle.rs`) closed by the #575 slice; **path 2 (`manifest.rs`) closed by this one**; **path 3 (`identity/card.rs`) remains, and is the only reason #569 stays open.**

State this explicitly wherever #569 is discussed. **Path 2 went unmentioned in the #575 handoff, and this slice had to rediscover that it was still open** — the exact failure this note exists to prevent. `card.rs` carries no secret-key material (public keys + display name + self-signature), which is why it was never the urgent third.

**Acceptance for path 3:** `ContactCard::to_canonical_cbor` builds a `CanonicalMap` of borrowed leaves rather than an owned `ciborium::Value`; `core/tests/data/` diff empty; `golden_vault_001_pinned` green; the card KATs re-run explicitly.

### Filed this slice (five)

- **#578** — manifest Property F never generates forward-compat `unknown` bags, so the randomized suite has never covered the round-trip #572's v2 soundness rests on. Widened twice; now requires subtrees on **both** sides of the canonicality boundary. ~~and carries the Python-side half.~~ **CORRECTED in the #584 review:** it does not. #578's body is entirely about `core/tests/proptest.rs`'s three strategies and never mentions `conformance.py`; the clean-room half is now **#585**, filed separately. This is a ninth instance of the slice's own recurring defect — a claim about coverage that the cited artefact does not carry.
- **#579** — `record.rs`'s `verbatim` / `bit-identical` doc overclaim, with a measured eight-row table.
- **#580** — crypto-design §11.1/§11.2 resolve an unknown-map collision by "the lex-larger canonical-CBOR-encoded value bytes", which **do not exist** for a subtree that is legitimately disordered or duplicate-keyed. Two conformant clients could diverge on merge outcome — a CRDT convergence failure. Not broken today and unreachable pre-v2.
- **#581** — executed-plan-archive citation rot (see §3).
- **#582** — `decode/entries.rs` at 523 lines (above).

### Filed by the #584 review (seven)

Raised while reviewing this branch, all verified against the code before filing, none fixed here.

- **#585** — §4.3 step 4 is now a normative reader MUST with no clean-room coverage: `conformance.py` has no `py_decode_manifest` at all, only the §4.1 envelope. The gate that exists to prove `docs/` implementable cannot see the rule this slice wrote into the spec.
- **#586** — `CanonicalMap` does not reject duplicate keys, so a `Manifest` whose `unknown` bag holds a known key name yields a *signed*, ambiguous manifest. Availability only (owner-signed, unreachable via decode), but the encoder should not be able to emit a document its own decoder rejects.
- **#587** — `encode_manifest` validates no v1 sentinel, so `sign_manifest` can sign a body no v1 client can open. Second instance of the same class as #586.
- **#588** — `to_canonical_vec` / `encode_canonical_map` fill a plain `Vec<u8>`; both error paths drop a fully-written cleartext buffer unwiped. Latent (neither path is reachable today) — this is the code half of the "option (a) built in full" correction made to the memory-hygiene memo in this same round.
- **#589** — the #573 duplicate-key rejection is 21 hand-copied runtime guards, not a type invariant. #572 backstops the *rejection* for any structurally parsed map, so a fifth parser that forgot would degrade the diagnostic rather than accept the input — but the backstop lives in `decode_manifest`, not in the parsers.
- **#590** — `NonCanonicalEncoding` collapses five causes with no locator, on the every-open path, right after this slice narrowed the accepted set.
- **#591** — `value_to_unknown` and `UnknownValue::to_canonical_cbor` pre-reserve without the `CapacityBoundExceeded` tripwire their two siblings carry. Pre-existing; relocated, not introduced, by #564.

### Fixed in the #584 review round

Committed on this branch after the review, all doc-accuracy or test-pin work — **two production-code changes only**, both one-liners:

- **The `bundle_plaintext` contrast that #571 falsified**, asserted in three places: `manifest/file/sign.rs`, `block.rs` (a file this slice never touched) and this memo's own §1248 paragraph — which the slice *edited* for an unrelated path repoint while leaving the falsified neighbour standing. All four encoder sites now match by the same mechanism; the comments say so.
- **Four more dangling/stale claims:** `extract.rs` describing the deleted `unknown_value_inner` as "in this same file"; `record_error_to_cbor_fault`'s "those two calls" (one remains); `scratch.rs`'s "none of the six" orphaned by the six→five correction three lines above it; and the claim in `canonical/mod.rs` + `CLAUDE.md` that `block.rs` keeps `canonical_sort_entries` alive — it calls it nowhere, and `encode_canonical_map` does not reach it either.
- **Smaller rot:** `proptest.rs` citing `core/tests/vault.rs` for unknown-key coverage (that file has zero `UnknownValue`); `encode.rs` citing a `core/Cargo.lock` that does not exist; `record.rs` citing `manifest.rs`; `entries.rs` carrying a "treat as missing-field by ignoring" clause above code that rejects; `manifest/mod.rs` claiming *every* CBOR-mapped struct carries an `unknown` bag (`KdfParamsRef` and `VectorClockEntry` do not, and reject unknown keys outright).
- **Two scoping tightenings:** "Nothing else" in `decode/mod.rs` and `error.rs` is true of the decoder, not of the byte comparison alone — a tag or float escapes the comparison too and is caught by the earlier `reject_floats_and_tags` walk.
- **Production:** the `sync/ingest.rs` conflict-copy log said "AEAD decrypt failed" for what is now also every #572/#573 rejection class; and `manifest_to_canonical` / `trash_entry_to_canonical` dropped from `pub(super)` to private (no caller outside `encode.rs`).
- **Two new test pins, each mutation-verified.** `every_array_sort_discipline_is_rejected_out_of_order_on_decode` covers the four disciplines that had no *decode-side* rejection test (only `vector_clock` did); deleting the `recipients` sort reds it. And the forward-compat fixture now splices a **distinct** subtree per level, so the byte scan can tell the three apart — re-emitting the trash-level subtree through a sorting `CanonicalMap` reds it, where before the top-level needle satisfied the `.any()`. Separately, `DuplicateKey`'s `index` had **zero** assertions anywhere; all six duplicate tests now assert the ordinal, and reporting a hardcoded `0` reds them.

Note for whoever picks this up: the encode-side sorts were *already* pinned by `manifest_props::manifest_roundtrip` (deleting the `recipients` or `trash` sort reds it — verified by mutation during the review). The gap was only ever the reader-side claim, which is the one the spec now states normatively.

### Still open, untouched by this slice

**#576** (nothing enforces the `from_secret_reader` discipline) · **#570** (`ciborium`'s decode-side realloc above 4 KiB) · **#519** (uniffi secret accessors have no Rust-side wipe) · **#563** / **#556** (the `block.rs` / `record.rs` splits) · **#562** (golden vaults are ASCII-blind) · **#574** (freshness backlog — commented this slice with all three numbers re-measured).

---

## (3) Open decisions and risks

### The highest-consequence change in the slice, and how it was proven

**#572 adds a check to the path every vault open takes.** If `encode_manifest` were not a perfect inverse for some manifest the decoder accepts, real vaults would stop opening. It went through **four review fix rounds** — the most in this slice's history — and the reviewer answered the central hazard by exhaustive enumeration rather than sampling: the unknown-bag `BTreeMap` ordering is **not** reachable, because `CanonicalMap::serialize` re-sorts all keys by `(len, bytes)` at serialise time, so the `BTreeMap`'s plain-lexicographic order never reaches the wire.

**This layer's check is deliberately stronger than `record`'s and `block`'s**: `encode_manifest` sorts five arrays, so an array out of §4.2 sort order is rejected too.

### The residual, stated exactly — the obvious wider claim is FALSE

Inside a forward-compat `unknown` subtree the check misses **duplicate map keys and map-key order, and nothing else.** Indefinite-length maps/arrays/strings and non-shortest-form integer and length prefixes are all **rejected** there.

The mechanism is the `from_secret_reader` call at the **top** of `decode_manifest`, not anything on the unknown-key path: `ciborium`'s `Value` reader collapses indefinite lengths and non-shortest heads at parse time. Do **not** attribute it to `extract::value_to_unknown`'s re-serialise/re-parse hop — that hop is an *identity* on an already-normalised `Value`, proven by natural experiment (`record.rs` has no such hop and behaves identically across all eight probes).

**Practical consequence, and it runs opposite to the intuitive reading:** a v2 client that puts **one indefinite-length item** inside an extension field makes those vaults **unopenable by v1**.

### Two frozen-spec edits — why editing a frozen spec was justified

**Neither changes a single byte on disk** — that is the load-bearing half of the justification, and it holds. But the two edits have *different* histories, and an earlier draft of this section flattened them into "behaviour the code has had since its first manifest commit (`6e53b49d`)". That is right about edit 1's **encoder** and wrong about its **reader**.

1. **`docs/vault-format.md` §4.2** — the five array sort disciplines are now normative, plus the repeated-array-value rules and a five-row per-rule table for `unknown` subtrees.
   - **Writer side — longstanding.** `6e53b49d` already sorted all five and listed them in its module doc, so every manifest this codebase has ever written is sorted, and no existing vault is invalidated.
   - **Reader side — NEW at `a2da3d24` (#572)**, the very commit that declared it normative. Verified against `git show main:core/src/vault/manifest.rs`: no `ManifestError::NonCanonicalEncoding` variant, no re-encode-and-compare, no array-order check anywhere on the decode path — `parse_vector_clock` / `parse_blocks` / `parse_trash` sort a *copy* of the ids purely to detect duplicates and never inspect input order.
   - **Therefore the accepted-manifest set genuinely narrowed** for any manifest not written by this codebase. Do not re-summarise this as "no reader behaviour changed" — someone later assessing whether the frozen-spec edit was safe would draw the wrong conclusion. The shipped source gets it right (`core/src/vault/manifest/error.rs:189-194`: the disciplines "had been in the **encoder** since the first manifest commit … but were never written into `docs/`"); it was the summaries that flattened it.

   The disciplines were *enforced-by-the-encoder and written down nowhere*, so a clean-room implementer reading `docs/` alone would have emitted unsorted arrays and been rejected by the new check. That is exactly the property `conformance.py` exists to gate, so this is **spec ambiguity** — the third of the three resolutions CLAUDE.md prescribes ("Rust bug, Python bug, or spec ambiguity — all three need to be resolved explicitly").
2. **`docs/crypto-design.md` §6.2 rules 1 and 5** (map-key order; reject duplicate keys) are now scoped to material the reader *interprets*. **This one is the opposite case from edit 1 — its reader half genuinely is longstanding, and nothing narrowed.** The Rust decoder has **always** accepted both inside `unknown` subtrees — in `record.rs` and `block.rs` too, verified by execution over **twelve** cases in a scratch crate outside the tree. The unscoped rules had been inconsistent with the implementation since v1; round 2 merely made it visible. Enforcing them instead would break forward-compat and require changing three modules.

**A correction worth carrying:** the ruling that authorised edit 1 claimed `golden_vault_001` "exhibits" the sort orders. **It does not** — every array in it has ≤1 element, so all five are only *vacuously* sorted and the fixture cannot distinguish sorted from unsorted. The real non-vacuous basis is Property F (256 randomized cases). The ruling was wrong in the same way the thing it was ruling on was wrong.

### The pattern this slice kept re-finding — carry this forward

Stated by the T6 implementer and worth quoting verbatim:

> *"This is the THIRD time in this task that tightening one claim loosened a neighbour; the pattern is that these paragraphs address two audiences (this reader, a future writer) and a sentence true of one is routinely false of the other."*

It reached **seven instances**, and **five of the seven were created by the fix for the previous one**. Instances 6 and 7 were found by the whole-branch review *of the commit that fixed instance 5*, and both were fixed in the same commit that records them — which is why this census now runs to seven rather than the five an earlier draft of this very section claimed:

1. Round 1's fix for the false-residual claim wrote that same false claim **into the normative spec** — caught by the implementer's self-review, not by a gate.
2. Round 1's correction traded one wrong mechanism for another (credited `value_to_unknown`'s hop instead of the top-level parse).
3. Round 2's writer/reader split would have made a v1 client **non-conformant for faithfully re-emitting a v2 subtree** — the exact behaviour forward-compat requires.
4. Round 2's `MUST` tightened one document and **contradicted the other**: crypto-design said "decoders MUST reject" duplicate keys while the new vault-format text said a reader MUST *preserve* them.
5. Round 3's own fix: §6.3.2 kept the structural mandate §4.2 had just retracted, **and cited §4.2 as corroboration it no longer gave**.
6. **Round 3/4's byte-retention licence, and it was a real interop hole.** Retracting the data-structure mandate for the *reader* audience left §4.2 and §6.3.2 offering "retaining the subtree's raw input bytes and re-emitting them" as a way to meet the §4.3-step-4 obligation. A byte-retaining reader reproduces its input **unconditionally**, so its re-encode always matches and it **accepts** exactly the subtrees the same section's table (rules 2/3 = "yes") and its "whole vault unopenable" paragraph require it to **reject** — two spec-conformant v1 readers disagreeing on the same manifest, which is the failure the §4.2 addition existed to prevent. Fixed by stating the obligation as two requirements rather than one, so byte retention stays admissible *provided the reader also checks rules 2-4*.
7. **§6.3.2 contradicting itself in consecutive sentences**, created by the same edit as 6. The paragraph opens *"'Preserved' is preservation of the parsed value, **not of the input bytes**"* and, a few sentences later, listed retained input bytes as a valid carrier. (Cited by sentence rather than line: §6.3.2 is a single unwrapped paragraph, so both sit on one line — and that line number moved when instance 6 was fixed, which is the citation-rot class #581 tracks, encountered while writing up the pattern census.)

**A note on why 6 was invisible to the sweep that should have caught it:** round 4's sweep hunted *surviving structural mandates* — the polarity left over from round 3's retraction. Instance 6 is the retraction's **overshoot**, the opposite polarity. A sweep scoped to one direction of a two-directional change cannot see the other, which is a sharper version of the same two-audience lesson.

**The operational lesson:** after changing one of these passages, re-read its *neighbours in both documents* for the other audience. A sweep beats a spot fix — round 4's sweep covered both frozen specs plus `threat-model.md` and all eleven ADRs over 13 terms, and tabulated all 24 hits **with their verdicts**, so the negatives are reproducible. An untabulated "found nothing" is not a result.

### Three residuals recorded, deliberately NOT fixed

- **R1 — the crypto-design §6.2 chapeau seam.** The chapeau binds every `canonical_cbor(...)` to the profile, so a v1 client faithfully re-emitting someone else's disordered subtree produces a technically non-conformant body, excused only by `vault-format.md:288-292`. Predates the slice; widening the frozen-spec surface a *third* time was not that task's call. The pointer rule 5 carries makes it findable.
- **R2 — `canonical=True`.** crypto-design §6.2 recommends `cbor2.dumps(record, canonical=True)` to clean-room implementers, while vault-format now names that exact idiom as what re-sorts an unknown subtree's keys away. Judged **not an instance at all** on four grounds (this read "not a sixth instance" until instances 6 and 7 were found and took that number; the judgement is unaffected, only its ordinal): opposite directions (authoring your own bytes vs re-emitting someone else's), the carve-out sits one paragraph above in the same rule list, the failure mode is **fail-closed** at the reader, and it is unreachable until a v2 extension exists.
- **#580** — filed rather than fixed; see §2.

### Risks

- **`decode/entries.rs` at 523 lines** (#582) — maintainability, not correctness.
- **#578 is the real coverage gap.** #572's v2 soundness rests on a round trip the randomized suite has never exercised, in either direction. If one thing from this slice deserves the next slice's attention, it is this.
- **Verification hazard — the cargo mtime trap.** Recorded in the memo's new section and as a persistent memory. `cargo` compares source mtime against the artifact, so a mutation applied by a **backdating** operation (`mv`, `cp -p`, `rsync -a`, `touch -t/-r`) is never compiled — the suite passes and the verifier concludes *"the mutation didn't red anything, so this mechanism is unpinned."* **That silent false negative is the dangerous direction**; a backdated *restore* is loud and self-limiting. In-place editors are immune (a write stamps "now"). Blast radius on this slice: the one task naming its literal command used a plain `cp` (safe); three others say "restored from backup" without the command and **could not be ruled out from report text** — no positive evidence of the dangerous direction, which is not the same as exclusion.

---

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-closeout
pwd && git branch --show-current && git worktree list     # ALWAYS first — parallel sessions switch branches

git push -u origin feature/manifest-closeout
gh pr create --fill                                        # user merges; do not auto-merge

# Full gate set for this slice (from the worktree):
cargo fmt --all --check
cargo build --release --workspace                          # separate from the test run ON PURPOSE (see CLAUDE.md)
cargo test --release --workspace                           # 1997 tests / 97 binaries
cargo clippy --release --workspace --tests -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace  # check it isn't a cache hit
uv run core/tests/python/conformance.py

# The two gates NO CI job covers — --workspace builds neither:
cargo check --release --features differential-replay --tests -p secretary-core
cargo test  --release --workspace --features differential-replay
cd core/fuzz && PATH="$HOME/.rustup/toolchains/nightly-2026-04-29-aarch64-apple-darwin/bin:$PATH" cargo check

# Must both be EMPTY:
git diff main...HEAD --stat -- core/tests/data/
git diff main...HEAD -- ffi/secretary-ffi-uniffi/src/secretary.udl

# Hygiene guards — --self-test FIRST, every time (a green guard must be proven non-vacuous).
# NOTE: run each as a literal command. zsh does not word-split unquoted variables,
# so a `for g in "bash x.sh"; do $g; done` loop reports FAIL on all of them.
bash ffi/scripts/check-lean-binding.sh --self-test        && bash ffi/scripts/check-lean-binding.sh
bash ios/scripts/check-public-log-hygiene.sh --self-test  && bash ios/scripts/check-public-log-hygiene.sh
bash android/scripts/check-log-hygiene.sh --self-test     && bash android/scripts/check-log-hygiene.sh
bash scripts/check-secret-slot-hygiene.sh --self-test     && bash scripts/check-secret-slot-hygiene.sh
uv run scripts/check-error-payload-hygiene.py --self-test && uv run scripts/check-error-payload-hygiene.py
uv run scripts/check-test-support-placement.py --self-test && uv run scripts/check-test-support-placement.py

# Freshness: expect FAIL: 90, member set identical to main (#574 tracks the backlog).
uv run core/tests/python/spec_test_name_freshness.py

# After the PR merges (squash leaves the branch "not fully merged"):
#   git worktree remove .worktrees/manifest-closeout
#   git branch -D feature/manifest-closeout
```

---

## (5) The handoff-file model

`NEXT_SESSION.md` at the repo root is a **relative symlink** to this file in `docs/handoffs/`. The baton is authored **once**, here; the symlink is retargeted in the **same commit on the feature branch**, so the baton rides inside the PR rather than landing on `main` separately.

**Do not sync this to `main` during the pause window** — `main`'s `NEXT_SESSION.md` is authoritative for `/nextsession`, and pushing a second copy produces an add/add conflict at merge time.

If you resume this branch for fixups after `main` has moved: `git fetch origin && git merge origin/main` **first** (the branch version wins on this document) before editing.

- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-08-29-manifest-closeout-shipped.md`
- **Previous baton:** `docs/handoffs/2026-08-25-cbor-residue-closeout-shipped.md`
- **Slice ledger** (rulings, corrections, per-task review history): `.superpowers/sdd/2026-08-27-manifest-closeout/progress.md`
