# NEXT_SESSION.md — core memory-hygiene residual closeout

**Session date:** 2026-08-23, from `main` @ `6e65ca8d`. Branch `feature/core-memory-hygiene-residuals`; worktree `.worktrees/core-memory-hygiene-residuals`.

Housekeeping → tracker hygiene → brainstorm → spec → 8-task plan → **subagent-driven execution, fresh implementer per task, independent review after each** → full gate run. **All 8 tasks complete. 12 commits.**

---

## (1) What we shipped

Six filed residuals plus two things the work uncovered. The slice as executed is
larger than the six issues by exactly two commits, and both additions are
justified below rather than folded in silently.

### Commits (12, `b0772567..42c4c3e7`)

| SHA | What |
|---|---|
| `b0772567` | design spec |
| `4b552702` `6ff5c724` | 8-task plan, + pre-flight ruling R1 |
| `9bb0f198` | **#523** — dangling SHA in CLAUDE.md repointed at `2e6dd764` |
| `adc8954f` | **#524** — `SecretBytes::concat` + `derive_wrap_key` |
| `f6bb520a` | **#522** — write-through `take_fixed_bytes_into`; by-value producer deleted |
| `75d0ebee` | **#544** — `pqcrypto` pinned `<1`; the clean-room gate was broken on `main` |
| `8cadacb7` | **#542** — `ZeroizingEntries` wipes `to_canonical_cbor`'s key clones on `Drop` |
| `a1b88569` | **#525** — expected-bytes KAT for `derive_device_kek` |
| `42249111` | **#527** — desktop `Candidate.value` is `SecretString` |
| `f140c209` | **#521** — `check-secret-slot-hygiene.sh` + empty allowlist + CI job |
| `42c4c3e7` | docs — audit memo, CLAUDE.md, guard LIMITS block |

### The two corrections that reshaped the slice

**#522 named one residue; there are three, and the third is the worst.** The
issue describes a stack copy in `take_fixed_bytes`' frame. But that function
reaches its array through `Vec::try_into`, whose implementation in the pinned
toolchain's own std source (`library/alloc/src/vec/mod.rs:4527`) is `set_len(0)`
followed by `ptr::read` — a **copy**, not a move-out. The `Vec`'s heap buffer is
then deallocated with the secret key still in it. Heap residue outlives stack
residue. This was **not** a new finding: the 2026-07-02 audit's **C-4** said
exactly that, and it was C-4's last live sub-item (the others closed by #357,
#513 Task 6, and #518). The memory-hygiene memo did not mention
`take_fixed_bytes` at all.

**#524's proposed fix does not close #524's own hazard.** The issue asks for
`SecretBytes::try_build`. Wrapping the buffer first covers a panic during the
fill, but **not a reallocation**: a realloc copies to a new block and frees the
**old** one unwiped, and `Drop` only ever wipes the buffer the `Vec` points at
when it drops — the new one. `SecretBytes::concat(parts)` derives the capacity
and performs the pushes from the same slice list in the same function, so they
cannot drift and no realloc can occur. It also lends no `&mut`, which matters
because #521 — in this same slice — exists to police exactly that capability.
`build`/`try_build` were deliberately **not** added to `SecretBytes`.

### The two additions beyond the six issues

- **#544 — `conformance.py` was broken on `main`, and would have redded every
  PR.** Its PEP 723 header pinned `pqcrypto>=0.3` unbounded, which admitted
  **1.0.0**, a major bump that (a) renamed `generate_keypair`→`keygen` and
  (b) changed `ml_dsa_65.verify` from returning a bool to **raising** on
  failure. Measured: a **valid** signature returns `None`; tampered and
  wrong-message each raise `InvalidSignatureError`. The helper returns that
  value directly, so `None` is falsy and every ML-DSA-65 check reported
  "rejected" — including the golden vault's genuinely valid contact card.
  Verified pre-existing by running it on a clean `main` checkout: byte-identical
  failure. **Attribution, per CLAUDE.md's rule that a Rust/Python disagreement
  must be named rather than papered over: neither Rust nor the spec is wrong.**
  The signature is valid and pqcrypto 1.0 agrees; only the success-signalling
  changed. Failure direction was **fail-closed** — valid rejected, never invalid
  accepted — so nothing was silently waved through.
- **The guard's LIMITS block**, folded into the docs commit after review found
  the new guard disclosed no blind spots at all, out of step with every sibling
  guard in the repo.

### Net

`SecretBytes::concat`; the by-value fixed-size decoder deleted and all four call
sites converted; `take_sized_bytes`'s reject path closed; C-4's write side closed
via `ZeroizingEntries`; a three-vector expected-bytes KAT where there was none;
desktop title candidates zeroize-typed; a new CI guard shipping with an **empty
allowlist**. **No on-disk format change, no FFI surface change, no `.udl` change,
no KAT regeneration** — `core/tests/data/` gained exactly one file.

---

## (2) What's next — concrete acceptance criteria

**Nothing on this branch is unfinished.** CI has never run on it; that is the
first thing to check.

- **Add the new check to the branch ruleset.** `f140c209` adds a CI job named
  **`rust secret-slot hygiene`**. `main`'s `protect_main` ruleset (id
  `15821032`) lists its required checks **by name**, so the new job will run but
  will **not be required** until someone adds it there. Acceptance: the check
  appears in `gh api repos/hherb/secretary/rulesets/15821032`.
- **#545 (filed this session)** — a module alias defeats the new guard's rule
  S1. `use std::mem as m;` then `m::swap(...)`: neither the `use` line nor the
  call site contains a `mem::<verb>` substring. **S2 is only partially exposed**
  — aliasing `ManuallyDrop` still writes that identifier once on the `use` line,
  which S2 matches. Do not flatten the two. Zero live producers; verified by
  execution against a planted probe. Acceptance: either a rule S3 with its own
  positive control **and** a matching LIMITS edit, or a recorded decision to
  leave it. Same root cause as #512/#517.
- **#544 (filed this session)** — the pin is a mitigation, not the fix. The
  other **five** deps in that PEP 723 header (`cryptography`, `pynacl`,
  `argon2-cffi`, `blake3`, `cbor2`) are equally unbounded. CLAUDE.md's own
  dependency doctrine already demands an exact pin plus a justifying comment on
  security-critical paths — `tempfile` is `=3.27.0` for exactly this reason —
  and this script is the clean-room verifier that doctrine exists to protect.
  Acceptance: bounds on all six, and a decision on migrating to pqcrypto 1.x
  with a tamper-rejection test that passes on whichever resolution is allowed.
- **#543 (filed this session)** — `core/src/unlock/bundle.rs` is now **1151** lines (986 before this branch)
  against the 500-line guideline. Deliberately not split here: mixing a
  structural move with a security fix means one review covers both.
- **#519 — still the largest unfixed exposure, and it did not move this
  session.** `ffi-uniffi`'s four secret accessors have no Rust-side wipe **at
  all**, leaking a device secret, a full recovery mnemonic, and decrypted record
  fields into freed heap on **every call, unconditionally, no panic required**,
  on both mobile platforms. The previous baton called it "should jump the
  queue"; it was consciously deprioritised this session in favour of the bounded
  residuals. It is now the oldest large item.
- Carried unchanged: **#501** · **#512** · **#514** · **#516** · **#517** ·
  **#494** · **#495** · **#502** · **#506** · **#508**–**#510** · **#473/#476** ·
  **#477** · **#459** · **#464** · **#492** · **#417** · **#447** · **#443/#444**.

---

## (3) Open decisions and risks

- **A commit was amended mid-flight to correct a false claim.** Task 4's
  implementer described its rustdoc fix as "pre-existing, introduced in
  `d0613622`". Verified false: on `main`, `bundle.rs` imports only `Sensitive`,
  so the bare `[SecretBytes]` shorthand did not resolve and the explicit link
  path was **required**. Task 3 (`f6bb520a`) widened that import, which made the
  shorthand resolve and the explicit path redundant in the same stroke — **this
  branch created the warning two commits earlier and cleared it here.** The
  implementer's `git stash` check could not have seen it: it stashed only the
  uncommitted Task 4 work while the causative import was already committed.
  Body amended (the pre-amend object is unreachable from any ref and is
  deliberately not cited by SHA — that is the #523 failure mode; the commit
  now on the branch is `8cadacb7`).
  **Generalizable, and worth remembering: widening a `use` can red the rustdoc
  `-D warnings` gate without touching a single doc comment.**
- **The gate set does not include a rustdoc run per task.** That is how the
  above surfaced one task late. Consider adding it to the per-task gate list.
- **What is proven, stated precisely.** A wipe of freed heap is **not observable
  from safe Rust**, and neither is a reallocation that did not happen. There is
  no per-site assertion for either and this slice does not pretend otherwise.
  `concat`'s no-realloc property is **structural** — capacity and pushes come
  from one slice list in one function. `ZeroizingEntries` does **not** cover a
  mid-`vec![…]`-literal unwind (reachable only via allocation failure, which
  aborts). Both boundaries are stated in the code, the spec, and the memo.
- **The new guard's self-test was proven load-bearing, not merely green.** Two
  mutations were run and both fail it: disabling rule S2 (positive controls
  P7/P8 stop firing) and reintroducing a `#[cfg(test)]` skip (P10 stops firing).
  The second is the one that matters — #496 found a sibling guard's test
  carve-out was **fail-open**, so this guard has none at all.
- **Ten stale-but-done issues were closed** at session start after verifying
  each against code on `main`: #513, #518, #503, #500, #504, #497, #526, #505,
  #507, #511. The repo cites fixes as `(#N)` and never `Closes #N`, so issues
  outlive their fixes until closed by hand.

---

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# After the PR merges (squash leaves the branch "not fully merged"):
#   git worktree remove .worktrees/core-memory-hygiene-residuals
#   git branch -D feature/core-memory-hygiene-residuals
git worktree list && git status -s

# Gates for this slice (run from the worktree while the PR is open):
#   cd /Users/hherb/src/secretary/.worktrees/core-memory-hygiene-residuals
#   cargo fmt --all -- --check
#   cargo build --release --workspace
#   cargo test --release --workspace
#   cargo clippy --release --workspace --tests -- -D warnings
#   cargo clippy --release --workspace -- -D warnings
#   RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
#   uv run core/tests/python/conformance.py
#   uv run scripts/check-error-payload-hygiene.py --self-test && uv run scripts/check-error-payload-hygiene.py
#   uv run scripts/check-test-support-placement.py --self-test && uv run scripts/check-test-support-placement.py
#   bash scripts/check-secret-slot-hygiene.sh --self-test && bash scripts/check-secret-slot-hygiene.sh   # NEW
#   bash ffi/scripts/check-lean-binding.sh --self-test && bash ffi/scripts/check-lean-binding.sh
#   bash ios/scripts/check-public-log-hygiene.sh --self-test && bash ios/scripts/check-public-log-hygiene.sh
#   bash android/scripts/check-log-hygiene.sh --self-test && bash android/scripts/check-log-hygiene.sh
#   actionlint .github/workflows/test.yml
#   (cd desktop && pnpm test && pnpm run svelte-check)
#   git diff main... -- ffi/secretary-ffi-uniffi/src/secretary.udl    # must be EMPTY
#   git diff main... --stat -- core/tests/data/                       # ONLY device_kek_kat.json
```

**Verified at `42c4c3e7`** (controller-run, not taken on report): `cargo test
--release --workspace` **1912 passed / 0 failed / 0 ignored across 97 binaries**
· `cargo build --release --workspace` clean · clippy clean **with and without**
`--tests` · rustdoc `-D warnings` clean · `cargo fmt --check` clean ·
`conformance.py` **PASS** · payload guard **OK** (41/18/55/32/11/3) · placement
guard **OK** (34/34 controls, 11 manifests) · **secret-slot guard OK** (12
positive, 6 negative, 2 allowlist controls; 6 roots, 2 rules, 0 findings) ·
lean-binding **OK** (3/3) · iOS log hygiene **OK** (21 positive, 9 negative) ·
Android log hygiene **OK** (27 positive, 14 negative) · `actionlint` clean ·
desktop `pnpm test` **786 passed** · `.udl` diff **EMPTY** ·
`core/tests/data/` diff **only `device_kek_kat.json`** · all **12** commits carry
the trailer (checked **per commit** — on git 2.54 a range `%(trailers:…)` audit
never returns empty) · no auto-close keyword + `#N` pattern in any commit body.

**Not verified:** **CI has never run on this branch** — check it first. The
Android Gradle build and `pnpm run svelte-check` were not re-run at `42c4c3e7`
(no Kotlin or Svelte file changed on this branch). The Swift/Kotlin conformance
runners are manual-only and nothing crossing the FFI changed (`.udl` diff empty).
`core/fuzz` (workspace-excluded, nightly) was not compiled.

---

## (5) Handoff file model

`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`.
Authored once here; the symlink is retargeted in the same commit on the feature
branch. Do **not** sync to `main` during the pause window. If resuming this
branch for fixups: `git fetch origin && git merge origin/main` FIRST (branch
version wins on this doc) before editing.

## (6) Post-review fixes (PR #546 review round)

A five-agent review of the PR found four things that had to change before
merge, plus corrections to prose in this branch's own docs. All are in the
branch now; every gate was re-run green afterwards.

**The guard failed OPEN on its own wiring — four ways, all proven by
execution.** A missing or renamed scan root (`[[ -d ]] || continue`), an
unreadable root (`grep 2>/dev/null || true` erasing exit >= 2), an
unrecognised CLI argument, and a success line printing the DECLARED root
count all produced `OK` and exit 0. A tree containing none of the roots
reported `OK (6 roots, 2 rules, no findings)` having read nothing — #496's
`Path.rglob` fail-open restated in bash, in the guard whose own header cites
#496 as its justification. All four are now fatal; `--self-test` drives
`run_guard` and asserts the exit code in both directions (previously it
asserted only on `scan_all`'s text, so `return 1` → `return 0` kept both CI
steps green).

**The root list omitted two workspace members, one secret-bearing.**
`browser/secretary-browser-host` handles the device secret and the master
password and holds two live S1 producers; `desktop/secretary-desktop-presence`
was also absent. So "the census is empty" and "ships with an EMPTY allowlist"
were properties of the six chosen directories, not of the tree. Both are
scanned now, the two `scrub_string` sites are reviewed allowlist rows (#549),
and — the actual fix — the guard checks `SCAN_ROOTS` against the root
manifest's `[workspace] members`, the treatment #505 gave the payload guard.
A self-test cannot substitute here: any assertion written over `SCAN_ROOTS`
disappears with a deleted entry, learned by mutation while writing it.

**#542 was about half closed.** `encode_map` did `pair.clone()` on every
entry one line after `ZeroizingEntries` took ownership — `ciborium::Value`
derives `Clone`, so all four secret keys were deep-copied into a second list,
moved into a `Value::Map`, and freed **unwiped on every call**, create and
unlock alike. The wrapper had moved the leak, not removed it, while this memo
and the type's doc comment both described the write side as closed. Now:
`encode_map` takes `&ZeroizingEntries` (so the wrapper is not optional at its
only call site), sorts indices with values riding along as borrows, and
serialises through a `BorrowedCanonicalMap` impl instead of an owning
`Value::Map`. Zero clones. Output buffer pre-reserved against an upper bound
so `into_writer` cannot realloc. `conformance.py` passing is the proof the
bytes are unchanged.

**#523 repointed the dangling SHA at the wrong commit** — its whole purpose.
`array32_from_vec_into` already exists in `2e6dd764`'s parent (`grep -c`
returns 2); `git log --all -S` puts its introduction in `9c187946` (#515),
whose parent `3775ef5` is the very merge-base the next sentence cites.

**`take_sized_bytes`'s comment asserted the opposite of its code.** It said
"ownership of the same heap buffer transfers and no copy is made" over
`Ok(bytes.expose().to_vec())`, which allocates — the fix had ADDED a live
copy of the 2400-byte ML-KEM-768 key on every unlock. Split into
`take_sized_secret` (returns `Sensitive<Vec<u8>>`, zero copies) and
`take_sized_public` (by-value, for the two public keys).

**`conformance.py` ran in NO workflow** — CLAUDE.md's "enforced every CI run"
was false; its only invocation is behind the off-by-default
`differential-replay` feature. That is why #544's `pqcrypto` break survived on
`main`. Added as the `clean-room conformance` job.

Smaller: the `ZeroizingEntries` test asserted `all(|b| b == 0)` on a vec that
`Zeroize` empties, so it passed vacuously and could not distinguish a wipe
from a bare `clear()` — corrected, with the limit stated rather than papered
over (neither form distinguishes those; safe Rust cannot read spare
capacity). `Drop → wipe` is now pinned by a `#[cfg(test)]` counter (deleting
`impl Drop` previously kept all 25 bundle tests green). `concat`'s
no-realloc property is asserted via `capacity()` — the doc claimed it was not
observable, which was wrong — and its length sum is `checked_add`ed, since
release builds wrap. Wrong-size coverage now runs over all six rewritten
extraction sites, which matters because `X25519_PK_LEN == ED25519_PK_LEN`
makes a swapped key constant invisible to a round-trip test (mutation-verified).

## Closing inventory

- **State on close:** PR-ready on `feature/core-memory-hygiene-residuals`, all
  8 tasks done plus the post-review round in §6, full gate set green.
  1922 tests / 0 failed / 18 ignored across 97 binaries; `conformance.py`
  PASS (the proof the `encode_map` rewrite is byte-identical); desktop
  786 passed. Note the PR description's original gate line claimed "0
  ignored" — the count is 18, the `--ignored` KAT generators.
- **Docs:** `memory-hygiene-audit-internal.md` extended (the three-residue
  correction, `concat`'s realloc reasoning) and then CORRECTED in the review
  round — it had recorded C-4 as "fully closed" and `ZeroizingEntries` as
  covering the write side, neither of which was true (#548, and the
  `encode_map` clone);
  `CLAUDE.md` gained the new guard's Commands entry **with its LIMITS**, and its
  zeroize section now names `concat`; `README.md` / `ROADMAP.md` deliberately
  unchanged — this slice adds no user-visible feature and no phase completion,
  and nothing in either file was falsified.
- **Filed this session:** **#542** · **#543** · **#544** · **#545**, and in the
  review round **#547** (record-field plaintext cloned into bare
  `ciborium::Value` on every save — same C-4 class as #542, much larger
  surface) · **#548** (C-4's read side: `from_canonical_cbor`'s map frees
  secret keys unwiped on every error path — the audit's own FIRST-named
  sub-item, which this branch had recorded as closed) · **#549** ·
  **#550** (`ed25519_verify`'s fail-OPEN twin + five unbounded deps) ·
  **#551** (`Sensitive::<Vec<u8>>::try_build` still reaches the realloc
  hazard `concat` exists to prevent) · **#552** · **#553** (`device_kek_kat`
  independence is reviewer-attested, not replayed by `conformance.py`) ·
  **#554**.
- **Closed this session** (verified against code on `main` first): #513, #518,
  #503, #500, #504, #497, #526, #505, #507, #511.
- **Next:** CI on the PR · add **`rust secret-slot hygiene`** AND
  **`clean-room conformance`** to the `protect_main` ruleset (id `15821032`) —
  both run and neither blocks until then ·
  **#519 (now the oldest large exposure)** · #544's remaining five deps · #545 ·
  #543 · #501.
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-08-23-core-memory-hygiene-residuals-shipped.md`.
