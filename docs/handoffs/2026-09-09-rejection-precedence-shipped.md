# NEXT_SESSION.md — which rule a rejecting reader names becomes normative, and cross-language (#618)

Branch `feature/dupkey-precedence`, worktree `.worktrees/dupkey-precedence`,
base `e02223a7` (`main`, i.e. immediately after PR #631 merged).

This slice is **(b)** from the previous baton's §(3) queue. The choice was put
to the user options-plus-recommendation and the recommendation was taken; one
design ruling inside it went the OTHER way, and that is the most consequential
decision in the slice (§(1)).

**Two issues filed:** [#634](https://github.com/hherb/secretary/issues/634),
[#635](https://github.com/hherb/secretary/issues/635). **One issue commented
with a measurement that makes it much cheaper:**
[#621](https://github.com/hherb/secretary/issues/621). The slice closes **#618**.

---

## (0) The starting-state check FIRED AGAIN — and the baton was stale in a second way

`git fetch origin && git log --oneline main..origin/main` returned `e02223a7`:
`main` had moved and the local checkout was one commit behind, so
`NEXT_SESSION.md` resolved to `2026-09-07-card-dedupe-shipped.md` — the baton
from the previous slice — and read as a completely coherent, current document.
I had read the whole thing before the fetch result was in. **That is now two
sessions in a row.** Run the fetch first; it costs one command.

### A stale NUMBER in the baton, found by measuring instead of trusting

The previous baton reported `main` at **2135** workspace tests. Measured, on a
clean `main` checkout: **2138**. The figure was written before that slice's own
review round added three tests and was never re-measured — the exact failure its
own commit message warned about ("re-measured rather than incremented").

This mattered: my branch reported 2142, and against 2135 that is +7 for a slice
that adds 4 tests. Chasing the discrepancy is what produced the name-set diff in
§(1), which is stronger evidence than either count. **Do not reconcile a test
count against a number in a document. Measure the baseline.**

Housekeeping: `.worktrees/manifest-sentinel` removed and
`feature/manifest-sentinel` deleted (merged as PR #631; its diff against `main`
was EMPTY, not merely "net deletions", so `-D` was safe rather than judged).
Three older local branches deliberately left alone, unchanged ruling —
`feature/manifest-uniqueness-parity` and `feature/noncanonical-cause` are
squash-merged, and `backup-pre-reword-1787543234` is a deliberate backup.

---

## (1) What shipped

### Commits

| SHA | What |
|---|---|
| `7b896455` | **#618** — the §4.2 precedence paragraph, `conformance.py`'s rule-4 pre-pass, `manifest_precedence_kat.json` + its Rust replay, Section MPR, `DuplicateMapKey` |
| `dd1e7500` | CLAUDE.md + ROADMAP, with three counts **re-measured** and one found already stale |
| *(this)* | the baton — a commit cannot cite its own SHA, so this row stays symbolic |

### The defect

`docs/` never said which rule a reader must report when a manifest body breaks
more than one at once. Rust pinned two such orderings — one from #589
(`Once::set` takes a closure, so a repeat is reported without parsing the second
copy), one from v1 (`reject_floats_and_tags` runs at `decode/mod.rs:131`, six
lines before `parse_manifest_map`). Neither was in `docs/`.

**The issue said "not a live divergence — the two implementations agree today."
That was false, and measuring it was the first thing this slice did:**

| repeated key's second copy | Rust | `conformance.py` (before) |
|---|---|---|
| float (§6.2 rule 4) | `FloatRejected` | `duplicate manifest key` |
| tag (§6.2 rule 4) | `TagRejected` | `duplicate manifest key` |
| wrong CBOR type | `DuplicateKey` | duplicate ✓ |
| indefinite length (rule 2) | `DuplicateKey` | duplicate ✓ |

`conformance.py` checked rule 4 **per value inside its entry loop**, which the
duplicate check pre-empts, so it never looked at the second copy. Both rejected —
nothing unsafe — but the two were not interoperable in what they said, and no
gate could see it (`differential_replay.rs` scores reject-vs-reject as agreement).

### The ruling put to the user, which went against my recommendation

I recommended the NARROW option: state the repeat-outranks-type rule, declare the
rule-4 interaction unspecified, file the divergence. **The user chose the larger
option — fix Python so the two agree.** That was the better call and the slice is
substantially stronger for it: the narrow option would have documented a
divergence that had a clean fix, and §4.2 *already* said "every reader enforces
rule 4 by a **separate** whole-body walk", which Python's interleaved check was
not. Python was already non-conformant with a sentence in the spec.

### What landed

- **`docs/vault-format.md` §4.2** gains one normative paragraph (+32 lines)
  fixing TWO orderings and explicitly refusing to fix a third.
- **`codec/scanner.py::reject_floats_and_tags`** — the clean-room twin, built on
  a new `_scan_item` **visitor** parameter rather than a second copy of that
  traversal (indefinite-length forms must be SCANNED THROUGH without rejecting,
  and `_scan_item` already gets that right).
- **`codec/scanner.py::DuplicateMapKey`** — a typed discriminator beside
  `NonCanonicalItem` and for its reason. Three raise sites converted,
  **message-preserving** (checked: no section matched those strings).
- **`core/tests/data/manifest_precedence_kat.json`** — 26 rows, six maps.
- **`core/tests/manifest_precedence_kat.rs`** + a `_helpers/` directory
  (`cases` / `build` / `assert` / `generate`), designed as a directory module
  from the start rather than split later.
- **Section MPR**, registered — REG **27 → 28**.
- **4 tests added, 0 removed** (2138 → 2142), plus 1 `#[ignore]` generator.

### Non-vacuity, by mutation

Eleven mutations, every restore **sha256-verified by the harness**, which aborts
rather than poisoning the next one.

| # | Mutation | Result |
|---|---|---|
| P1 | delete `conformance.py`'s rule-4 pre-pass | RED |
| P2 | **widen the pre-pass to rules 2+3+4** | RED — *green before `top__non_shortest` existed* |
| P3 | rule-4 walk stops rejecting TAGS | RED |
| P4 | rule-4 walk visits only the ROOT item | RED |
| P5 | duplicate check moved AFTER the value's canonicality check | RED — *false GREEN first, see §(4)* |
| P6 | delete the nested entry-map duplicate check | RED |
| P7 | delete the `kdf_params`/`vector_clock` duplicate check | RED |
| R1 | make `Once::set` EAGER | RED — KAT + 3 lib tests |
| R2 | delete `decode_manifest`'s rule-4 walk | RED — KAT + `rejects_float_in_unknown_value` |
| R3 | `DuplicateKey` names the FIRST occurrence's ordinal | RED — KAT + 6 lib tests |
| R4 | five NESTED row bodies replaced by the top-level one | RED both languages — *Rust only, until §(4)'s fix* |

**R1/R2 and P1 are the pair that matters**: neither implementation's
precedence survives deleting the mechanism that produces it, in either language.

### The measured gate set

- **`cargo test --release --workspace`: 100 binaries, 2142 passed, 0 failed, 22
  ignored**, exit 0.
- **Test NAME SET diffed against a MEASURED `main` baseline**, not against a
  document: **0 removed, exactly 5 added**, all this slice's. `git diff`-based
  counting is vacuous here — every new test file is UNTRACKED, so the diff
  reports 0 added `#[test]` attributes and 0 removed fns while five tests exist.
- **`--features differential-replay` exit 0** (100 binaries, 2143 passed).
- `cargo fmt --all --check`, `cargo build --release --workspace`,
  `cargo clippy --release --workspace --tests -- -D warnings`,
  `RUSTDOCFLAGS="-D warnings" cargo doc` (forced non-cached) all exit 0.
- **`conformance.py` exit 0**, **28** sections, REG `28 drivers, 28 registered`,
  **0 `FAIL` lines** — checked by exit code AND grep.
- **All six hygiene guards pass, each `--self-test` first.** No probe residue.
- **`spec_test_name_freshness.py` = 90**, and `main` **re-measured at 90** rather
  than taken from the baton. The new §4.2 paragraph cites no test name (verified
  by grepping the added lines).
- `core/fuzz` checks clean under the pinned nightly.
- **Format invariants**: `core/fuzz/seeds/` and the UDL diffs EMPTY;
  `core/tests/data/` is **one added file and zero modified** (checked with
  `--name-status`, not by eyeballing a stat); normative `docs/` is
  `vault-format.md` only, +32.
- Every file created or touched is under 500 (largest: `cases.rs` 255,
  `build.rs` 245, the section 241).

### `clippy --tests` earned its place for a fourth session

`cargo test` compiled green while `clippy --release --workspace --tests` failed
on `needless_lifetimes` in `build.rs`. Fixed properly, not `#[allow]`ed.

### README was deliberately not touched

Checked, not assumed. README describes `conformance.py` by its four capability
CATEGORIES (line 235) and cites no section count; its 38/38 · 118/118 figures are
the conformance-KAT harnesses, untouched. This slice changes no user-visible
behaviour, no on-disk format and no FFI surface. `ROADMAP.md` and `CLAUDE.md`
both changed.

---

## (2) What this slice does **not** claim

- **It does NOT make the two implementations agree on every multi-violation
  body**, and §4.2 now says so normatively. §6.2 rules 1, 2 and 3 stay
  **unspecified** against rules 4 and 5. Measured: a body with a non-shortest
  head at an early key and a repeat at a later one is reported by Rust as the
  repeat and by Python as rule 3, and **both are conformant**. A normalising
  reader can only see rules 1-3 at the §4.3 step-4 re-encode (after
  interpretation); a byte-retaining reader must see them during its scan (before
  it). Fixing an order outlaws one of the two designs §4.2 admits.
- **The generalisable test, which is the transferable part**: a rule BOTH
  architectures see outside the re-encode can be given a precedence; one only a
  byte-retaining reader sees early cannot. Rule 4 qualifies *only* because
  neither design gets it from the re-encode.
- **The Rust replay asserts the error FAMILY, not the variant.**
  `vault::canonical` is `pub(crate)`, so an integration test cannot name
  `CanonicalError::{FloatRejected,TagRejected}`. That is why MPR's vocabulary
  has one `rule4` word and not two. Same limit the canonicality corpus
  documents; now **#635**, rather than a third `assert.rs` LIMIT comment.
- **The `unknown`-subtree residual is untouched.** No duplicate-key check looks
  inside an `UnknownValue`, deliberately; `DuplicateMapKey` is never raised for
  one.
- **`differential_replay.rs` still cannot see any of this** — **#634**.
- **#621 is NOT closed.** Its case is Rust `ArraySortOrder` vs Python rule 2,
  which my sentence does not cover (it names §6.2 rules 1-3, not §4.2's array
  disciplines). The comment on it carries the argument that would close it.
- **#623 / #624 / #625 / #626 / #628 / #629 / #630 / #633 / #612 / #596 / #603 /
  #609 / #610 / #611 / #619 / #620 stay open and untouched.**

---

## (3) What is next — with acceptance criteria

**(a) #621 — the multi-violation precedence divergence.** Now the cheapest real
item, and this slice did most of the thinking. Rust says `ArraySortOrder`,
Python says rule 2, same bytes, offset 929. **Acceptance:** extend §4.2's new
"unspecified" sentence to cover §4.2's five array disciplines alongside §6.2
rules 1-3 — the two-architecture argument already there justifies it verbatim —
and make MCC's docstring and `classify.rs` say so. **Still needs a user ruling**
on whether to declare it unspecified (cheap, and now well-founded) or to fix a
precedence (expensive, and would have to break one architecture). Read the
comment posted on #621 first.

**(b) #634 — `differential_replay.rs` scores reject-vs-reject as agreement.**
Filed by this slice. The harness that exists for cross-language decoder
agreement was green throughout a live divergence. **Acceptance:** either compare
a normalised rule token with an explicit allowlist for the pairs §4.2 declares
unspecified (the typed vocabulary exists on both sides now), or record the
limitation at that arm so the next person does not assume it is covered.

**(c) #612 — `manifest_uniqueness_kat.rs` (848 lines).** REOPENED, and the
tracker believed it done once already, so it will be lost again if not taken
soon. `80c3c488` is the worked example. **Acceptance:** under 500, sharing its
`Case` / `Verdict` / surgery helpers through a `manifest_uniqueness_kat_helpers/`,
committed as a behaviour-preserving move with the test name set diffed.

**(d) #633 — writer-side encode refusals reach users as "try again".** All six
(#600's three, #587's three) fold through a `VE::Manifest(_)` wildcard, so iOS
renders retry advice for a deterministic programmer bug. Zero tests pin the
mapping either way. **Acceptance:** the cheap half — one bridge test asserting
the six fold where they do, plus a comment at the wildcard noting the enum
inside is not covered by that file's no-catchall guarantee.

**(e) #625 — `card.rs` is 1264 lines.** Directory module split by ROLE, every
file under 500, behaviour-preserving, with `golden_vault_001` /
`conformance.py` / the byte-identity tests green throughout.

**(f) #596 — a `manifest_body` cargo-fuzz target, the natural eighth.** The seed
corpus is 38 bodies. Note this slice added **no** seeds, deliberately: a
precedence row's value is its expected RULE, which a crash-only fuzz target
cannot read.

**(g) #623 / #624 / #626 / #628 / #629 / #630 / #635 / #603 / #609 / #610 / #611
/ #619 / #620 stay open and untouched.**

### Issues this slice closes — verify against the code, not this document

**#618.** Per the `(#N)`-not-`Closes #N` convention it stays open until a human
closes it — and per the previous baton's §(0), **do not close it from a merge
sweep without checking the code first.** Acceptance is checkable in four commands:

```bash
# 1. The corpus replays, and its bodies are bound to their labels.
cargo test --release -p secretary-core --test manifest_precedence_kat   # 4 passed
# 2. The clean-room half is registered and green.
uv run core/tests/python/conformance.py | grep -A 3 "Section MPR"
# 3. REG went up by one.
uv run core/tests/python/conformance.py | grep "section registry"       # 28/28
# 4. The spec says it.
grep -c "Which rule a reader reports" docs/vault-format.md              # 1
```

---

## (4) Open decisions and risks

### The finding that generalises furthest: a documented scope is not a pinned one

`reject_floats_and_tags` is **rule 4 only**, and the reason is real — widening it
to `_check_canonical_item` reintroduces the divergence in the other direction.
I wrote that reason into the function's docstring, the call site's comment and
CLAUDE.md. Then I measured it: **widening the pre-pass to rules 2+3+4 left the
ENTIRE verifier green, exit 0, zero FAIL lines.** Three prose statements, zero
tests.

`manifest_precedence_kat.json`'s `top__non_shortest` row exists solely to red
that mutation. It is `Level::Top`-only **by the spec, not for convenience**: at a
nested level the enclosing value's canonicality check fires first in a
byte-retaining reader, which is exactly the ordering §4.2 declines to fix, so a
nested row would assert something no conformant reader owes.

**Generalise it:** when you write "this must not be widened, because X", the next
action is to widen it and watch something red. If nothing does, the constraint is
a comment.

### The measurement trap this slice hit: a stale `.pyc` reported a false GREEN

Mutation P5 (move the duplicate check after the value's canonicality check)
reported **exit 0, zero failures**. It was wrong. P5 was the only
**size-preserving** mutation in the set — a pure statement reorder — and it was
applied and reverted inside one second. CPython invalidates a `.pyc` on
`(source_mtime, size)` with the mtime stored in whole **seconds**, so the stale
bytecode was served and the mutation never ran.

I caught it only because the result was *surprising* — I could see by reading
that `_check_canonical_item` raises rule 3 on that row's second copy — and
debugged rather than recording the green. The harness now clears `__pycache__`
and sets `PYTHONDONTWRITEBYTECODE`; P5 reds.

**This is already in memory as a known trap and I still hit it.** The tell is not
the mechanism, it is the shape: **a mutation that changes no bytes is the one
whose green you must not believe.**

### A gap found by mutating the FIXTURE rather than the code

R4 — replacing five nested rows' bodies with the top-level one — red the Rust
replay (`every_row_body_matches_the_case_its_label_names` rebuilds each body) and
left **Python green**. Python cannot rebuild a body; it has no encoder for one.

Measuring the narrower R4b (bodies swapped, `field` column left alone) showed
Python's `exc.key != row["field"]` check DID catch it — my R4 had defeated it by
editing `field` in lockstep. Closed by deriving the expected key from the row's
LABEL (`_LEVEL_KEYS`), so a lockstep edit now reds Python too and defeating it
additionally requires renaming the label, which the coverage floor catches.

**Generalise it:** when a mutation reds one language and not the other, the
interesting question is not "should it?" but "what is the WEAKEST mutation that
still reds the silent side?" — that boundary is the real assertion.

### Standing risks this slice does not remove

- **Two sessions running, the baton was resolved from a stale checkout**, and the
  symlink gives no signal. Nothing structural has changed.
- **A number in a baton was stale and was reconciled against, not measured**
  (§0). The counts in *this* document were all re-measured; that is not a
  property of the format.
- **Five of the six PEP 723 deps remain unbounded** (`cryptography`, `pynacl`,
  `argon2-cffi`, `blake3`, `cbor2`), and `ed25519_verify` still has the "no
  exception means success" shape whose failure direction is fail-**open**
  (#544 / #550).
- **#634**: the cross-language decoder-agreement harness cannot see a WHICH-rule
  divergence. It was green through this slice's entire live divergence.
- **The `unknown`-subtree residual is untouched**: no duplicate-key or key-order
  check looks inside an `UnknownValue`, deliberately.
- **`card.rs` (1264), `manifest_uniqueness_kat.rs` (848), `canonical/value.rs`
  (1082), `manifest/encode/tests.rs` (620), `sync/state.rs` (570)** are all past
  the 500-line guideline — #625 / #612 / #603 / #630 / #626.
- **#628** (a `CheckedEntries` newtype for "call the check first") is unaffected;
  this slice adds no new "call it first" precondition to `encode_manifest`.

---

## (5) How to resume — the exact commands

```bash
# FIRST, and BEFORE reading the baton — this has now fired two sessions running:
git fetch origin && git log --oneline main..origin/main

cd /Users/hherb/src/secretary/.worktrees/dupkey-precedence
pwd && git branch --show-current && git worktree list   # expect feature/dupkey-precedence

# --- the gates this slice is actually about ---
cargo test --release -p secretary-core --test manifest_precedence_kat   # expect 4 passed, 1 ignored
uv run core/tests/python/conformance.py                                 # 28 sections; REG 28/28

# --- the rest of the gate set ---
cargo fmt --all --check
cargo build --release --workspace          # separate from the test run ON PURPOSE
# Redirect, then echo $? — a `| grep` pipeline reports GREP's exit code:
cargo test --release --workspace > /tmp/suite.txt 2>&1; echo "CARGO EXIT: $?"
grep -E "^test result" /tmp/suite.txt | \
  awk '{p+=$4; f+=$6; i+=$8} END {print NR, p, f, i}'   # expect 100 2142 0 22
# NOT redundant with the above — it caught a needless_lifetimes error this slice:
cargo clippy --release --workspace --tests -- -D warnings
touch core/src/lib.rs   # rustdoc caches; a ~5s run did nothing
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace

# The cross-language contract (no CI job covers this one). SLOW, and it holds
# cargo's package-cache lock — run it BEFORE the fuzz check, not in parallel.
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

# --- citation freshness: 90, and MEASURE main rather than trusting this line ---
uv run core/tests/python/spec_test_name_freshness.py

# --- format invariants. Seeds + UDL EMPTY; data/ is one ADDED file and zero
#     modified (use --name-status, a --stat cannot tell add from modify);
#     normative docs is vault-format.md only, +32. ---
git diff origin/main...HEAD --stat -- core/fuzz/seeds/
git diff origin/main...HEAD -- ffi/secretary-ffi-uniffi/src/secretary.udl
git diff origin/main...HEAD --name-status -- core/tests/data/
git diff origin/main...HEAD --stat -- docs/ ':!docs/handoffs/' ':!docs/manual/'
```

Re-running this slice's mutation harness (it clears `__pycache__` and sets
`PYTHONDONTWRITEBYTECODE` — see §(4) — and sha256-asserts every restore,
aborting rather than poisoning the next mutation):

```bash
uv run --with cbor2 python3 <scratchpad>/m_py.py    # P1-P7, Python
uv run --with cbor2 python3 <scratchpad>/m_rust.py  # R1-R3, Rust
uv run --with cbor2 python3 <scratchpad>/m_fix.py   # R4, the fixture itself
```

Re-proving the divergence this slice closed — the fastest way to see what #618
was. Revert `conformance.py`'s pre-pass and watch the two implementations name
different rules for the same bytes:

```bash
# Rust reports rule 4; pre-#618 Python reported the repeat.
git show 7b896455^:core/tests/python/conformance_lib/codec/manifest_decode.py \
  > /tmp/md-before.py
diff <(grep -n "reject_floats_and_tags" /tmp/md-before.py) \
     <(grep -n "reject_floats_and_tags" core/tests/python/conformance_lib/codec/manifest_decode.py)
```

---

## (6) Where this document lives

`NEXT_SESSION.md` at the repo root is a **symlink**, retargeted this session to
`docs/handoffs/2026-09-09-rejection-precedence-shipped.md`. This file is the
single authored baton — do not create a second copy at the root, and do not sync
it to `main` during a pause window (that produces an add/add conflict).
