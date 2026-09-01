# NEXT_SESSION.md — split the clean-room verifier into a package (#593)

Branch `feature/conformance-split`, worktree `.worktrees/conformance-split`,
base `7fa4ddb3` (`main`, i.e. immediately after PR #595 merged).

This slice is **(a)** from the previous baton's queue, which named #593 as *"THE NEXT
SLICE, not the one after"* and recorded the final review's load-bearing judgement:
shipping the #572 canonicality pin was acceptable **only because** #593 was filed with
concrete acceptance criteria. That debt is now paid.

**One issue was filed: #597** — a pre-existing, seed-dependent nondeterminism in a
rejection `detail` string, found while building the byte-exact replay baseline.
Deliberately not fixed here; see §(4).

---

## (1) What shipped

`core/tests/python/conformance.py` went from **6849 lines** to a **136-line
entrypoint** over a **52-file `core/tests/python/conformance_lib/` package**. Largest
module: **383 lines**. Nothing else in the repo changed shape — no Rust, no fixture, no
UDL, no seed.

### The three user decisions taken at the top of the session

| Question | Chosen |
|---|---|
| Package name | `conformance_lib/`, not `conformance/` — matches the in-tree `check-error-payload-hygiene.py` → `payload_guard/` precedent, where entrypoint name ≠ package name. Both were verified to work under `uv run`; the same-name form shadows the entrypoint on import, which is subtle for no gain. |
| Output uniformity | Yes, via a section registry. |
| Scope | #593 only. #594 gets its own session; its frozen-spec edit should not ride inside a diff dominated by file moves. |

### Layout, and the seam it is cut along

`wire/` vs `codec/` is **the distinction the spec itself draws**, not an invented one:
`wire/` parses a file in order to **inspect** it (the golden-vault verification path),
`codec/` parses in order to **re-emit it byte-identically** (the `--diff-replay` path).
Two pairs of modules therefore legitimately share a basename — `wire/vault_toml.py` /
`codec/vault_toml.py` and `wire/block_file.py` / `codec/block_file.py` — and each says
in its own docstring which side it is on. That is not an accident to tidy up.

```
conformance.py                  136  entrypoint: PEP 723 header + docstring + main()
conformance_lib/
  __init__.py                        the layout, and the naming convention (below)
  constants.py  cursor.py  primitives.py  derivations.py  canonical.py
  fixtures.py                        ONE anchor for every committed-fixture path
  rejection.py                       which exceptions are rejection VERDICTS
  tamper.py                          the shared byte-flip helper
  diff_replay.py                     the --diff-replay CONTRACT
  wire/     6 modules                §4.1/§6.1 envelope parsers + golden-vault verify
  codec/    9 modules                the strict decode/encode round-trip pairs
  merge/    3 modules                §11 CRDT
  sections/ 18 modules               replay drivers + registry + completeness
```

**Naming convention, recorded in `conformance_lib/__init__.py`:** a leading underscore
now means "internal to this **package**", not to the module. ~30 such names cross a
module boundary after the split. Renaming them would have turned a mechanical move into
a large semantic diff, so they were left alone **deliberately and uniformly** — a
2-of-30 rename would have been worse than none. Two were relocated rather than renamed:
`_REJECTION_EXCEPTIONS` into `rejection.py` (it had four importers, which is why
`wire/golden_vault_verify.py` was otherwise importing the replay driver to name one
tuple) and `_bytes_flip` into `tamper.py` (so Section 3 need not import Section 2).

### How the split was performed — and why that matters for review

Not by hand. An AST-driven extractor took a hand-authored map of module → source line
ranges and **derived every cross-module import by scope analysis**, so an import could
not be guessed wrong or forgotten. Two things about that tool are worth knowing, because
both were found by execution rather than by reasoning:

- Its first version used one flat bound-name set per module, which is **fail-open**: a
  function-local sharing a name with a module-level symbol elsewhere in the file masks a
  genuine cross-module reference, the import is silently omitted, and the module only
  fails at call time on whichever branch reaches it. Replaced with real scope analysis.
- `symtable.Symbol.is_global()` is **not** reliable for this question — on CPython 3.12
  a nested `def f` inside a function reports `is_global() == True` alongside
  `is_local() == True`. Resolution is done against the explicit enclosing-scope chain
  instead, with class bodies correctly not contributing bindings to their children.

`symtable` does not see names inside **string annotations**; `pyflakes` does, and caught
the four (`Path` / `Any` in `wire/device_wrap.py`) that this missed. Both tools were
needed; neither alone was sufficient.

### `main()`: one registry replacing four hand-maintained copies

Before, each section appeared in `main()` **three** times — the call-and-print block, the
banner string, the `FAIL:` line — plus a fourth appearance as one term of a 22-term `and`
chain that decided the exit code. Omitting that fourth was **silent and fail-open**: the
section's failure lines would print and `main()` would still return 0.

`sections/registry.py` declares each section once; banner, verdict line and exit code are
all derived. **Mutation-proven** (`sections/unknown_map.py` forced to return `False`):
exit 1, `FAIL:` on stderr, no `PASS`.

The registry creates a **dual** hazard that could not exist before: a section module can
now exist, be correct, and never be reached, because registering it is a separate edit
from writing it — and a never-registered section produces no banner, no output and no
failure, i.e. is indistinguishable from one that does not exist. Section **REG**
(`sections/completeness.py`) closes it, by **discovery** rather than a second
hand-maintained list (which would have the drift problem it exists to detect). Three
fail-closed checks: every discovered `section*` driver is registered; nothing registered
was not discovered; ids and banners are unique. **Both directions mutation-proven** —
unregistering Section 5 and duplicating an id each red it with a precise message.

### Correction to #593's own constraint 4

The issue says the eight newest sections "return `(ok, issues)` and print nothing when
they pass … a reader of the output cannot tell those eight ran at all." **That is stale**
— the PR #595 fix wave gave all eight summary `PASS` lines, and the baseline run shows
all 22 sections reporting. The registry still earns its place, but on the argument above
(three-copy drift + a fail-open exit code), not on that one. The corrected premise is
recorded as a comment on #593.

### Incidental fixes, each a real defect the split exposed

- **`fixtures.py`: one anchor, not nine.** Every helper re-derived the layout inline, in
  two different spellings (`.parent.parent` and `.parents[1]`), so the one-level-deeper
  `__file__` broke them individually. Now all hang off `test_data_dir()`. Three
  fuzz-seed paths in the guard sections likewise route through `manifest_body_seed()`.
- **Section 4b's banner and `FAIL:` line disagreed** ("trash-list merge replay" vs
  "…merge cross-language replay"). The registry derives both from one title, so the
  drift is now unrepresentable. This is one of only two stdout changes.
- **Stale pointers in the PEP 723 header** — a comment that says "Cite the symbol, not
  the line" then twice said "below" about `ml_dsa_65_verify`, which now lives in
  `conformance_lib/primitives.py`.
- `spec_test_name_freshness.py`'s allowlist comment, `differential-replay-protocol.md`'s
  "Adding a new target" steps, and `core/fuzz/README.md`'s pointer all updated.

---

## (2) What this slice does **not** claim

- **It is not a rewrite.** Every one of `main`'s **229** top-level definitions is present
  (`LOST: NONE`, verified by AST comparison). The nine gained are exactly `Section`,
  `SECTIONS`, `discover_drivers`, `section_registry_completeness`, `_NON_DRIVER_MODULES`,
  `__all__`, `test_data_dir`, `manifest_canonicality_kat_path`, `manifest_body_seed`.
- **It fixes no decoder and changes no acceptance set.** #594's Rust/Python divergence is
  untouched and still live.
- **The two stdout changes are exactly two**, and both intended: Section 1 gains a banner
  (it was the only section without one), and Section 4b's banner adopts the `FAIL:`
  wording. Everything else is byte-identical.
- **The `--diff-replay` contract is byte-identical to `main`** across all 40 committed
  corpus inputs — 7 targets plus the two harness-failure paths — **with
  `PYTHONHASHSEED=0`**. That qualifier is load-bearing: see #597 in §(4).
- **`REG` checks the registry, not the sections.** It proves every driver runs; it says
  nothing about whether a driver's assertions are good.

---

## (3) What is next — with acceptance criteria

**(a) #594 — the manifest's three uniqueness invariants are enforced by Rust and stated
NOWHERE in `docs/`.** Now the top of the queue, and the previous baton's reasoning is
unchanged: `DuplicateBlockUuid`, `DuplicateTrashUuid` and `VectorClockDuplicateDevice`
have no normative counterpart (`grep -c "uniq" docs/vault-format.md` returns **0**), and
§4.2's sort disciplines do not imply them — `[x, x]` **is** sorted. A body with two
`blocks[]` entries sharing a `block_uuid` is ACCEPTED by the Python reader and rejected
by Rust. **Two halves that must land together:** the frozen-spec edit stating the three
invariants, and the `py_decode_manifest` fix. Doing only the second encodes a rule the
spec still does not state — the divergence class the #572 slice existed to remove.
**Acceptance:** §4.2 states all three; `py_decode_manifest` rejects each; each pinned by
a test row; golden vault still decrypts and `conformance.py` still PASSes. The fix now
lands in `conformance_lib/codec/manifest_decode.py`, and its guard rows belong in
`sections/manifest_body_schema_guards.py`.

**(b) #597 — the nondeterministic rejection detail** (filed this session). Small, and
worth doing before anyone else tries to take a byte-exact replay baseline.
**Acceptance:** the same input under two different `PYTHONHASHSEED` values yields an
identical `detail`; verdicts (`status` / `error_class`) unchanged.

**(c) #590 — `ManifestError::NonCanonicalEncoding` collapses five causes with no
locator, on the every-open path.** Unchanged from the previous baton, including its
correction: six of the 21 corpus rows land on one undifferentiated variant, not all of
them — `*__rule4_float` is caught earlier by `reject_floats_and_tags` as
`CanonicalError::FloatRejected`, which already carries a field hint. **Acceptance:** the
variant carries a fieldless cause discriminant plus a byte offset (the `CborFault` shape,
so it stays data-free by construction); each of those six rows names its own cause; the
payload-hygiene guard passes with **no new allowlist entry**.

**(d) #589 — the 21 duplicate-key guards are hand-copied, not a type invariant.**
**Acceptance:** expressed once; all 21 sites route through it; deleting the single
implementation reds more than one test.

**(e) A `manifest_body` cargo-fuzz target — the natural eighth.** **Acceptance:**
`core/fuzz/fuzz_targets/manifest_body.rs` exists, starts from the 21 seeds already at
`core/fuzz/seeds/manifest_body/`, and `CLAUDE.md`'s "Seven targets" line becomes eight.

**(f) #586 / #587 stay open and untouched.** The encoder can still emit or sign a body
its own decoder would reject. **Do not record these as addressed.**

### Issues this slice closes — verify against the code, not this document

**#593.** Per this repo's `(#N)`-not-`Closes #N` convention it stays open until a human
closes it. Nothing here closes **#594, #590, #589, #586, #587, #597**.

---

## (4) Open decisions and risks

### Rulings taken on the reader's behalf

1. **Underscore names left alone, uniformly.** See §(1). Cost if wrong: ~30 names read as
   module-private while being package-internal; mitigated by stating the convention in
   `conformance_lib/__init__.py`.
2. **`sections/` split into three guard modules by what they check** — schema (MD/MDN/
   MRK/MERF), shape (MSS/MSH), canonicality (MOC/MAS) — rather than two, because every
   two-way cut put at least one section under a name that did not describe it.
3. **`REG` runs last.** It reports on the table above it, so it reads as a summary of the
   run rather than a precondition for it.
4. **#597 filed, not fixed.** This PR's central claim is that the `--diff-replay`
   contract is byte-identical before and after; editing a decoder's rejection text in the
   same change would muddy exactly that claim.
5. **README.md deliberately NOT changed.** Its two `conformance.py` references are the
   invocation and the doc-table entry, both still accurate. The internal file layout of a
   test script is below README's altitude.

### A verification trap worth carrying forward

A mutation test's **restore** step was verified with `git diff --stat`, which reports
nothing for an **untracked** file — the whole new package was untracked at that point, so
the check was **vacuous** and reported a restore that had not happened. The real cause
was a **stale `__pycache__`**: `"MOC"` → `"MAS"` is a same-length edit, so the restored
file had identical size and (same second) mtime and Python reused the mutated bytecode.
This is the Python flavour of the known cargo mtime trap, and it can produce a false
**PASS**. Purge `__pycache__` between mutation rounds, and never verify a restore of an
untracked file with `git diff`.

### Standing risks this slice does not remove

- **`conformance.py` is still not a blocking gate.** The `clean-room conformance` job is
  not in `main`'s `protect_main` ruleset by name, so it runs without blocking (unchanged
  from #546; noted so the split is not misread as strengthening it).
- **Five of the six PEP 723 deps remain unbounded**, and `ed25519_verify` still has the
  "no exception means success" shape whose failure direction would be fail-**open**
  (#544 / #550). The split moved that function; it did not change it.

---

## (5) How to resume — the exact commands

```bash
cd /Users/hherb/src/secretary/.worktrees/conformance-split
pwd && git branch --show-current && git worktree list   # expect feature/conformance-split

# --- the gate this slice is actually about ---
uv run core/tests/python/conformance.py                 # expect exit 0, trailing "PASS"
uv run --with pyflakes python -m pyflakes core/tests/python/conformance.py \
                                          core/tests/python/conformance_lib

# --- the cross-language contract (no CI job covers this one) ---
cargo test --release --workspace --features differential-replay
cargo check --release --features differential-replay --tests -p secretary-core

# --- the rest of the gate set ---
cargo fmt --all --check
cargo build --release --workspace                       # separate from the test run ON PURPOSE
cargo test  --release --workspace
cargo clippy --release --workspace --tests -- -D warnings
touch core/src/lib.rs   # rustdoc caches; a ~5s run did nothing
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

# --- citation freshness: baseline is 90, unchanged from main ---
uv run core/tests/python/spec_test_name_freshness.py

# --- format / fixture invariants: all three must be EMPTY ---
git diff main...HEAD --stat -- core/tests/data/
git diff main...HEAD --stat -- core/fuzz/seeds/
git diff main...HEAD --stat -- ffi/secretary-ffi-uniffi/src/secretary.udl
```

Re-taking the byte-exact `--diff-replay` baseline (**pin the hash seed** until #597 lands
— otherwise one `contact_card` row flips between two equally-correct rejection details):

```bash
for t in vault_toml record contact_card bundle_file manifest_file manifest_body block_file; do
  for f in core/fuzz/seeds/$t/* core/tests/data/fuzz_regressions/$t/*; do
    [ -f "$f" ] || continue
    printf '%s\t%s\t%s\n' "$t" "$f" \
      "$(PYTHONHASHSEED=0 uv run core/tests/python/conformance.py --diff-replay "$t" "$f")"
  done
done
```

---

## (6) Where this document lives

`NEXT_SESSION.md` at the repo root is a **symlink**, retargeted this session to
`docs/handoffs/2026-09-01-conformance-split-shipped.md`. This file is the single authored
baton — do not create a second copy at the root, and do not sync it to `main` during a
pause window (that produces an add/add conflict).
