# NEXT_SESSION.md — #474 secret-free error payloads in `core`, enforced

**Session date:** 2026-08-05, resuming from `main` @ `876dcfd` (PR #475 / **#472** merged during the pause window). Branch `feature/474-error-payload-hygiene`; worktree `.worktrees/474-error-payload-hygiene`.

Full brainstorm → spec → plan → **subagent-driven execution, 13 tasks, an independent review after every one** → final whole-branch review → one consolidated fix wave. User decisions: pick **#474** from the prior baton's menu; scope **"C"** (fix the class *and* enforce it, not the single site the issue names); payload shape `{ field: &'static str, index: usize }`; one branch with the Rust work first and the platform narrowing last; Python matcher plus a parity test rather than a two-language pipeline.

## Session-start cleanup

- `main` fetched, verified at `876dcfd`; dropped the merged `.worktrees/472-android-log-hygiene-gate` worktree + branch.
- **#472 confirmed already closed** with the merge SHA. Two unrelated `.claude/worktrees/` detached checkouts left alone.
- **#478 filed** — the `VaultSyncError.Failed` follow-up drafted but never filed by the prior session. Its pinning test cited "the #475 follow-up", which did not exist.

## (1) What we shipped

**#474.** `core/src/vault/record.rs` formatted a **decrypted CBOR field name** into `RecordError::DuplicateKey`'s message. That string reached iOS as `VaultAccessError.corruptVault` (logged at `privacy: .public`) and Android as `VaultBrowseError.SaveCryptoFailure` (logcat, which has no redaction concept at all). Both platforms defended by **redacting the whole arm** — losing the detail for *every* corruption diagnostic, not just the leaking one.

The branch fixes it at the source, proves it stays fixed, and takes both redactions off.

### The issue understated the surface by an order of magnitude

The issue names one site. A sweep of every `#[error(...)]` in `core/src/**` found **129 variants that interpolate anything** and **23 that interpolate a runtime `String`**. Three facts reshaped the slice before code was written:

- `RecordError::DuplicateKey` has **three** construction sites, not one.
- **`BlockError::DuplicateKey` is the identical leak** and the issue never mentions it. So is `BundleError::UnknownField`, which carries an arbitrary map key read from the **decrypted identity bundle**.
- Six variants stringify a `ciborium` error whose `Display` is its `Debug` form, printing `Semantic(_, String)` verbatim. Those were safe **only** because every production `from_reader` targets `ciborium::value::Value` — a content-traced claim about a third-party crate, invalidated by a version bump with no diff near any error definition. That is why option "A" (fix `DuplicateKey`, narrow the iOS redaction) could not honestly deliver its own second acceptance bullet.

### The mechanism

- **Group 1 — plaintext-bearing.** `{ field: &'static str, index: usize }` — a compile-time-constant map-level hint plus an ordinal, rendered 1-based like `MnemonicError::UnknownWord`. **Strictly more diagnostic information than the old message**: you now learn which of the four map levels raised it.
- **Group 2 — `ciborium` passthrough.** New pure module `core/src/cbor.rs`; `classify_de`/`classify_ser` discard the upstream message at the boundary and project onto a fieldless `CborErrorKind` plus an optional byte offset. It is the **only** place in the tree that ever sees that message.
- **`CardError` / `BundleError` split by shape**, not blanket-swapped — they carried ~50 hand-written literals a type swap would have destroyed. Now `CborFault` for real codec faults, `Malformed(&'static str)` for structural literals, `MissingField`/`DuplicateField { field: &'static str }`, `UnknownField { index }`.
- **`scripts/check-error-payload-hygiene.py`** — default-deny, `--self-test` **39 positive / 18 negative**, 11 reviewed allowlist entries in three sections by review weight, wired into `test.yml` on ubuntu.
- **Both platform redactions removed.** `InvalidArgument` stays redacted on both: its payload is *platform*-authored (`RecordEditModel.kt` / `RecordEditViewModel` interpolate a decrypted field name), a different class entirely.

### Two structural results worth more than the diff

**`set_once`'s `&'static str` parameter makes an invariant compile-time enforced.** "This key is always a spec constant" used to be a comment. Two independent reviewers proved it by trying to pass the loop-local `String` and getting `E0597: argument requires that `key` is borrowed for `'static``.

**The guard's lexer is verified against `rustc` itself** — 200k randomized adversarial inputs, all 53 `core/src` files × 7 blank-kind combinations, and a **26-shape differential** where each shape is compiled and the compiler's verdict on whether a `const` is module-scope is compared to the guard's. 26/26 agree, zero fail-open.

### Commits

| SHA | What |
|---|---|
| `4d48298` `26b7abb` | design spec, implementation plan |
| `f238446` | `core/src/cbor.rs` — `CborFault` + classifiers |
| `8922d65` `2345cf5` `05a93c0` | `RecordError`/`BlockError::DuplicateKey` → `{ field, index }` |
| `cbf6a74` | four pure-passthrough enums → `CborFault` |
| `2909053` `df5a30e` `2bb6905` | `CardError` / `BundleError` splits; `SyncState`'s ciborium fix |
| `1834abe` … `c609c53` | the guard: landed RED, then **five fix rounds** |
| `857d8da` `685db68` | allowlist populated — **guard GREEN** — + parity test |
| `0074ed4` | CI job |
| `13a8069` `b932ae7` | iOS and Android redactions removed |
| `7191185` `b3f4243` | docs; the `#473`/`#476` citation correction |
| `0e8f551` `e4dfda2` `df01a0c` | final fix wave |

### The reviews are the story of this session

Every task got a fresh implementer and an independent reviewer, and the reviewers verified by **execution** — mutating real source and watching the right thing fail — not by reading.

**The guard took five fix rounds, and every round's fix created the next round's hole.** Reviewers defeated it with: a `#[source]` attribute on a *struct* field (which hid **two live `std::io::Error` sites** — a filesystem path — because `parse_fields` split on the first `:`); `#[cfg(all())]` between the attribute and the variant; a raw string containing its own declaration (`r#"a" const X: usize = 1; "b"#`); and a char literal `'}'` popping the brace stack. Round 5 replaced four ad-hoc blanking passes with **one lexer**, which is what finally converged.

**The final review found a Critical the parked list had rated "defer".** `type CborFault = String;` was a lint-clean, one-line, single-file silent bypass. The documented limit named only `type usize = String;` — which rustc's own `non_camel_case_types` rejects under `-D warnings`. The CamelCase spelling compiles silently. `find_type_aliases` already discovered the alias by name; denying `DATA_FREE_TYPES ∩ aliases.keys()` closed it in ~2 lines.

**Five vacuous controls were caught by mutation.** Three in the guard's own self-test — including one pinning the *single feature the plan singled out as essential*, which broke nothing when deleted. One test caught a regression only incidentally, via a hardcoded shape pattern that a future edit would have loosened.

**My plan was wrong at least six times, and the process caught every one.** Stale line numbers in three briefs; an instruction that did not type-check (`card.rs:272` wraps `encode_canonical_map`, not a raw ciborium error); a producer count of 3 where the truth was 10 across 4 files; a suggested test input (`&[0xA2]`) that was vacuous because it classifies as `Io`; and a design spec carrying five false claims by the end, corrected in the final wave.

## (2) What's next

- **#478 is scoped narrower than the gap it is cited for.** It covers `VaultSyncError.Failed`; three sites cited it as owning the whole "guard scans `core/src/**` only, the FFI bridge is unscanned" gap. Those citations are now honest, but **if #478 closes the narrow way, the `CorruptVault`/`SaveCryptoFailure` bridge-authored details become unowned** — the very arms this branch un-redacted. **Acceptance:** either file a dedicated bridge-scan issue and re-point the citations, or amend #478's acceptance to make the broad reading mandatory. *(An issue is drafted in the fix-wave report; it was not filed because issue creation needs your sign-off.)*
- **#476** — Android sibling of #473: three sites render a carried diagnostic as on-screen copy. **Acceptance:** the three render friendly copy, their allowlist entries go, guard still passes. `CreateVaultWizardScreen.kt:63` is legitimate and must be left alone.
- **#477** — retire the Kotlin grep rules for a type-aware detekt rule. **Acceptance:** catches every `--self-test` positive control including the ones rule C cannot; the four non-throwable entries are deleted; `check-log-hygiene.sh` is removed in the same change or a decision recorded for why both remain.
- **#474 follow-up (small):** add control **P40** for the symmetric half of `foreign_use_names`' union — see risks below.
- **#459 on-device confirmation** — still outstanding. **Acceptance:** install on the iPhone, type a new grace value, tap Save **without** dismissing the number pad, re-open Settings, confirm it persisted; then clear a field, Save, confirm the refusal. **Run the repro INSIDE the grace window** — outside it the Face ID prompt dismisses the keyboard, which flushes the binding and reads as a false "no bug". Also one pass with an Arabic or Persian keyboard.
- **#464** — CodeQL Swift analysis. #469 proved the recipe. **Acceptance:** `swift` appears in `gh api repos/:owner/:repo/code-scanning/analyses` after it lands on `main`.
- **#417** — mobile Trash purge-notice render test. **#447** — biometric unlock for Tauri desktop (needs the ADR-0011 coexistence question first). **#443 / #444** — Linux/Windows presence providers, not testable on this macOS host.

## (3) Open decisions and risks

- **The guard scans `core/src/**` only.** The FFI bridge builds its own detail strings and is unscanned. Live proof this is not theoretical: `SettingsWarning::Corrupt` (`ffi/.../settings/orchestration.rs:70`) interpolates a **decrypted settings field name**. It is not an `FfiVaultError` and reaches only desktop, so it is out of this branch's scope — but it is exactly the shape the guard cannot see. See the #478 item above.
- **The symmetric half of `foreign_use_names`' union has zero control coverage** — and it is fail-open in direction. Pointing the pass at the *raw* read only (dropping the blanked half) leaves the **entire self-test green at exit 0**. The uncovered shape is real: `use std::/*why*/io::Error;` yields `[]` from the raw read and `['Error']` from the blanked one. The wave closed one half of a two-sided gap; this is the other half.
- **Allowlist Section 3 holds construction-site claims the guard structurally cannot verify.** It sees *declarations*, not producers. Five entries rest on "a human read every current producer" — and that enumeration was wrong twice before the fix round made it exhaustive. A new producer passing real vault content would be caught by review of the allowlist comment, not by CI.
- **Five residual disclosures, now stated rather than implicit.** `CborFault.offset` and `DuplicateKey.index` are new; `RecordError::InvalidUuid { length }`, `BlockError::InvalidUuid { length }` and `ManifestError::InvalidByteLength { length }` are pre-existing byte lengths over decrypted plaintext — but **this branch is what first routes them to logcat and the unified log** by removing the redactions. All are positional/length oracles, accepted because file sizes are already disclosed.
- **Documented guard limits:** no macro expansion (unclosable lexically); foreign **glob** imports (`use some_crate::*;`) leave bare-name credits intact; a shadow whose name is in *no* trusted set (e.g. `type Fingerprint = String;`) needs a real resolver; `scan_source` locates `#[error(` with strings intact **on purpose**, since blanking there is the one fail-open direction.
- **Kotlin block comments NEST.** Writing `core/src/**` or `ffi/.../src/**` literally inside a KDoc opens a nested comment and silently swallows the rest of the file. This bit two separate agents this session, with 16 cascading unresolved-reference errors the second time. Write "everything under `core/src/`" instead.
- **`android/vault-access` uses `kotlin("jvm")`, not the Android Gradle plugin**, so `:vault-access:compileDebugKotlin` does not exist — the real task is `:vault-access:compileKotlin`. And `:vault-access:test` is **not** on the branch's standard verify list despite catching a real Kotlin breakage; consider adding it for any commit touching Kotlin.
- **Four agents stalled by backgrounding a slow build and returning unfinished.** Work was never lost, but each cost a resume cycle. Instruct implementers to run foreground with a long `timeout`.

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# After the PR merges (squash-merge leaves the branch "not fully merged"):
#   git worktree remove .worktrees/474-error-payload-hygiene && git branch -D feature/474-error-payload-hygiene
git worktree list && git status -s

# Gates for this slice (run from the worktree while the PR is open):
#   cd /Users/hherb/src/secretary/.worktrees/474-error-payload-hygiene
#   cargo test --release --workspace
#   cargo clippy --release --workspace --tests -- -D warnings
#   RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
#   uv run core/tests/python/conformance.py
#   uv run core/tests/python/spec_test_name_freshness.py
#   uv run scripts/check-error-payload-hygiene.py --self-test && uv run scripts/check-error-payload-hygiene.py
#   bash ios/scripts/check-public-log-hygiene.sh --self-test && bash ios/scripts/check-public-log-hygiene.sh
#   bash android/scripts/check-log-hygiene.sh --self-test && bash android/scripts/check-log-hygiene.sh
#   bash ffi/scripts/check-lean-binding.sh --self-test && bash ffi/scripts/check-lean-binding.sh
#   bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh
#   bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh
#   swift test --package-path ios/SecretaryVaultAccess
#   (cd android && ./gradlew :vault-access:test :kit:compileDebugKotlin)
```

**Acceptance, verified at `df01a0c`:** `cargo test --release --workspace` **96 suites, 0 failures** · clippy `-D warnings` **clean** · rustdoc `-D warnings` **clean** · `conformance.py` **pass** · `spec_test_name_freshness.py` **116 resolved / 0 unresolved** · error-payload guard **39 positive / 18 negative**, real scan **exit 0** · iOS log guard **21/9** · Android log guard **27/14** · lean-binding guard **pass** · both uniffi conformance runners **38/38** · `swift test` **357/357** · `:vault-access:test` **442 tests, 0 failures** · `git diff main... -- ffi/secretary-ffi-uniffi/src/secretary.udl` **EMPTY** · **all 26 commits carry the trailer**.

**Not verified locally:** the new CI job on a real runner (no workflow in this repo has installed `uv` before — `astral-sh/setup-uv` is SHA-pinned and the SHA was confirmed to be a real commit that `v9.0.0` resolves to, but it has never executed); branch-protection required-checks config; `core/fuzz` compilation (grep-verified only — it is workspace-excluded and needs nightly); `:app:assembleDebug` (~10 min, four ABIs); the iOS `SecretaryKit` / `SecretaryApp` targets.

## (5) Handoff file model

`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; the symlink retargeted in the same commit on the feature branch (new path → no add/add conflict). The handoff rides inside the PR — do **not** sync to `main` during the pause window. If resuming this branch for fixups, `git fetch origin && git merge origin/main` first (branch version wins on this doc) before editing.

## Closing inventory

- **State on close:** PR on `feature/474-error-payload-hygiene`, shipping **#474**. Net: `core/src/cbor.rs`; three error enums' plaintext payloads restructured; two enums split by shape; six CBOR variants declassified; a new fail-closed CI guard with an 11-entry reviewed allowlist and a Python↔bash parity test; both platform redactions removed; docs. **No on-disk format change, no `FfiVaultError` variant change, no `.udl` change.**
- **Docs:** README and ROADMAP **unchanged by precedent** — verified by grep that `#189`, `#467` and `#472`'s guards appear in neither. CLAUDE.md gained the command pair, an architecture section, and a **replacement** for the now-obsolete instruction that said `SaveCryptoFailure` must stay redacted.
- **Next:** **#478 scope** · #476 · #477 · guard control P40 · #459 on-device · #464 · #417 · #447 · #443/#444.
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-08-05-474-error-payload-hygiene-shipped.md`.
