# NEXT_SESSION.md — FFI TOFU-substitution hardening (#206) ✅ SHIPPED (PR opening)

**Session date:** 2026-06-24→25. Started from a clean baton — PR #296 (#207/#208/#209 daemon cluster) had merged to `main` (`648f6887`); cleaned up the prior `.worktrees/daemon-rollback-hardening` worktree + deleted branch. Picked **#206** (FFI `share_block` TOFU substitution — you chose it over #295 / #210 / #251+#229). Brainstormed → spec → plan → executed via **subagent-driven development** (fresh implementer + spec/quality reviewer per task, final whole-branch review on opus) → fixed review findings → README note → opening PR.

**Status:** ✅ **SHIPPED — branch `feature/ffi-share-tofu-hardening`, PR opening.** Bridge security hardening + PyO3 + uniffi projection; final whole-branch review (opus): **Ready to merge, 0 Critical / 0 Important**; 1 final-review Minor fixed (`dfffc96e`), 2 carried Minors deferred (justified).

## (1) What we shipped this session

**The vulnerability (#206, Medium, security):** the only recipient-sharing primitive projected through PyO3/uniffi was the **raw `share_block`**, which trusted caller-supplied contact-card bytes. A forged card (a trusted contact's `contact_uuid` + attacker KEM keys, attacker-self-signed so it passes `verify_self`) let an FFI consumer (a) **re-key a block to the attacker** (keys taken from caller bytes) AND (b) **overwrite the trusted on-disk `contacts/<uuid>.card`** (persistent TOFU substitution, load-bearing for all future recipient resolution). The safe primitives (`import_contact_card` TOFU-import, `share_block_to` share-by-UUID) already existed in the bridge but were **never projected** to Python/mobile.

**The fix (two halves, `ffi/` only + one `core/` doc comment):**
- **Bridge hardening** (`share/orchestration.rs`): three gates before `core::share_block` runs — (1) `verify_self` the new card, (2) `verify_self` every existing recipient card (both Ed25519 ∧ ML-DSA-65 halves, via `read_verified_card`), (3) a pure TOFU **non-overwrite guard** (`guard_new_recipient_no_substitution`): on-disk card byte-different → reject `ContactAlreadyExists`; byte-identical → allow (legit re-share / the `share_block_to` path); absent → allow (first-contact TOFU). Closes both harms before any re-key/overwrite.
- **Core doc-contract** (`orchestrators.rs` Step 12): comment only — states callers must supply verified, non-substituting bytes; the FFI projection enforces it. No behavior/format change.
- **Projection**: `import_contact_card` / `share_block_to` + a `ContactSummary` type now exposed on **PyO3** (pyclass + 2 pyfunctions, `src/contacts.rs`) and **uniffi** (`ContactSummary` dictionary + 2 namespace fns + UDL, `wrappers/contacts.rs` + `namespace/contacts.rs`). Raw `share_block` retained (smoke harness + pinned uniffi checksum depend on it) but **documented discouraged** across bridge rustdoc / pyo3 docstring / UDL.
- **No new `FfiVaultError`/`VaultError` variant** — the guard reuses `ContactAlreadyExists`; `share_block_to`'s missing-card reuses `ContactNotFound`. Both were already projected across UDL / uniffi `From` / pyo3 exception classes / Swift+Kotlin `ConformanceErrors` (the D.1.6/D.1.7 scaffolding had landed the error surface but never wired the functions). → zero exhaustive-match / conformance-harness churn, and `conformance.py` untouched.

**Branch commits** (off `main` @ `648f6887`):
| SHA | What |
|---|---|
| `bbd8d02c` | design doc (`docs/superpowers/specs/2026-06-24-ffi-share-tofu-hardening-design.md`) |
| `d2cfaf19` | design: bring existing-recipient-card verification into scope |
| `9ea80cc2` | implementation plan (`docs/superpowers/plans/2026-06-24-ffi-share-tofu-hardening.md`) |
| `6e4c2061` | **fix(#206)**: harden raw `share_block` (3 gates) + core doc-contract (Task 1) |
| `9dabe1a3` | **test**: verify-gate tests parse-then-verify-fail (Task 1 review fix) |
| `6e9b9260` | **feat(ffi-py)**: project `import_contact_card` / `share_block_to` + `ContactSummary` (Task 2) |
| `6e298e74` | refactor(ffi-py): tidy per review (Task 2 review fix) |
| `fdeb07d2` | **feat(ffi-uniffi)**: project the same + `ContactSummary` dictionary + smoke (Task 3) |
| `6b5340ca` | refactor(ffi-uniffi): tidy per review (Task 3 review fix) |
| `dfffc96e` | docs(ffi): guard raw-bytes-comparison is fail-closed (final-review Minor) |
| `d63b9069` | docs(readme): note #206 hardening + verified path on the B.4d row |
| (+ handoff commit) | this baton + retargeted `NEXT_SESSION.md` symlink |

**Tests added:** Bridge — `mint_forged_card` helper + 4 tests in `tests/share_block.rs`: the **teeth test** (`share_block_raw_rejects_substituting_a_trusted_card` — asserts `ContactAlreadyExists`, on-disk bytes byte-unchanged, AND block not re-keyed; fails on pre-fix code), `..._rejects_unsigned_new_card` + `..._rejects_unsigned_existing_card` (parse-then-verify-fail, asserting the "self-signature" detail so they prove the *verify* gate fired, not the parse gate), `..._allows_byte_identical_existing_card_on_disk`. PyO3 — `tests/test_contacts.py` (import round-trip + duplicate→`VaultContactAlreadyExists` + tampered→`VaultCardDecodeFailure`). uniffi — `ContactSummary` round-trip + Swift smoke (Assert 31) + Kotlin smoke (Assert 32): import → `share_block_to` (2 recipients) + duplicate-import → `ContactAlreadyExists`.

### Acceptance (all GREEN locally on the branch, verified by the controller, not assumed)
```bash
cd /Users/hherb/src/secretary/.worktrees/ffi-share-tofu-hardening
cargo test --release --workspace                             # exit 0 (all crates)
cargo clippy --release --workspace --tests -- -D warnings    # clean
cargo fmt --all -- --check                                   # clean
uv run core/tests/python/conformance.py                      # PASS (unchanged — no format/semantics change)
# foreign layers (all ran + passed this session):
cd ffi/secretary-ffi-py && uv run maturin develop --release && uv run pytest tests/test_contacts.py -v
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh             # Swift smoke (62 assertions incl. #206 safe-path)
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh            # Kotlin smoke (65 assertions incl. #206 safe-path)
```
**CI is the real gate once pushed** — `test.yml` (rust ×2 OS + desktop vitest + swift/kotlin conformance + smoke) + `rust-lint.yml` (fmt/clippy) + CodeQL. No new `FfiVaultError`/format surface → conformance KAT + harnesses unaffected.

## (2) What's next
**#206 done (PR open). Pick a fresh item.** Remaining sync/daemon + memory-hygiene + tooling backlog:
- **#295** — `once` mode doesn't `log_outcome` (rollback/veto surfaced only via exit code, no forensic clocks). Small, pure-Rust/cli; spinoff of the daemon cluster. Just call `daemon::log_outcome` on the `Ok` arm of `dispatch_once_subcommand`.
- **#210** — fuzz monitor dashboard binds `0.0.0.0` with no auth (docs say localhost). Python; small, quick win.
- **#251** (`openBlocks`/`VaultSession` accumulates decrypted plaintext until lock — iOS + Android) / **#229** (iOS passwords as plain `[UInt8]`/`Data` not zeroized across the Swift FFI surface) — memory hygiene; Swift/Kotlin.
- **#290** — allowlist the 3 D.4 freshness false-positives (`origin_binding`/`registrable_domain`/`exact_origin`) once the `d4-browser-autofill` session settles (worktree `.worktrees/d4-browser-autofill` still active).
- **Possible #206 follow-up (not filed):** the other already-built contact primitives (`enumerate_contact_cards`, `delete_contact_card`, `block_recipients`, `owner_card_export`, `revoke_block_from`, `contact_blocks`) are still unprojected to PyO3/uniffi. Out of scope here (security fix only); file an issue if a Python/mobile consumer needs general contact management.

**Acceptance criteria template for the next pick:** a failing test that reproduces the gap on `main`, the typed-error/enforcement surface *proven* not assumed (security paths), full `cargo test --workspace` + clippy `-D warnings` green, and spec/`conformance.py` updated in lockstep if observable bytes/semantics change.

**Open follow-up issues (carried):** #295 / #290 / #284 / #280 / #277 / #273 / #272 / #269 / #255 / #252 / #251 / #247 / #246 / #234 / #232 / #231 / #229 / #224 / #218 / #210 / #193 / #192 / #190 / #189 / #186 / #183. (#206 now closed by this PR; #207/#208/#209 + #205 + #293 closed earlier.)

## (3) Open decisions and risks
- **Guard placement = bridge, not core (deliberate).** The bridge guard fully closes the reported FFI threat (PyO3/uniffi/desktop all route through the bridge; if a trusted card is on disk the call is rejected *before* core runs). A core-level guard would additionally defend a *hypothetical future in-repo Rust caller* that bypasses the bridge — a compile-visible, code-review-catchable surface, NOT the threat model's adversary — at the cost of a new `VaultError` variant + frozen-v1 spec change + conformance re-run. Rejected as disproportionate; the core Step-12 **doc-contract** warns that caller instead. Don't "promote" the guard into core without re-litigating this.
- **Guard compares RAW caller bytes, not re-canonicalized bytes (fail-closed, by design).** A non-canonical re-encoding of a genuine card is treated as a substitution (rejected). Commented at the call site (`dfffc96e`). Do NOT "fix" it to compare `new_decoded.to_canonical_cbor()` — that would *weaken* the guard.
- **`verify_self` alone does not fix the substitution** — a fully attacker-generated card (attacker keys + victim UUID) self-verifies. The load-bearing control is the non-overwrite guard; `verify_self` is additive hygiene (reject malformed/unsigned).
- **`import_contact_card` is stricter than the share guard** (rejects *any* existing file via `path.exists()`, even byte-identical) — pre-existing, defensible asymmetry (import = "add a new contact"; share = idempotent re-share OK). Not changed.
- **Carried Minors (deferred, justified by final review):** guard uses `std::fs::read` directly rather than `core::vault::io` (read-only check, no atomicity stake); "Step 1.5" fractional comment label. Neither blocks merge.
- **Risk:** none introduced — honest-vault behavior unchanged (the new gates only bite on a forged/unsigned card or a substitution attempt; `share_block_to` flows through the same gates with disk-loaded byte-identical bytes → never false-rejects). Full suite + final security review clean.

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# If PR merged: branch + worktree .worktrees/ffi-share-tofu-hardening can be removed:
#   git worktree remove .worktrees/ffi-share-tofu-hardening && git branch -D feature/ffi-share-tofu-hardening
git worktree list && git status -s

# Run any gate locally (from the worktree if the PR is still open):
cargo test --release --workspace
cargo clippy --release --workspace --tests -- -D warnings
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; symlink retargeted in the same commit on the feature branch. New-path handoff → no add/add conflict. Branch was cut from current `origin/main` (`648f6887`) and `origin/main` had **not** advanced at handoff time (verified: `origin/main` == merge-base), so no history-binding merge was needed this session.

## Closing inventory
- **State on close:** PR opening on `feature/ffi-share-tofu-hardening` (11 code/doc commits + handoff). Worktree `.worktrees/ffi-share-tofu-hardening`.
- **Acceptance:** local GREEN — full workspace suite (exit 0), conformance PASS, clippy + fmt clean, pytest green, Swift+Kotlin smoke green. Final whole-branch review (opus): Ready to merge, 0 Critical/0 Important; 1 Minor fixed (`dfffc96e`), 2 carried Minors deferred. CI pending on push.
- **README.md:** updated — concise note on the B.4d row (#206 hardening + verified sharing path now projected). **ROADMAP.md:** unchanged — Sub-project B is already ✅ through B.6; this is a security hardening + projection within a complete milestone, not a milestone move.
- **CLAUDE.md:** unchanged (the "both halves" hybrid-verify property it documents is preserved and now also enforced at the raw-`share_block` FFI boundary).
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-06-25-ffi-share-tofu-hardening-shipped.md`.
