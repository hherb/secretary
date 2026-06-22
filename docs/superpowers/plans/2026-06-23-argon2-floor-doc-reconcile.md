# Argon2id v1-Floor Doc Reconciliation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolve issue #204 — make `docs/threat-model.md` (and two derived docs) state the *true* Argon2id v1-floor enforcement (creation-time-only), and back the real open-path defense with a regression test.

**Architecture:** Documentation-correctness change plus one new integration test. No production crypto code changes. The new test characterizes (locks in) the already-correct behavior that a tampered/downgraded `vault.toml` cannot open a vault at the pure `open_with_password` layer.

**Tech Stack:** Rust (stable), `cargo test --release --workspace`, `uv` for the `spec_test_name_freshness.py` drift checker.

## Global Constraints

- Stable Rust toolchain (workspace `rust-toolchain.toml`); always build/test with `--release`.
- `#![forbid(unsafe_code)]` workspace-wide — no `unsafe`.
- Clippy must stay clean: `cargo clippy --release --workspace --tests -- -D warnings`.
- Python via `uv` only — never `pip`.
- Tests must use random crypto values at runtime, never hardcoded byte arrays (CodeQL "hardcoded cryptographic value"). This plan's test uses `ChaCha20Rng` seeds for vault creation (matching the existing `core/tests/unlock.rs` `create()` helper) — seeds drive key *generation*, they are not themselves keys, consistent with the file's existing pattern.
- Don't fix spec/code divergence silently — this plan resolves #204 as a deliberate documentation fix with a test.
- "Both halves" hybrid-verify and KDF invariants are untouched (no verification or KDF call site changes).

---

### Task 1: Regression test — downgraded `vault.toml` cannot open via `open_with_password`

**Files:**
- Modify/Test: `core/tests/unlock.rs` (add one `#[test]` fn; reuse existing imports + `create_vault_unchecked`)

**Interfaces:**
- Consumes (already imported at top of `core/tests/unlock.rs`): `unlock::{self, create_vault_unchecked, open_with_password, UnlockError}`, `Argon2idParams`, `SecretBytes`, `ChaCha20Rng`.
- `unlock::vault_toml::decode(&str) -> Result<VaultToml, _>` and `unlock::vault_toml::encode(&VaultToml) -> Result<String, _>`; mutable field `vt.kdf.memory_kib: u32`.
- Produces: test `open_with_password_downgraded_kdf_params_fails` — cited by `docs/threat-model.md` in Task 2.

**Note on TDD shape:** This is a *characterization / regression* test — it locks in security behavior that already holds in current code (a param change yields a different Master KEK → `wrap_pw` AEAD fails). It will pass on first run. Step 2 confirms it has teeth by temporarily inverting the assertion before settling on the real one.

- [ ] **Step 1: Write the test**

Add to the end of `core/tests/unlock.rs`:

```rust
#[test]
fn open_with_password_downgraded_kdf_params_fails() {
    // #204: open_with_password does NOT enforce the v1 memory floor, but a
    // tampered/downgraded vault.toml still cannot open the vault — changing
    // memory_kib changes the derived Master KEK, so the wrap_pw AEAD unwrap
    // fails its auth tag and we get WrongPasswordOrCorrupt. This characterizes
    // the real defense the threat model relies on (no open-time floor check
    // needed). The original (strong) Argon2 cost stays bound into the
    // ciphertext regardless of what vault.toml claims.
    let pw = b"hunter2";
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    // Create at a higher-than-tamper memory cost (still tiny → fast test).
    let v = create_vault_unchecked(
        &SecretBytes::new(pw.to_vec()),
        "Alice",
        1_714_060_800_000,
        Argon2idParams::new(32, 1, 1),
        &mut rng,
    )
    .expect("create_vault_unchecked");

    // Downgrade memory_kib in the cleartext vault.toml to a different (lower)
    // sub-floor value. 8 KiB is the argon2 minimum, so the KDF itself still
    // runs — the open fails on the AEAD tag, not on a rejected param.
    let vt_str = std::str::from_utf8(&v.vault_toml_bytes).unwrap();
    let mut vt = unlock::vault_toml::decode(vt_str).unwrap();
    assert_ne!(vt.kdf.memory_kib, 8, "tamper value must differ from original");
    vt.kdf.memory_kib = 8;
    let tampered_toml = unlock::vault_toml::encode(&vt).unwrap();

    let err = open_with_password(
        tampered_toml.as_bytes(),
        &v.identity_bundle_bytes,
        &SecretBytes::new(pw.to_vec()),
    )
    .unwrap_err();

    assert!(
        matches!(err, UnlockError::WrongPasswordOrCorrupt),
        "downgraded kdf params must fail to open (different KEK → AEAD fail), got {err:?}"
    );
}
```

- [ ] **Step 2: Run and confirm it has teeth**

Run: `cargo test --release --workspace --test unlock open_with_password_downgraded_kdf_params_fails -- --nocapture`
Expected: PASS.
Then temporarily change the final `matches!(err, UnlockError::WrongPasswordOrCorrupt)` to `matches!(err, UnlockError::CorruptVault)` and re-run — expected: FAIL (proves the assertion is meaningful, not vacuous). Revert to `WrongPasswordOrCorrupt` and re-run — PASS.

- [ ] **Step 3: Clippy**

Run: `cargo clippy --release --workspace --tests -- -D warnings`
Expected: clean (no warnings).

- [ ] **Step 4: Commit**

```bash
git add core/tests/unlock.rs
git commit -m "test: downgraded vault.toml cannot open via open_with_password (#204)

Characterizes the real open-path defense: changing memory_kib in the
cleartext vault.toml yields a different Master KEK, so wrap_pw AEAD
fails (WrongPasswordOrCorrupt). No open-time floor check is needed; the
strong Argon2 cost stays bound into the ciphertext.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Correct the false floor-enforcement claim in the three docs

**Files:**
- Modify: `docs/threat-model.md` (the "Brute-force the master password" row, ~line 90; and the test-citation bullet, ~line 177)
- Modify: `docs/manual/contributors/side-channel-audit-internal.md` (~line 297-302)
- Modify: `CLAUDE.md` (the "Argon2id v1 default … v1 floor below which `open_with_password` errors" bullet under "Crypto layering")

**Interfaces:**
- Consumes: test name `open_with_password_downgraded_kdf_params_fails` from Task 1; existing tests `create_vault_rejects_sub_floor_argon2_params` (`core/src/unlock/mod.rs`), `core/tests/create_vault.rs`, `open_vault_kdf_params_mismatch_rejected` (`core/tests/open_vault_neg.rs`).
- Produces: corrected normative docs; no code interface.

- [ ] **Step 1: Fix `docs/threat-model.md` ~line 90 (Brute-force row)**

Replace the existing sentence beginning "The v1 *floor* … is **enforced as a typed error** (`UnlockError::WeakKdfParams`) at `open_with_password` time, so a tampered `vault.toml` cannot silently downgrade the cost; opening errors before any KDF runs." with:

```markdown
The v1 *floor* — `V1_MIN_MEMORY_KIB = 64 MiB`, iterations ≥ 1, parallelism ≥ 1 — is **enforced at vault creation** as a typed error (`UnlockError::WeakKdfParams` from `create_vault`), so a conformant vault is never written below the floor. A tampered cleartext `vault.toml` cannot downgrade the *effective* cost two ways: (1) changing the KDF parameters changes the derived Master KEK, so the `wrap_pw` AEAD unwrap fails its auth tag and the vault refuses to open (`WrongPasswordOrCorrupt`) — the strong Argon2 cost is bound into the ciphertext, so an offline attacker who steals the files still pays the original cost regardless of what `vault.toml` says; and (2) the orchestrator open path (`open_vault`) cross-checks `vault.toml [kdf]` against the **signed** manifest and rejects any mismatch (`KdfParamsMismatch`). Note: `open_with_password` itself does *not* re-validate the floor at read time (the spec does not require it — the two defenses above make it unnecessary). The KDF parameters are recorded cleartext in `vault.toml` (intentional — the cross-language verifier needs them to reproduce the derivation, and the values do not leak useful information beyond the work factor).
```

- [ ] **Step 2: Fix `docs/threat-model.md` ~line 177 (test-citation bullet)**

Replace:

```markdown
- **Argon2id v1 floor enforcement at open** → `core/src/unlock/mod.rs` `WeakKdfParams` typed error; `core/tests/unlock.rs` covers the open-side rejection path.
```

with:

```markdown
- **Argon2id v1 floor enforcement (creation-time)** → `core/src/unlock/mod.rs::create_vault_rejects_sub_floor_argon2_params` (unit) + `core/tests/create_vault.rs` (integration, `WeakKdfParams` via `create_vault`). The open path is *not* floor-gated; a downgraded `vault.toml` is instead defeated by (a) `core/tests/unlock.rs::open_with_password_downgraded_kdf_params_fails` (different KEK → AEAD fail) and (b) `core/tests/open_vault_neg.rs::open_vault_kdf_params_mismatch_rejected` (signed-manifest `[kdf]` cross-check).
```

- [ ] **Step 3: Fix `docs/manual/contributors/side-channel-audit-internal.md` ~line 297-302**

Replace the bullet that reads "`Argon2idParams::V1_MIN_MEMORY_KIB` floor is enforced as a **typed error** (`UnlockError::WeakKdfParams`, …) *before* any Argon2id work runs, so a tampered `vault.toml` cannot silently downgrade the cost." with:

```markdown
- `Argon2idParams::V1_MIN_MEMORY_KIB` floor is enforced as a
  **typed error** (`UnlockError::WeakKdfParams`) at vault *creation*
  (`unlock::create_vault`), not at open. A tampered `vault.toml`
  cannot downgrade the effective cost: a changed KDF param yields a
  different Master KEK (so `wrap_pw` AEAD fails), and the orchestrator
  open path cross-checks `vault.toml [kdf]` against the signed manifest
  (`KdfParamsMismatch`). No constant-time concern here — the comparison
  is over public cleartext metadata.
```

(Preserve the surrounding list formatting / line references; only the floor bullet's text changes.)

- [ ] **Step 4: Fix `CLAUDE.md` "Crypto layering" bullet**

Replace:

```markdown
- Argon2id v1 default is m=256 MiB, t=3, p=1 (`Argon2idParams::V1_DEFAULT`); v1 floor below which `open_with_password` errors is m=64 MiB (`V1_MIN_MEMORY_KIB`), iter ≥ 1, par ≥ 1. The floor is enforced as a **typed error** (`UnlockError::WeakKdfParams`), not a silent downgrade.
```

with:

```markdown
- Argon2id v1 default is m=256 MiB, t=3, p=1 (`Argon2idParams::V1_DEFAULT`); v1 floor is m=64 MiB (`V1_MIN_MEMORY_KIB`), iter ≥ 1, par ≥ 1. The floor is enforced at **vault creation** as a typed error (`UnlockError::WeakKdfParams` from `create_vault`) — `open_with_password` does NOT re-check the floor at read time (the spec does not require it). A tampered `vault.toml` still can't downgrade cost: a changed KDF param → different Master KEK → `wrap_pw` AEAD fails, and the orchestrator `open_vault` cross-checks `vault.toml [kdf]` against the signed manifest (`KdfParamsMismatch`). The floor would become load-bearing at open only if a future change-password/re-wrap flow re-derives the KEK from `vault.toml` params — that flow must route through `try_new_v1`.
```

- [ ] **Step 5: Verify no drift introduced by the new citations**

Run: `uv run core/tests/python/spec_test_name_freshness.py`
Expected: PASS / no new drift. The phantom "open-side rejection path" citation is gone; the new citations (`open_with_password_downgraded_kdf_params_fails`, `create_vault_rejects_sub_floor_argon2_params`, `open_vault_kdf_params_mismatch_rejected`) all resolve to real test names. If the script flags any citation, fix the doc text to match the exact test name and re-run.

- [ ] **Step 6: Commit**

```bash
git add docs/threat-model.md docs/manual/contributors/side-channel-audit-internal.md CLAUDE.md
git commit -m "docs: correct Argon2id floor enforcement to creation-time-only (#204)

threat-model.md falsely claimed open_with_password enforces the v1 floor
and cited a non-existent test. Correct the claim across threat-model.md,
side-channel-audit-internal.md, and CLAUDE.md to state creation-time-only
enforcement, and describe the two real open-path defenses (different KEK →
AEAD fail; signed-manifest [kdf] cross-check). Repoint the test citation
at the tests that exist plus the new regression test.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Full-suite verification

**Files:** none (verification only).

- [ ] **Step 1: Full workspace test**

Run: `cargo test --release --workspace`
Expected: all pass (prior baseline 1411 pass / 0 fail, plus the new test).

- [ ] **Step 2: Clippy + freshness re-confirm**

Run: `cargo clippy --release --workspace --tests -- -D warnings && uv run core/tests/python/spec_test_name_freshness.py`
Expected: clippy clean; freshness PASS.

- [ ] **Step 3: Confirm scope guardrail (docs + one test file only)**

Run: `git diff main...HEAD --name-only`
Expected: exactly `core/tests/unlock.rs`, `docs/threat-model.md`, `docs/manual/contributors/side-channel-audit-internal.md`, `CLAUDE.md`, plus the spec/plan docs under `docs/superpowers/`. No production crypto source (`core/src/`, `ffi/`) modified.
