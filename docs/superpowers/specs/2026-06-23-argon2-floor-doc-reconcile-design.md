# Design: Reconcile Argon2id v1-floor documentation with code (#204)

**Date:** 2026-06-23
**Issue:** #204 — "Argon2id v1 floor not enforced at open; threat-model.md falsely claims it is + cites a non-existent test"
**Type:** documentation correctness + one regression test. No crypto-behavior change.

## Problem

`docs/threat-model.md` (a *normative, source-of-truth* document and a principal
handoff artifact for the paid external review) claims that the Argon2id v1
memory floor is enforced at `open_with_password` time as a typed
`UnlockError::WeakKdfParams`, and cites a test in `core/tests/unlock.rs` that
covers this open-side rejection. **Both claims are false:**

- `open_with_password` ([core/src/unlock/mod.rs:377](../../../core/src/unlock/mod.rs#L377))
  constructs params via `Argon2idParams::new(...)` — the explicitly
  *non-validating* constructor — and runs `derive_master_kek` with **no floor
  check**. The floor is enforced only at `create_vault`
  ([core/src/unlock/mod.rs:148](../../../core/src/unlock/mod.rs#L148)).
- No open-side floor test exists in `core/tests/unlock.rs`; the only reference
  there is a comment (line 18). The actual floor coverage is create-side:
  `create_vault_rejects_sub_floor_argon2_params`
  ([core/src/unlock/mod.rs:526](../../../core/src/unlock/mod.rs#L526)) and
  [core/tests/create_vault.rs:408](../../../core/tests/create_vault.rs#L408).

The same false claim is repeated in
`docs/manual/contributors/side-channel-audit-internal.md:299` and in
`CLAUDE.md` ("v1 floor below which `open_with_password` errors is m=64 MiB").

The approved B.2 design
(`docs/superpowers/specs/2026-05-04-ffi-b2-vault-unlock-design.md`) explicitly
states the opposite of the threat-model text: *"`open_with_password` does not
enforce the floor at read time (the spec does not require it)."* So the code and
the design agree; only the threat model and two derived docs are wrong.

## Why the missing open-time check is not a vulnerability

The original brute-force-downgrade concern is **cryptographically refuted**:

1. **Different params → different Master KEK.** Lowering `memory_kib` in the
   cleartext `vault.toml` changes the Argon2id derivation, producing a different
   Master KEK. The `wrap_pw` AEAD unwrap then fails its auth tag →
   `WrongPasswordOrCorrupt`. The vault does not open. The Argon2 cost is bound
   into the ciphertext, so an offline attacker who steals the files pays the
   *original* (strong) cost regardless of what `vault.toml` says.
2. **Signed-manifest cross-check.** The orchestrator `open_vault` — the only
   open path the FFI and apps use — independently cross-checks `vault.toml [kdf]`
   against the **signed** manifest body
   ([core/src/vault/orchestrators.rs:829](../../../core/src/vault/orchestrators.rs#L829))
   and rejects any mismatch with a loud typed `VaultError::KdfParamsMismatch`,
   already tested by `open_vault_kdf_params_mismatch_rejected`
   ([core/tests/open_vault_neg.rs:383](../../../core/tests/open_vault_neg.rs#L383)).

An open-time floor check would therefore add **zero** security while **breaking**
the test suite's fast-KDF strategy: most fixtures open vaults built with 8 KiB
params via `create_vault_unchecked` for speed, and an open-time floor would
reject all of them — forcing a parallel `open_with_password_unchecked` escape
hatch (API bloat for no gain) and reversing the frozen B.2 design.

## Decision

**Correct the documentation to match the code (creation-time-only floor
enforcement), and back the *true* defense with a new regression test** — rather
than silently softening the docs. This satisfies the project rule "don't fix
divergence by changing one side silently": the divergence is resolved as a
deliberate documentation fix that also makes the real defense test-backed.

## Changes

1. **`docs/threat-model.md` (the "Brute-force the master password" row, ~line 90)**
   — rewrite to state the truth:
   - Floor (`V1_MIN_MEMORY_KIB = 64 MiB`, iterations ≥ 1, parallelism ≥ 1) is
     enforced **at vault creation** (`create_vault` → `WeakKdfParams`).
   - A tampered `vault.toml` cannot downgrade cost because (a) different params
     yield a different Master KEK → `wrap_pw` AEAD fails (`WrongPasswordOrCorrupt`),
     and (b) the orchestrator `open_vault` cross-checks `vault.toml [kdf]` against
     the signed manifest → `KdfParamsMismatch`.
   - Remove the false "enforced as a typed error … at `open_with_password` time"
     assertion.

2. **`docs/threat-model.md` (test-citation list, ~line 177)** — replace the
   non-existent `core/tests/unlock.rs` open-side citation with the tests that
   exist: create-side `create_vault_rejects_sub_floor_argon2_params`
   (`core/src/unlock/mod.rs`) + `core/tests/create_vault.rs`; the manifest
   cross-check `open_vault_kdf_params_mismatch_rejected`
   (`core/tests/open_vault_neg.rs`); **plus** the new downgrade-refutation test
   from step 4.

3. **`docs/manual/contributors/side-channel-audit-internal.md:299` + `CLAUDE.md`**
   — correct the same repeated claim to creation-time-only enforcement, noting
   the two open-path defenses above.

4. **New regression test** (TDD, RED first) in `core/tests/unlock.rs` — prove the
   refutation at the pure `open_with_password` layer: build a known-good vault,
   downgrade `memory_kib` in its `vault.toml` below the floor, and assert
   `open_with_password` returns `WrongPasswordOrCorrupt` (not a successful weak
   open, not a panic). Test name chosen so `spec_test_name_freshness.py` resolves
   the new doc↔test citation, e.g.
   `open_with_password_downgraded_kdf_params_fails`.

## Out of scope (YAGNI)

- **No open-time floor check** and **no `open_with_password_unchecked` API.**
- **No FFI bridge mapping change** — the bridge's "structurally-unreachable
  `WeakKdfParams`" comment
  ([ffi/secretary-ffi-bridge/src/error/unlock.rs:88](../../../ffi/secretary-ffi-bridge/src/error/unlock.rs#L88))
  stays accurate.
- The docs will note that the floor becomes load-bearing *at open* only if a
  future change-password / re-wrap flow re-derives the KEK from `vault.toml`
  params — capturing the requirement for whoever builds that flow, without
  building it now.

## Test / verify

- `cargo test --release --workspace` — new test green (after RED), full suite
  still green.
- `cargo clippy --release --workspace --tests -- -D warnings` — clean.
- `uv run core/tests/python/spec_test_name_freshness.py` — confirms the new
  doc↔test citations introduce no drift and the phantom citation is gone.
