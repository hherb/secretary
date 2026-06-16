# D.4.2 — Per-fill open (implementation plan)

**Date:** 2026-06-16
**Status:** Plan (pending implementation)
**Sub-project:** D.4 (browser autofill), second slice
**Design:** [2026-06-15-d4-browser-autofill-design.md](2026-06-15-d4-browser-autofill-design.md) §4
**Builds on:** [D.4.1 skeleton](2026-06-16-d41-native-messaging-skeleton-plan.md) (the proven channel)
**Scope:** attach the **first crypto** to the D.4.1 channel. On a `query`, the host opens the
**casual** vault per fill via the existing `open_with_device_secret` (B.2 / ADR 0009)
verify-before-decrypt path, counts candidate records, and replies `available { count }`.
**Still no secrets cross the channel** — the reply is a count, nothing more. Real origin
matching (PSL, bindings, iframe rules) is D.4.3; credential injection is D.4.4.

## 1. Resolved scoping decisions (2026-06-16)

Two decisions shape this slice (the rest follow the design):

1. **Device secret source → a port + a dev provider now; real OS keystore deferred.** D.4.2
   defines a `DeviceSecretSource` trait (the port) and ships **one CI-testable provider** that
   reads the 32-byte secret from a helper-local file. Real macOS Keychain / Linux Secret Service
   adapters land behind the same port in a follow-up (they are platform-specific and not
   CI-gatable in this Linux container). This mirrors the iOS B.3 pure-core-port / real-adapter
   split (CLAUDE.md "iOS device unlock").
2. **Enrollment → host consume-side + a dev enroll tool; desktop Tauri UI deferred.** D.4.2
   builds the host's open+count path plus a small CI-testable enrollment binary that calls the
   existing `add_device_slot`, writes the helper config, and stashes the secret for the dev
   provider. The native-app (Tauri) enrollment UI is a later slice (and can't be built in this
   GTK-less container anyway).

Decisions taken without asking (defensible defaults):

3. **Dependency → `secretary-core` directly** (not the FFI bridge). The host is a Rust binary,
   not a foreign-language binding; core gives `open_vault` + `Unlocker::DeviceSecret` +
   `device_slot::add_device_slot` without pulling the bridge's `secretary-cli` sync machinery.
   The open still goes through the **identical** `open_vault` verify-before-decrypt path the
   bridge's `open_with_device_secret` wraps — invariant 7 holds.
4. **Candidate count → `OpenVault.manifest.blocks.len()`** (live, authenticated block entries).
   No origin filtering yet — D.4.2 returns the casual vault's candidate count for any query;
   D.4.3 replaces this with real per-record origin matching. Counting blocks needs no further
   block decryption.
5. **Helper-local config → JSON** at `$SECRETARY_BROWSER_HOST_CONFIG` (override, for tests) or
   `dirs::config_dir()/secretary/browser-host.json`. Reuses the existing `serde_json` dep.

## 2. Security invariants this slice must hold (design §12)

- **Invariant 1/2** — the host opens **only** the casual vault (the one whose path + device slot
  the config names); the high-value vault is simply never enrolled. The host holds **no key
  material between fills**: the `Context` holds the *source*, not the secret. Per query it fetches
  the secret, opens, counts, and drops — the fetched bytes are zeroized immediately after the
  `open_vault` call (the `Sensitive`/`SecretBytes` discipline from CLAUDE.md "zeroize discipline").
- **Invariant 7** — the per-fill open is `open_vault(Unlocker::DeviceSecret{..})`, the same
  manifest verify-before-decrypt as password/recovery/device. No parallel or weaker open.
- **Invariant 6 (forward)** — no secrets cross the channel: the reply gains a real `count`,
  nothing else. Credentials wait for D.4.4's native-confirmation gate.
- **Structural (D.4.1)** — no listening socket; manifest-bound extension ID; framing never
  panics and caps at 1 MiB. `#![forbid(unsafe_code)]` + clippy `-D warnings` stay clean across
  the now-`secretary-core`-linked host.
- **Dev-provider caveat (loud).** The dev file secret source stores a device secret in a file
  in cleartext. It is a **development-only** provider, gated/named so it can never be mistaken
  for the production keystore path. Documented in code and READMEs.

## 3. Layout (additions to D.4.1)

```
browser/secretary-browser-host/
  Cargo.toml                       + secretary-core (path), + dirs; (serde/serde_json already present)
  src/lib.rs                       run() takes a Context { config, secret_source }; query → open+count
  src/protocol.rs                  UNCHANGED (Outbound::Available already carries `count`)
  src/frame.rs                     UNCHANGED
  src/config.rs                    HostConfig { vault_path, device_uuid, secret_source } + load/locate
  src/secret_source.rs             DeviceSecretSource trait + DevFileSecretSource (+ a test fake)
  src/vault.rs                     per_fill_count(): open_vault(DeviceSecret) → manifest.blocks.len()
  src/main.rs                      build Context from config, run loop (graceful no-config → count:0)
  src/bin/enroll.rs                dev enroll tool: add_device_slot → write config + stash secret
  tests/per_fill_open.rs           open+count over a temp golden vault enrolled with a device slot
```

## 4. Task breakdown

| Task | Deliverable | Test gate |
|---|---|---|
| **1** | Add `secretary-core` + `dirs` deps. `secret_source.rs`: `DeviceSecretSource` trait + `DevFileSecretSource` (hex file, 0600, loud dev-only docs) + a test fake. `config.rs`: `HostConfig` (vault path, device_uuid hex, secret-source descriptor) + env-override/default locate + load. | Unit: config round-trip + locate precedence; dev provider read/zeroize; missing file → typed error. |
| **2** | `vault.rs::per_fill_count(config, secret_source)`: fetch secret → `open_vault(Unlocker::DeviceSecret{..})` → `manifest.blocks.len()`; zeroize the fetched secret; map `VaultError` → a typed host error. | Integration (`tests/per_fill_open.rs`): enroll a slot on a temp golden vault via core `add_device_slot`, stash secret in a dev file, assert `per_fill_count` == known block count; wrong secret → typed error; absent slot → typed error. |
| **3** | `run()`/`Context`: `query` → `per_fill_count` → `available{count}`. No config / not enrolled / secret unavailable → `available{count:0}` (graceful: an un-enrolled browser shows no affordance, never crashes). Open failure on a *configured* vault → `error` frame. | `tests/echo.rs` extension: configured Context → `available{count:N}`; absent config → `available{count:0}`; corrupt/unopenable configured vault → `error`. |
| **4** | `src/bin/enroll.rs` dev tool: read vault path + master password (prompt/stdin), `add_device_slot`, write `HostConfig`, stash the secret via `DevFileSecretSource`. Loud dev-only banner. | Integration: run enroll against a temp golden vault → config + secret file written → `per_fill_count` opens and counts. (Drives the same APIs as task 2; CI-gated.) |
| **5** | Docs: `browser/README.md` + `host-manifest/README.md` gain the enrollment + per-fill-open dev flow and the dev-provider caveat. Workspace gates green. | `cargo test -p secretary-browser-host`; `cargo clippy --release --workspace --exclude secretary-desktop --tests -- -D warnings`; `#![forbid(unsafe_code)]` holds. |
| **6** | `docs/handoffs/2026-..-d42-shipped.md` + repoint `NEXTSESSION_BROWSER_PLUGIN.md` → D.4.3. | Docs reviewed; handoff lists what D.4.3 picks up. |

Tasks 1–4 are CI-gated in Rust (a temp copy of `golden_vault_001` + an enrolled slot — no
browser, no network). The browser round trip stays the documented manual smoke from D.4.1.

## 5. Testing strategy

- **Crypto reuse, not re-implementation.** Tests enroll a real device slot on a temp copy of
  `core/tests/data/golden_vault_001` via `secretary_core::vault::device_slot::add_device_slot`,
  then open via `open_vault(DeviceSecret)` — exercising the genuine ADR 0009 path. No fixture
  crypto is hand-rolled.
- **Zeroize asserted by construction.** The fetched secret lives in a `SecretBytes` and is
  dropped immediately after the open; the `Context` never stores it. (Reviewed at the call site,
  per CLAUDE.md "security-critical code reviews must prove enforcement.")
- **No-secrets-cross holds trivially** — the only new wire content is an integer `count`.
- **CodeQL discipline** — test secrets (device secret, password) derive from runtime file reads
  (the golden inputs fixture / `OsRng` via `add_device_slot`), never hard-coded literals
  (CLAUDE.md `feedback_test_crypto_random_not_hardcoded`).

## 6. Definition of Done

1. `cargo test -p secretary-browser-host` (incl. the new open+count + enroll integration tests)
   and `cargo clippy --release --workspace --exclude secretary-desktop --tests -- -D warnings`
   are green; `#![forbid(unsafe_code)]` holds. (Desktop excluded only for the container's missing
   GTK; the ffi-bridge read-only-folder test still fails only under the root container — both are
   the pre-existing D.4.1 environment caveats, not regressions.)
2. A `query` against an enrolled casual vault returns `available{count: N}` where N is the live
   block count, proven over a temp golden vault in `tests/`.
3. The open uses `open_vault(Unlocker::DeviceSecret{..})` — the same verify-before-decrypt as
   every other path (invariant 7).
4. The host holds no key material between fills; the fetched secret is zeroized after each open
   (invariant 1).
5. No secrets cross the channel — the reply is a count (invariant 6, forward).
6. The high-value vault is never opened — the host opens only the configured casual vault
   (invariant 2).
7. Structural D.4.1 invariants still hold (no socket, manifest-bound ID, never-panic framing).

## 7. What D.4.3 picks up

A host that opens the casual vault per fill and returns a candidate count. D.4.3 replaces the
trivial "all live blocks" count with the **real origin-matching engine** — PSL (eTLD+1) /
`exact_origin`, top-frame-governs, cross-origin-iframe refusal, HTTPS-only, IDN de-confusion —
gated by the pinned `origin_match_kat.json` corpus (design §5, the security-critical slice),
still returning only a count with injection deferred to D.4.4. The real OS-keystore providers
(behind the D.4.2 `DeviceSecretSource` port) and the desktop enrollment UI are the other
deferred follow-ups.

## 8. Related

- D.4 design §4 (per-fill open & enrollment), §12 (security invariants).
- ADR 0009 — per-device wrap slot (the enrollment foundation).
- ADR 0010 — browser autofill via native messaging.
- B.2 `open_with_device_secret` (`core/src/vault/orchestrators.rs::open_vault`,
  `ffi/secretary-ffi-bridge/src/device.rs`) — the path reused, not reimplemented.
