# Full security audit — Secretary (pre-release, second pass)

- **Date:** 2026-09-03
- **Scope:** Whole repository — Rust cryptographic core, vault/merge layer, sync orchestration + CLI daemon, FFI surface (bridge + PyO3 + uniffi), Tauri desktop client, browser-autofill track (native-messaging host + extension), native iOS/Android clients (partial — see §1.2), supply chain / CI / repo hygiene.
- **Method:** Seven independent domain auditors (crypto, vault, sync/CLI, FFI, desktop, browser, supply chain) plus one lead, each reading every production file in scope against the normative specs (`docs/crypto-design.md`, `docs/vault-format.md`, `docs/threat-model.md`) and the contributor memos, and **verifying every substantive claim by execution** with throwaway probes (since deleted). The lead independently re-verified each Critical/High finding, then **fixed** everything with a contained, testable fix in this same change set (§3), and documented the rest with a concrete recommendation (§4). The mobile auditor was interrupted by an API quota before writing its report; the lead re-verified the prior audit's only live-exploit mobile finding (A-1) by hand.
- **Baseline:** `main` at `1929711` (the tree immediately after PR #599). Previous audit: [`2026-07-02-full-audit.md`](2026-07-02-full-audit.md).

> Line references were accurate at audit time; treat the surrounding symbol names as the durable anchor.

---

## 1. Executive summary

**One Critical and four High findings, all confirmed by execution, all fixed in this change set.** The most serious defeats the vault's core authenticity guarantee from the primary adversary's position:

- **VL-1 / FF-1 / CR-1 (Critical, fixed).** The owner's identity public keys were trusted from `contacts/<owner-uuid>.card` — a file the hostile cloud-folder host can rewrite — and never cross-checked against the AEAD-authenticated Identity Bundle. Because the manifest's `author_fingerprint` and both signature halves sit outside the AEAD AAD *and* the signed range, the host can substitute a self-signed card carrying the victim's `contact_uuid` but its own keys and re-sign the unchanged ciphertext. `open_vault` accepted it on all three unlock paths; the substituted card then became the owner's KEM recipient identity, so every block the victim wrote afterwards was wrapped to the attacker's keys. Three auditors reproduced plaintext recovery independently. Fixed at the single chokepoint (`read_and_verify_manifest`) with a four-key equality check against the bundle, a typed error, a regression test, and a normative spec sentence; the spec had in fact always said the owner keys come from the bundle — the code had diverged.
- **VL-2 (High, fixed).** Block fingerprints were checked only at open; `share_block`/`revoke_block_recipient` and the bridge read/edit path re-read `blocks/<uuid>` with no binding to the manifest, so a post-open rollback to an older owner-signed version was accepted and *laundered* into a freshly signed manifest by any re-key or edit. Fixed with one verified-read choke-point in core and the same check in the bridge; regression test proves a rolled-back file is refused, not re-signed.
- **DT-1 (High, fixed).** The Tauri webview had no navigation restriction, so a compromised renderer could reveal everything and `location.href` it to an attacker origin, bypassing every IPC gate. Fixed with an `on_navigation` guard pinned to the app origin plus `form-action`/`base-uri`/`object-src`/`frame-src` CSP directives.
- **BR-1 (High, fixed).** The browser host's only device-secret source read the secret from a *cleartext file* and was compiled into every release build. It is now behind a default-off cargo feature (tests enable it via a self dev-dependency); a release host fails closed as not-enrollable.
- **VL-3 / FF-2 (High, OPEN — needs a product decision).** `contacts/` in the hostile folder is the sole trust root for *recipient* identity: the bridge enumerates every self-signed card found there and loads recipient keys from there at share time, so a substituted or planted contact card silently redirects a share to the attacker. The correct fix (pinning each imported contact's fingerprint in authenticated, host-unwritable state) changes the cross-device contact model and the FFI API; it is specified in §4.1 rather than half-implemented here.

Also fixed: the release-asset leak of the golden vault's password/mnemonic/secret keys into shippable Android/iOS/macOS builds (SC-2), unconcealed clipboard copies of secrets and the recovery mnemonic (DT-2), the origin matcher treating two IPv4 literals or unknown-TLD siblings as one site (BR-2/BR-4), and nine Low/Info items (§3).

### Severity tally (unique findings, de-duplicated across auditors)

| Severity | Found | Fixed here | Open |
|---|---|---|---|
| Critical | 1 | 1 | 0 |
| High | 4 | 3 | 1 (VL-3/FF-2) |
| Medium | 9 | 3 | 6 |
| Low | 26 | 8 | 18 |
| Info | ~25 | 1 | documented |

### 1.1 What held (verified clean by execution)

The invariants the design depends on all hold: hybrid signatures are enforced as **AND** at the single primitive and every call site; hybrid KEM decapsulation runs both halves with one AEAD oracle and full transcript binding; nonces are `OsRng` everywhere; verify-before-decrypt ordering holds on all three unlock paths (the VL-1 flaw was *which key* was trusted, not the order); the manifest re-encode canonicality check, the four uniqueness scans, the repair gates (#350), the CRDT proptests, atomic writes (`tempfile =3.27.0`), the memory-hygiene wrapper discipline, the error-payload hygiene guards, the Android path-traversal guard (A-1: segment scan **and** canonical-path containment; SAF `findFile` cannot traverse parents), the Keystore/Secure-Enclave posture, and the six repo hygiene guards (all pass, including self-tests). All six prior crypto findings (C-1..C-6/I-1), D-2, D-3, A-1, S-2, S-3, S-4, S-7, F-2, F-3, F-4 and V-1/V-2/V-3/V-F4 are fixed.

### 1.2 Coverage limits

- **Mobile (iOS/Android):** the domain auditor was terminated by an API quota mid-run and wrote no report. The lead re-verified A-1 (fixed, complete) and the app-side fixture provisioning (SC-2, now debug-gated). A-2 and iOS-1..iOS-6 from the July audit were **not** re-verified this pass; treat them as still open until checked.
- **Root-only test artifacts:** three tests inject write failures by `chmod 0o555` and fail when run as root (root bypasses mode bits): `core/tests/trash_restore.rs::{trash_block_rename_failure_still_commits_manifest, trash_block_manifest_write_failure_leaves_state_untouched}` and `ffi/secretary-ffi-bridge/tests/save_block.rs::save_block_failure_leaves_in_memory_manifest_unchanged`. They fail identically on the untouched baseline and pass under non-root CI; nothing in this change touches their paths.
- Xcode/Android SDK were unavailable; iOS/macOS/Gradle changes were verified by reading only.

---

## 2. Findings by domain

IDs are the auditors' (CR crypto, VL vault, SY sync/CLI, FF FFI, DT desktop, BR browser, SC supply chain). **Fixed** items are detailed in §3; **Open** items carry their recommendation in §4.

### 2.1 Cryptographic core (`core/src/{crypto,unlock,identity}`)

- **CR-1 [Critical] — Fixed.** Owner public keys trusted from the folder, not the bundle (same root cause as VL-1/FF-1; independently reproduced: the attacker decapsulated a real `save_block` and a forged "owner-authored" block verified for the victim).
- **CR-2 [Low] — Open.** `Argon2idParams::try_new_v1` (the nominated KDF-floor choke-point) has zero production callers; `create_vault`'s floor is an ad-hoc scalar check. Not exploitable today (AEAD + signed-manifest cross-check compensate); a future change-password/re-wrap flow must route through it.
- **CR-3 [Info] — Fixed.** `bundle_file::decode` computed `pos + total` unchecked; on a 32-bit `usize` a hostile `bundle_ct_len` wraps the bounds check into a slice panic. Now `checked_add`.
- **CR-4 [Info] — Open (for the external reviewer).** `ml-kem 0.2.3` performs no FIPS 203 encapsulation-key modulus check; not exploitable given the hybrid HKDF binding, single AEAD oracle and OOB card import.
- Verified clean: AND-verify at `sig::verify` and all four call sites; KEM both-halves + transcript binding; AEAD nonce sourcing and AAD; KDF domain tags; bundle/device-file header parsing; mnemonic handling carries no phrase content in any error; all July findings C-1..C-6/I-1 fixed; the memory-hygiene refactor did not regress the AND-verify, single-oracle, nonce or zeroize invariants.

### 2.2 Vault layer (`core/src/vault`, `core/src/cbor`)

- **VL-1 [Critical] — Fixed.** See §1 and §3.1.
- **VL-2 [High] — Fixed.** Post-open block rollback laundered by re-key/edit. §3.2.
- **VL-3 [High] — Open.** `contacts/` is the sole recipient trust root (probe through the real bridge API: host swaps Bob's card / plants "Carol" → both listed → `share_block_to(bob)` wraps only to the attacker → attacker decrypts). §4.1.
- **VL-4 [Low] — Open.** `open_vault` runs the folder-mutating trash sweeps before the bridge's §10 rollback check; a rolled-back manifest can relocate a live block and wedge the vault (availability only).
- **VL-5 [Low] — Open.** No symlink/size/regular-file guard on any vault read (a planted symlink to `/dev/zero` hangs the open; DoS only — writes never dereference).
- **VL-6 [Low] — Fixed.** `conflict.rs::value_lex_bytes` copied decrypted field values into un-wiped `Vec<u8>`s on every LWW tie; now compares in place through the zeroize-typed wrappers.
- **VL-7/8/9 [Info] — Open.** `OpenVault`'s `Debug` prints decrypted block names; re-key readers do not bind `header.vault_uuid`/`block_uuid` (now transitively bound by the VL-2 fingerprint check); unlisted `blocks/*` files are never surfaced (V-6 restated).
- Prior audit: V-1, V-2 fixed (repair #350 genuinely closes them and its gates held against every hostile residue tried); V-3 fixed for app-facing opens (residual: the check runs after the sweeps — VL-4); V-F4 documented; V-5 partially fixed and subsumed by VL-3; V-6 open (Info).

### 2.3 Sync orchestration and CLI (`core/src/sync`, `cli/`)

- **SY-1 [Medium] — Open.** The `highest_vector_clock_seen` rollback baseline is an unauthenticated plaintext CBOR file, fail-open on absence, not the OS keystore crypto-design §10 mandates; if the state dir is itself cloud-synced, the host can roll back vault + baseline together, or delete the baseline to disable detection (verified). §4.3.
- **SY-2 [Low] — Open.** Vault files are read whole before any size/type check; a planted FIFO wedges the single-threaded daemon (DoS).
- **SY-3 [Low] — Open.** Attacker-chosen conflict-copy filenames are logged verbatim at `-vv` (terminal-escape injection).
- **SY-4 [Low] — Open.** One planted owner-signed orphan block sibling makes `prepare_merge` hard-error on every sync (targeted wedge).
- **SY-5/6 [Info].** Sync commit re-encrypts merged shared blocks to owner-only (fail-safe; v1 sync is single-owner); CLI derives state identity from cleartext `vault.toml` (fails closed via `VaultUuidMismatch`).
- Verified clean: conflict copies are authenticated against the owner identity before any byte influences state; no exfiltration, signing-oracle or resurrection primitive; commit atomicity and TOCTOU freshness; password sourced from stdin/TTY only (never argv/env); secrets zeroized on graceful shutdown; no secrets in logs or filenames; #494 carries no secret. Note that SY-1's "owner identity" was the on-disk card until VL-1 was fixed — the same fix closes the sync-side variant.

### 2.4 FFI surface (`ffi/secretary-ffi-{bridge,py,uniffi}`)

- **FF-1 [High] — Fixed** (= VL-1; probe recovered `"hunter2-leak"` through the bridge).
- **FF-2 [High] — Open** (= VL-3).
- **FF-3 [Medium] — Open.** No contact fingerprint (`fingerprint`/`mnemonic_form`) is projected through the bridge, UDL or PyO3 (`ContactSummary` = uuid + name + count), so the OOB verification the threat model delegates to the UI is unimplementable on mobile.
- **FF-4 [Medium] — Open.** Mutating orchestrators snapshot → core → write back without a per-handle write lock; concurrent writes on one `OpenVaultManifest` lose updates and orphan block files (probe: 8/8 "Ok", 7 blocks lost). §4.4.
- **FF-5 [Low] — Fixed.** `auto_purge_expired`/`expired_trash_entries` accepted any `window_ms`; the one-day retention floor was bypassable outside the settings path. Now clamped at the trust boundary.
- **FF-6 [Low] — Fixed.** `Sensitive::new(*x.expose())` temporaries of the IBK / Ed25519 / X25519 keys left un-wiped stack copies; now the named-copy trailing-wipe form.
- **FF-7/8 [Info] — Open.** Raw `revoke_block` skips `verify_self` (not exploitable — wire-table fingerprint match); peer-controlled `display_name` reaches all UIs unfiltered.
- Prior audit: F-2, F-3, F-4, I-1 fixed. Verified clean: validation parity in both bindings, wiped-handle write paths, error-payload hygiene, repair consent/rollback gate, settings, sync surface, build hooks; `check-test-support-placement.py` and `check-lean-binding.sh` pass.

### 2.5 Desktop client (`desktop/`)

- **DT-1 [High] — Fixed.** No navigation restriction; CSP lacked `form-action`. §3.3.
- **DT-2 [Medium] — Fixed.** Secret and recovery-mnemonic copies went through the plugin's plain `set_text` (no concealment flags; recorded by Windows Clipboard History / Cloud Clipboard and macOS managers), and the webview held a general clipboard-write capability. §3.5.
- **DT-3 [Low] — Open.** No failure counter/backoff on `unlock_with_password`/`preview_repair`/`repair_vault`/`verify_password`; `use_recent_vault` re-approves the last vault without a gesture, so a locked app is an online password oracle (bounded by Argon2id at 256 MiB/guess).
- **DT-4 [Low] — Fixed.** `create_vault_impl` accepted an empty master password (only the UI refused it).
- **DT-5 [Low] — Open.** `core:default` over-grants (`event:emit`, menu/tray, path resolution, devtools toggle, `image:from-path`); can be narrowed to `event:allow-listen/unlisten`.
- **DT-6..9 [Info] — Open.** Remaining CSP gaps (`worker-src`; `style-src 'unsafe-inline'` = D-4); auto-lock is wall-clock and webview-driven (`notify_activity` is an unbounded keep-alive); `authenticate_presence(reason)` lets the page choose the Touch ID prompt text; plaintext lifetime in the webview exceeds the 20 s re-mask (editor shows every field unmasked).
- Prior audit: D-1 still open by design (verified: no Rust write, settings change or presence-pref write is gated; the Touch ID result is advisory); D-2 fixed (no bypass found for `..`, symlink escape, prefix-sibling, trailing `/`, `.`); D-3 fixed (frontend-only); D-4 open (Info). The presence crate's six `unsafe` blocks are memory-safe and fail-safe. 48 → 50 commands, all classified.

### 2.6 Browser-autofill track (`browser/`)

- **BR-1 [High] — Fixed.** `DevFileSecretSource` (cleartext secret file) was the only source and compiled into every release build; enroll wrote the casual vault's device secret as hex into `~/.config`. §3.4.
- **BR-2 [Medium] — Fixed.** `registrable_domain` never checked `psl::Suffix::is_known()`: `1.2.3.4` and `5.6.3.4` were "the same site" under `registrable_domain` (rule 3 *and* the cross-origin-iframe rule 2 collapsed for IP literals); the KAT's IPv4 vector passed vacuously.
- **BR-3 [Medium] — Open (latent, must land before D.4.4).** Page origins are self-reported by the content script (`frame_origin = top_origin = window.location.origin`) and `background.ts` ignores `sender.*`; cross-origin-iframe refusal currently rests on `all_frames` being unset. §4.5.
- **BR-4 [Low] — Fixed.** Unknown TLDs (`.internal/.local/.corp/…`) collapsed to a two-label "site" — same root cause as BR-2, same fix, pinned by KAT.
- **BR-5 [Low] — Open.** A character of a malformed secret file is echoed across the channel (`hex` error `Display`); host error types carry `String` payloads outside every hygiene guard.
- **BR-6 [Low] — Fixed.** Secret file written at umask permissions then chmod'ed (window + symlink-follow); now created `0o600` at `open(2)`.
- **BR-7 [Low] — Open.** The hex-secret `String` is never wiped; transient wipes are elidable loops (core re-exports `Zeroize`).
- **BR-8 [Low] — Fixed.** `install-dev.sh` warned-only on a bad `--ext-id`; a crafted id injected a second `allowed_origins` entry (verified by dry-run). Now fatal.
- **BR-9 [Low] — Open.** Every enroll mints a new device slot and never revokes the old one.
- **BR-10..19 [Info] — Open.** Mixed-script flag false positives/negatives; error frames echo attacker JSON values; stderr path disclosure; extension tests not in CI; process-scoped `request_id`; the host ignores Chromium's argv caller origin; non-PSL shared hosts (`sharepoint.com`, `github.dev`) cross-fill; host-normalisation notes; stored scheme/port ignored under `registrable_domain`; `SECRETARY_VAULT_PASSWORD` env/echo in the dev tool. The auditor's list of 13 invariants the shipped code relies on but does not enforce is reproduced in §4.5 for the injection slice.

### 2.7 Supply chain, CI, repo hygiene

- **SC-1 [Medium] — Open.** The accepted HIGH quick-xml advisories (RUSTSEC-2026-0194/0195) are now clearable: `wayland-scanner 0.31.11` is on `quick-xml ^0.41` and `cargo update -p plist -p wayland-scanner` resolves to a single `quick-xml 0.41.0`; `.cargo/audit.toml`'s "verified 2026-07-06" rationale is stale. Deliberately not bumped inside an audit change set — do it as its own reviewed PR and drop the two ignore entries.
- **SC-2 [Medium] — Fixed.** Release-configuration builds bundled the public golden vault, its password, 24-word mnemonic, secret keys and device-slot secret, and the apps self-provisioned it. §3.6.
- **SC-3 [Medium] — Open.** No release workflow, signing, notarization, SBOM, provenance or `SECURITY.md`; zero GitHub releases; Android release unsigned; macOS hardened runtime off. §4.6.
- **SC-4 [Low] — Fixed.** No `--locked` on any CI `cargo` invocation; drift was silently re-resolved, diverging from what `cargo audit` scanned. Added to build/test/clippy/doc.
- **SC-5/6/7 [Low] — Open.** Guard bypass classes with zero live producers: secret-slot guard blind to `Box::leak`/`Box::into_raw`/`Vec::leak`/`Rc::into_raw`; Android logcat guard blind to `print(e)` / `java.util.logging`; iOS log guard blind to legacy `os_log("%{public}@")`/`NSLog`. Each needs a LIMITS entry and, where cheap, a rule.
- **SC-8 [Low] — Open.** Placement guard blind to a `build.rs` `cargo:rustc-cfg=feature="test-support"` (PoC compiled and ran the hatch with no manifest change).
- **SC-9 [Low] — Open.** `cargo audit --deny warnings` exits 0 when the yanked check errors (178 registry 503s → EXIT=0).
- **SC-10 [Low] — Open.** Gradle wrapper JAR run in CI without wrapper-validation; no Maven dependency verification.
- **SC-11 [Low] — Open.** `spec_test_name_freshness.py` fails (90 unresolved, #574) and is not in CI; `browser/extension` has no CI job.
- **SC-12..15 [Info] — Open.** `Swatinem/rust-cache` pinned to an untagged commit; `cargo install cargo-audit` unpinned; no pnpm `packageManager` hash; `brew install xcodegen`; `audit.yml` path filter vs required-check semantics (unverifiable); `core/fuzz/Cargo.lock` never audited (clean today); 12 dev-tooling npm advisories (`--prod` clean); `.cargo/config.toml` source replacement undenied.
- Prior audit: S-2, S-3, S-4, S-7 fixed; S-1, S-6 partial; S-5 informational. All 9 action SHA pins resolve; no committed secrets; all 801 lock entries are crates.io.

---

## 3. Fixes in this change set

Every fix below compiles under `-D warnings`, passes `cargo test --release --locked --workspace` (except the three root-only artifacts in §1.2), `RUSTDOCFLAGS="-D warnings" cargo doc`, all six hygiene guards with their self-tests, and the desktop frontend gates (786/786 tests, `svelte-check` 0 errors, `eslint` clean).

### 3.1 VL-1 / FF-1 / CR-1 — bind the owner card to the Identity Bundle

- `core/src/vault/mod.rs`: new `VaultError::OwnerCardKeyMismatch`.
- `core/src/vault/orchestrators.rs::read_and_verify_manifest`: after the `contact_uuid` check and **before** the manifest signature is verified, require `x25519_pk`, `ml_kem_768_pk`, `ed25519_pk`, `ml_dsa_65_pk` of the on-disk card to equal the bundle's. The bundle is decrypted under the caller's credential and is the only owner-key material the host cannot forge; an attacker card either carries different keys (rejected here) or copies the real public keys and then cannot self-sign (rejected by `verify_self`). Public keys, so no constant-time compare is needed. All three `Unlocker` arms, `read_vault_manifest(_full)`, `repair_vault`/`preview_repair` and the sync ingest path funnel through this helper, so the fix covers the sync-side variant too.
- `ffi/secretary-ffi-bridge`: the variant is routed explicitly (no catch-all) in the central `From<VaultError>` fold (→ `CorruptVault`) and the eight exhaustive orchestration matches.
- `docs/vault-format.md` §4.3 step 7: normative sentence pinning the cross-check (the step already said "use the Identity Bundle's pubkeys").
- Regression: `core/tests/open_vault_neg.rs::open_vault_substituted_owner_card_key_mismatch_rejected` — forges the attacker card + re-signed envelope exactly as the probe did and asserts `OwnerCardKeyMismatch`.

### 3.2 VL-2 — verified block reads after open

- `core/src/vault/orchestrators.rs::read_verified_block_file(folder, &BlockEntry, ctx)`: reads the file, requires `blake3(bytes) == entry.fingerprint` (`BlockFingerprintMismatch`), then decodes. The fingerprint covers the whole file, so `header.block_uuid`/`vault_uuid` are transitively bound (VL-8). `share_block` and `revoke_block_recipient` now use it instead of a bare `fs::read`.
- `ffi/secretary-ffi-bridge/src/record/orchestration.rs::decrypt_block_plaintext`: the same fingerprint check against the snapshot's `BlockEntry` before decrypt — this path feeds `read_block` **and** every edit primitive (`edit/*`, `move_record`, `rename`, `tombstone`), so an edit can no longer re-commit rolled-back content.
- Regression: `core/tests/share_block.rs::share_block_rejects_post_open_block_rollback` — saves v1 then v2, rolls the file back to v1, asserts `share_block` returns `BlockFingerprintMismatch`, that reopen still detects the rollback (nothing laundered), and that restoring v2 reopens.

### 3.3 DT-1 — navigation guard + CSP

- `desktop/src-tauri/src/main.rs`: a `tauri::plugin::Builder::on_navigation` guard (`navigation_guard_plugin`) registered first; `is_app_origin` allows only `tauri:` and `tauri.localhost` (plus `localhost:1420` under `debug_assertions`); `https:`, `file:`, `data:`, `javascript:`, `blob:` and every remote host are refused.
- `desktop/src-tauri/tauri.conf.json`: CSP gains `form-action 'none'; base-uri 'none'; object-src 'none'; frame-src 'none'`.

### 3.4 BR-1 / BR-2 / BR-4 / BR-6 / BR-8 — browser host

- `Cargo.toml`: `dev-secret-source` feature (default off), self dev-dependency enabling it for tests, `required-features` on the `secretary-browser-enroll` bin. `secret_source.rs`: `DevFileSecretSource` + its tests `#[cfg(feature = …)]`. `config.rs`: `build_secret_source` → `Result`, new `ConfigError::SecretSourceUnavailable`; `lib.rs`: `enroll` module gated, `from_default_config` propagates. Verified: `cargo build --release` links no dev-source code (the "no dev secret file" string is absent from the binary) and produces no enroll binary; tests and clippy pass with the feature both on and off.
- `origin_match.rs::registrable_domain`: gated on `psl::suffix(host).is_known()`. KAT +4 vectors (28): two IPv4 literals sharing trailing octets refuse under `registrable_domain` (rule 3 and rule 2), unknown-TLD siblings refuse, same exact host still fills.
- `enroll.rs::write_secret_file`: `OpenOptions::mode(0o600)` at create; `install-dev.sh`: non-`[a-p]{32}` ids are fatal.

### 3.5 DT-2 — concealed clipboard

- `desktop/src-tauri/src/commands/clipboard.rs`: `copy_secret_text` / `clear_clipboard` use `arboard` directly with `SetExtWindows::{exclude_from_history, exclude_from_monitoring}` and `SetExtApple::exclude_from_history`, zeroizing the argument; registered in `main.rs`; direct `arboard` dep (already in the lock via the plugin; unified).
- `capabilities/default.json`: `clipboard-manager:allow-write-text` revoked — the webview can no longer write (nor ever read) the clipboard; the plugin stays registered but is inert.
- `desktop/src/lib/ipc.ts` (`copySecretText`, `clearClipboard`), `FieldRow.svelte`, `create/MnemonicStep.svelte` switched; `writeCommands.ts` classifies the two commands; tests updated to the `invoke` seam (`FieldRow.test.ts`, `MnemonicStep.test.ts`; stale plugin mocks removed from `CreateVault.test.ts`, `FieldViewer.test.ts`).

### 3.6 SC-2 — no fixture secrets in release builds

- `android/app/build.gradle.kts`: staging moved to `src/debug/assets` and wired to `mergeDebugAssets` only; `mergeReleaseAssets` now fails the build if the fixture or its inputs JSON exist in a source set it consumes. `android/.gitignore` covers the new path. (A release APK is thus fail-closed at runtime by the existing asset check until a real vault picker lands — the skeleton app is not shippable either way, see SC-3.)
- `ios/scripts/build-app.sh`, `build-macos-app.sh`: refuse to stage fixtures when `CONFIGURATION=Release`. `AppVaultProvisioning.swift`, `MacVaultProvisioning.swift`: `#if !DEBUG` throws before any fixture is touched.

### 3.7 Smaller fixes

- **DT-4** `commands/create.rs`: empty master password → `InvalidArgument` in the trust boundary.
- **FF-5** `retention/orchestration.rs`: `window_ms` clamped to `RETENTION_WINDOW_MIN_MS` in both entry points (bridge test rescaled to days; a sub-floor window is asserted to be clamped).
- **FF-6** `vault/manifest.rs`, `identity.rs`: named-copy + `zeroize()` for the three `Copy` key temporaries.
- **VL-6** `conflict.rs`: `value_lex_cmp` compares through the wrappers; ordering identical to the old prefixed encoding.
- **CR-3** `unlock/bundle_file.rs`: `checked_add` on `pos + total`.
- **SC-4** `.github/workflows/{test,rust-lint}.yml`: `--locked` on `cargo build/test/clippy/doc`.
- **CLAUDE.md**: three new invariant bullets (owner-card binding, verified block reads, dev secret source gating).

---

## 4. Open findings — recommendations

### 4.1 VL-3 / FF-2 (High) — pin imported contact fingerprints in host-unwritable state

`contacts/<uuid>.card` is the only place a recipient's public keys live, and the host writes it. `import_contact_card`'s `ContactAlreadyExists` guard protects only the API; `enumerate_contact_cards` auto-discovers every self-signed card in the synced folder (contradicting threat-model §3.4 and vault-format §5), and `share_block_to` re-reads the card at share time. Two sound designs, both needing a product decision first:

1. **Per-device TOFU pins (matches the threat model's "import is an explicit act").** Persist `(contact_uuid → 16-byte card fingerprint)` in the OS-local state dir at import; `load_card_bytes`, `enumerate_contact_cards` and core's `resolve_recipient_uuids`/`rewrite_block_with_recipients` require `fingerprint(card) == pinned`, treating an unpinned or mismatching card as `ContactCardSubstituted` and never listing it. Consequence: a contact imported on device A must be re-imported (re-verified OOB) on device B — the semantics §3.4 already describes.
2. **Authenticated pins in the manifest.** A `contacts: [{contact_uuid, fingerprint}]` extension in the manifest's forward-compat `unknown` bag (no on-disk format change; v1 readers round-trip it). Cross-device, but every import becomes a manifest write and the extension must be specified for the clean-room verifier.

Either way, **FF-3** (project `fingerprint`/`mnemonic_form` through the bridge/UDL/PyO3) is a prerequisite for the UI to show what is being pinned, and the share dialog should display the recipient fingerprint. Until then, a user who imports a card from a channel the host can influence, or who does not re-compare the fingerprint OOB before every share, can be redirected to an attacker.

### 4.2 BR-3 and the injection slice (D.4.4)

Derive `top_origin` in the background service worker from `sender.tab`/`sender.frameId === 0` (or `chrome.webNavigation`), never from the content script; refuse when `sender.origin` disagrees with the claimed `frame_origin`. The 13 invariants the shipped host relies on but does not enforce (casual-vault-only enrollment, honest origins, page-accurate count, the default binding, stored-URL normalisation, no rollback baseline on the browser path, etc.) are listed in the browser auditor's report and must each become code or a test before any secret crosses the channel.

### 4.3 SY-1 — the rollback baseline

Move `highest_vector_clock_seen` into the OS keystore as crypto-design §10 requires (a keyed MAC under a keystore-held key is the minimal form), fail **closed** when the baseline store exists but is unreadable (repair already does), and refuse a state dir that resolves inside a cloud-synced tree where that is detectable.

### 4.4 FF-4 — per-handle write gate

Add a `write_gate: Mutex<()>` to `OpenVaultManifest` held across snapshot → core → write-back in every mutating orchestrator. Audit the call graph first: a mutating orchestrator that calls another (rather than core directly) would deadlock on a non-reentrant mutex. Not attacker-reachable (requires the app to issue concurrent writes on one handle) — correctness/availability.

### 4.5 Availability hardening (VL-4, VL-5, SY-2, SY-4, DT-3)

A bounded, regular-file-only read helper in `core::vault::io` used by every reader; give core `open_vault` the same `load_baseline` hook `repair_vault` has so the §10 check precedes the sweeps; a failure counter/backoff on the desktop unlock commands and a gesture on `use_recent_vault`.

### 4.6 SC-3 — release integrity before v1

`release.yml` on `v*` tags: `cargo build --release --locked`, `pnpm tauri build` with signing/notarization secrets and the Tauri updater key, `./gradlew assembleRelease` with a signing config, `cargo cyclonedx`/`pnpm sbom` artifacts, `actions/attest-build-provenance`, a `SHA256SUMS`; `ENABLE_HARDENED_RUNTIME` on for macOS; a `SECURITY.md` with a disclosure channel. Do SC-1 (`cargo update -p plist -p wayland-scanner`, drop the two `audit.toml` ignores) as its own PR. Add guard LIMITS entries (or rules) for SC-5/6/7/8, `--deny yanked`-style hardening or an explicit yanked-check exit assertion for SC-9, gradle wrapper validation (SC-10), and CI jobs for `spec_test_name_freshness.py` (once #574 is cleared) and `browser/extension` (SC-11).

---

## 5. Prior-audit (2026-07-02) status

| ID | Status | Note |
|---|---|---|
| C-1..C-6, I-1 | Fixed | ml-kem `zeroize` on; seed/stack copies wiped; `UnknownWord { index }` |
| V-1, V-2 | Fixed | repair #350 + resumable restore |
| V-3 | Fixed (app opens) | residual ordering → VL-4 |
| V-F4 | Fixed (docs) | crypto-design §5a "Revocation boundary" |
| V-5 | Partial → VL-3 | core verifies the card but TOFU premise is void while the host writes `contacts/` |
| V-6 | Open (Info) | VL-9 |
| F-2, F-3, F-4 | Fixed | `persist_noclobber`, `is_wiped()`, output wipes |
| D-1 | Open (accepted) | write re-auth remains a UX presence gate |
| D-2 | Fixed | `path_auth.rs`; no bypass found |
| D-3 | Fixed | frontend gate |
| D-4 | Open (Info) | `style-src 'unsafe-inline'` (#134) |
| iOS-1..6, A-2 | Not re-verified | mobile auditor interrupted (§1.2) |
| A-1 | Fixed (complete) | segment scan + canonical containment; SAF push side cannot traverse |
| S-1 | Partial | `audit.yml` + `.cargo/audit.toml` exist; SC-1/SC-9 residuals |
| S-2, S-3, S-4, S-7 | Fixed | SHA pins, snap revision, enumerated ignores, CLAUDE.md wording |
| S-5, S-6 | Info | unchanged |

---

## 6. Verification record

- `cargo fmt --all --check` clean; `cargo clippy --release --locked --workspace --tests -- -D warnings` clean; `cargo build --release --locked --workspace` clean (non-test build — proves the lockfile matches the manifests and that neither `test-support` nor `dev-secret-source` reaches a release artifact); `cargo test --release --locked --workspace`: all green except the three root-only artifacts in §1.2; `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked --workspace` clean.
- Guards (self-test then real): lean-binding ✅✅, iOS log hygiene ✅✅, Android log hygiene ✅✅, error-payload hygiene ✅✅, test-support placement ✅✅, secret-slot hygiene ✅✅, `spec_test_name_freshness` self-test ✅ / real ❌ (pre-existing 90 unresolved citations, #574, unchanged by this work).
- Desktop frontend: 786/786 tests, `svelte-check` 0 errors, `eslint` clean. Browser host: 73 unit + 5 echo + 2 KAT (28 vectors), clippy clean with the feature on and off.
- Cargo.lock delta: exactly two dependency edges (`secretary-browser-host` self dev-dep, `arboard`); no version moves.
