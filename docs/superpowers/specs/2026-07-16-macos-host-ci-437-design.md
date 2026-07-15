# Design — `#437`: wire `run-macos-tests.sh` into CI (macos-host job)

**Date:** 2026-07-16
**Issue:** [#437](https://github.com/hherb/secretary/issues/437) — *[D.5] Wire run-macos-tests.sh into CI (macos-host job)*
**Branch:** `ci/wire-macos-host-437` (worktree `.worktrees/macos-host-ci-437`, off `main` @ `2ec8930f`)
**Scope:** CI configuration only. No `core` / crypto / FFI / Swift / on-disk-format change. No change to any shell script under `ios/scripts/`.

## Problem

`ios/scripts/run-macos-tests.sh` is the D.5.1 layered acceptance runner for the native macOS SwiftUI client (merged in #436/#438). It runs, in order:

1. `swift test` on the two FFI-free host packages (`SecretaryDeviceUnlock`, `SecretaryVaultAccess`) — platform-agnostic.
2. `build-xcframework.sh` — cross-compiles `secretary-ffi-uniffi` for 4 Apple target triples (iOS device + 2 simulator slices + `aarch64-apple-darwin`), builds the host cdylib, runs uniffi-bindgen, and assembles `Secretary.xcframework` (incl. the `macos-arm64` slice).
3. `swift test` on **`SecretaryKit` on the macOS host** — the headline D.5.1 capability (SecretaryKit host-builds without a simulator).
4. `build-macos-app.sh` — `xcodegen generate` + a signing-free `SecretaryMac.app` compile proof.

It is **manual/local only**. There is no `macos-host` job in CI. The existing `ios-host` job (in `test.yml`) covers step 1 only (the two FFI-free packages are platform-agnostic). Steps 2–4 — the Rust→Swift xcframework integration, the SecretaryKit macOS host test, and the app compile — are **uncovered**. A regression (e.g. a future SecretaryKit adapter importing UIKit or gating a symbol `#if os(iOS)`, or an ffi UDL change that alters the generated Swift API so SecretaryKit no longer compiles) would go unnoticed until the next manual macOS run.

This is a deliberate deferral from #436/#438, not a regression — mirroring how the iOS xcframework build + app build are also out of CI because the Rust cross-compile is multi-minute. #437 closes it.

## Decision

Add a **standalone, path-gated workflow file** `.github/workflows/macos-host.yml` that runs `bash ios/scripts/run-macos-tests.sh` on a pinned `macos-26` runner.

### Why a separate workflow file (not a job in `test.yml`)

`test.yml` is the general behavior gate: **all** its jobs (`rust-test`, `desktop-test`, `swift-conformance`, `kotlin-conformance`, `ios-host`, `android-host`) run **unconditionally** on every push/PR. `run-macos-tests.sh` is the single heaviest CI leg (4 Apple target triples + host cdylib + uniffi bindgen + xcframework assembly + a `SecretaryKit` host test + a `SecretaryMac.app` compile). Adding it to `test.yml` would force that multi-minute Apple cross-compile onto every unrelated PR (docs, Android, desktop).

The repo already has the precedent for exactly this situation: **`.github/workflows/ios-tsan.yml`** — an expensive, macOS-only, Rust-cross-compiling job in its own file, path-gated to relevant changes, with no third-party action. The comment in `ios-tsan.yml` states the rationale verbatim: *"A separate workflow file is the cleanest no-third-party-action way to scope this without gating test.yml's rust/desktop/conformance jobs (which must run on every PR)."* `macos-host.yml` follows that pattern.

Note: GitHub Actions `paths:` filters apply at the **workflow** level, not per job. Path-gating a single job inside `test.yml` would require a third-party changed-files action (`dorny/paths-filter` or similar) + `if:` conditions — the repo deliberately avoids that (see `ios-tsan.yml` comment). A dedicated file is the idiomatic, zero-dependency answer.

## Workflow shape

`.github/workflows/macos-host.yml`:

- **Triggers** — `push: branches: [main]` and `pull_request`, both `paths`-filtered to:
  - `ios/**` — SecretaryKit adapters, `SecretaryMacApp` sources, and the `ios/scripts/*` runners themselves.
  - `ffi/**` — the uniffi UDL / bridge; a signature change alters the generated Swift API `SecretaryKit` compiles against.
  - `core/**` — the Rust crate the xcframework is built from.
  - `.github/workflows/macos-host.yml` — self (so edits to the workflow trigger it).

  This is **broader than `ios-tsan.yml`** (which filters `ios/**` only), and that is intentional: this job's differentiator vs `ios-host` is precisely the Rust→Swift integration, so an `ffi`/`core` change that breaks the macOS build is exactly what it must catch. (`ios-tsan.yml` guards the Swift concurrency *lock*, which only changes with `ios/**` edits, so its narrower filter is correct for *its* purpose — the divergence is deliberate, not an oversight to copy.)

- **`concurrency`** — `group: macos-host-${{ github.ref }}`, `cancel-in-progress: true` (mirrors `ios-tsan.yml`).

- **`permissions`** — `contents: read` (mirrors every other workflow).

- **Job `macos-host`:**
  - `runs-on: macos-26` — pinned, **not** `macos-latest` (which nondeterministically resolves to macos-15 / Swift 6.0 or macos-26 / Swift 6.3; the Swift packages target 6.3). Same rationale as every other macOS leg (#424).
  - `timeout-minutes: 45` — the cold cross-compile of 4 target triples + 2 `xcodebuild` invocations is heavier than any 30-min `test.yml` leg but lighter than `ios-tsan.yml`'s 60 (TSan is 5–15× slower). Provisional; re-tune against live CI once first-run duration is known (matches the repo's provisional-timeout comment convention).
  - **Steps:**
    1. `actions/checkout` — SHA-pinned `34e114876b0b11c390a56381ad16ebd13914f8d5 # v4` (repo-wide pin).
    2. `maxim-lobanov/setup-xcode` — SHA-pinned `ed7a3b1fda3918c0306d1b724322adc0b8cc0a90 # v1.7.0`, `xcode-version: '26.5'` (Swift 6.3; repo-wide pin).
    3. `Swatinem/rust-cache` — SHA-pinned `e18b497796c12c097a38f9edb9d0641fb99eee32 # v2` (the Rust cross-compile is the cost; caching it is essential).
    4. `brew install xcodegen` — explicit provisioning. `build-macos-app.sh` hard-requires `xcodegen` (errors `brew install xcodegen` if absent) and it has never run in this repo's CI before. An explicit step gives deterministic presence rather than depending on undocumented image contents. It installs the latest formula version; we pin later only if a bump ever bites (non-security dev tool that generates an `.xcodeproj` from `project.yml`).
    5. `bash ios/scripts/run-macos-tests.sh` — the acceptance-defined entry point, run as-is.

### Why the script is used unchanged

`run-macos-tests.sh` is the acceptance-defined entry point (#437 says "runs run-macos-tests.sh") and already runs green as the D.5.1 acceptance runner in this repo. Its step 1 re-runs the two FFI-free host packages that `ios-host` also covers — negligible duplication next to the multi-minute build, not worth special-casing. Keeping the script as the single source of truth means the local command and the CI command stay identical.

## Testing / verification (TDD-analog for CI config)

CI-workflow changes are locally gateable in this repo (`actionlint` + `shellcheck` installed):

- **Primary gate:** `actionlint .github/workflows/macos-host.yml` must be clean. This validates YAML shape, action refs, `paths:`/`on:` syntax, expression syntax, and shell in `run:` steps.
- **No script change** → `shellcheck` scope is unchanged; the existing `ios/scripts/*` scripts are untouched.
- **Structural confidence:** the workflow is a faithful mirror of the proven `ios-tsan.yml`, and `run-macos-tests.sh` is already a known-good runner (D.5.1 acceptance).
- **Full-run confidence:** the actual GitHub-hosted macOS run can only be observed once, on the PR itself (`gh pr checks`). A first-run green (and the job going **red** if a SecretaryKit macOS host test or the app compile breaks) is the terminal acceptance — verified on the PR, not locally.

## Acceptance criteria (from #437)

- [ ] A `macos-host` CI job runs `run-macos-tests.sh` and goes **red** if the SecretaryKit macOS host test or the `SecretaryMac.app` compile proof breaks.
- [ ] Runner pinned to `macos-26` + `setup-xcode` (no `macos-latest`), `timeout-minutes` set, per the #424/#427 CI-hardening conventions.
- [ ] `actionlint` clean on the new workflow.
- [ ] Path-gated so the job does **not** run on unrelated (docs / Android / desktop-only) PRs.

## Out of scope

- Changing any `ios/scripts/*` script (used as-is).
- Adding an `x86_64-apple-darwin` (Intel macOS) slice — deferred per `build-xcframework.sh`.
- Any Swift / Rust / crypto / format change.
- Pinning `xcodegen` to an exact version (revisit only if a bump breaks the build).
- On-device Touch ID / Secure-Enclave verification (that remains the manual proof in `ios/SecretaryMacApp/MANUAL-PROOF.md`; CI is a signing-free compile proof only).

## Risks

- **First-run duration unknown.** `timeout-minutes: 45` is a generous provisional headroom; if the cold run exceeds it, bump after observing `gh pr checks`. rust-cache should make warm runs much faster.
- **`brew install xcodegen` version drift.** Latest-version install; acceptable for a non-security project-file generator. If a future XcodeGen release changes generated settings and breaks the compile proof, pin the formula then.
- **`xcodegen` may already be preinstalled on `macos-26`.** If so, `brew install` is a (cheap) no-op/upgrade — still correct, and keeps the dependency explicit rather than relying on undocumented image contents.
