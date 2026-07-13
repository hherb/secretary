# Design — CI hardening: pin macOS toolchain + universal `timeout-minutes` (#424)

**Date:** 2026-07-13
**Issue:** [#424](https://github.com/hherb/secretary/issues/424) — *CI hardening: pin Xcode toolchain + add timeout-minutes uniformly across test.yml jobs*
**Branch:** `feature/ci-hardening-424` off `main` @ `e0f47586`
**Scope class:** CI/config only — [.github/workflows/test.yml](../../../.github/workflows/test.yml) is the **only** file changed. **No** `core` / crypto / FFI / on-disk-format change; no new error variant; `#![forbid(unsafe_code)]` intact; no production code. Additive/hardening — no job's *behaviour* changes, only its runner determinism and its runaway ceiling.

## Problem

Two latent-reproducibility gaps surfaced by the #423 final review, both **repo-wide** across `test.yml`'s jobs:

1. **Unpinned macOS toolchain.** The macOS jobs rely on the runner image's *default* Xcode. Last session proved this is nondeterministic: the same commit compiled green on `macos-26` (Swift 6.3) and red on `macos-15` (Swift 6.0), both requesting `macos-latest` (GitHub is mid-migration of that label). The Swift packages target Xcode 26.5 / Swift 6.3 and use integer-literal type inference Swift 6.0 rejects. `ios-host` was pinned to `macos-26` as a point fix (commit `77819765`), but `swift-conformance` still runs on `macos-latest`, and neither macOS job pins the *Xcode within* the image — the image's default Xcode can still drift over the image's lifetime.
2. **No `timeout-minutes` on any job.** A hung `swift test` or a stalled Gradle configure runs to the GitHub default of **6 hours**, burning the scarce/paid macOS runner minutes the #423 spec explicitly flagged as a cost concern.

Neither gap is a correctness bug today; both are reproducibility/cost hardening. Left unfixed they re-introduce exactly the class of flake that cost a full CI cycle last session.

## Goals

1. **Deterministic macOS toolchain.** Every macOS job runs on a pinned runner *image* and a pinned Xcode *version*, so a future image or default-Xcode change cannot silently alter the compiler. Drift fails **loud** (never a false green), and is bumped deliberately — the repo's existing pin-explicitly discipline (cf. the pinned kotlin snap revision in `kotlin-conformance`, #367; the exact-pinned `tempfile` in `core`).
2. **Bounded runaway.** Every job caps at a `timeout-minutes` well under the 6h default, so a hang is killed in tens of minutes, not hours.
3. **Uniformity — no per-job drift.** The two fixes are applied to *every* applicable job, not a subset (#424 acceptance #3). No nondeterministic `macos-latest` label remains anywhere in the file.
4. **Follow CI discipline:** pinned action SHAs, minimal third-party actions, no behavioural change to any job.

## Non-goals (out of scope, documented not done)

- **Swift test-literal hardening.** Making the fragile `[N * 86_400_000]` array literals in the iOS host tests explicitly `UInt64` so they compile under *any* Swift version. Obviated by pinning the toolchain to Swift 6.3 (the literals compile fine there), and it **cannot be verified** without a `macos-15` runner to reproduce the Swift 6.0 rejection on. Left as a documented non-goal; can be filed as a standalone code-hygiene issue if a paper trail is wanted.
- **Emulator instrumented job** (`:browse-ui:connectedDebugAndroidTest`) — separate roadmap item.
- **`:app`/`:kit` compile-gate** — heavier full-Android-build lift, separate enhancement.
- **Retrofitting timeouts/pins onto the Rust/Linux workflows** (`rust-lint.yml`, `audit.yml`). Scoped to `test.yml`, the file #424 names. Tracked in **#427**. **(Review addendum:** the PR review found `ios-tsan.yml` — a *macOS Swift* job building SecretaryKit under `xcodebuild` — is exposed to the *same* Swift-toolchain flake, so it was **pulled in** and pinned in this PR. The remaining `rust-lint.yml`/`audit.yml` are Rust builds with no Swift-literal flake, hence still deferred to #427.)

## Design

All edits are within the existing `jobs:` map of `.github/workflows/test.yml`. The `on:` triggers, `concurrency`, `permissions`, and `env` blocks are untouched.

### Change 1 — Pin the Xcode toolchain on the two Swift jobs

Both `swift-conformance` and `ios-host` gain, as the **first step after `checkout`** (before any cargo/rust-cache/swift build, so the selected toolchain is in effect for everything downstream):

```yaml
- uses: maxim-lobanov/setup-xcode@ed7a3b1fda3918c0306d1b724322adc0b8cc0a90 # v1.7.0
  with:
    xcode-version: '26.5'   # Swift 6.3 — the macos-26 image default AND the code's target
```

- `swift-conformance` **also** moves `runs-on: macos-latest` → `macos-26` (matching `ios-host`, which is already pinned). This closes the macos-15/26 image nondeterminism at the *image* layer.
- `xcode-version: '26.5'` is the current `macos-26` image default (build 17F42, Swift 6.3), so this is behaviourally a no-op **today** — its value is making the toolchain *explicit*: if a future image changes its default or drops 26.5, `setup-xcode` fails loud and we bump the version string deliberately.
- Rationale for pinning **both** image and Xcode (belt-and-suspenders): the image pin alone leaves the default Xcode free to drift within the image's lifetime; the Xcode pin alone (on `macos-latest`) doesn't help because the flake is the *image* resolving to `macos-15`, which may not even carry Xcode 26.5 (`setup-xcode` would then hard-fail). Only pinning both is fully deterministic. This satisfies #424 acceptance #1 (pinned-SHA action) literally.

`rust-test`'s macOS matrix leg does **not** get `setup-xcode` — it compiles no Swift; its Rust toolchain is already pinned via `rust-toolchain.toml`. It gets an image pin only (Change 3).

### Change 2 — `timeout-minutes` on every job

Add `timeout-minutes: 30` at the job level to **all six** jobs (`rust-test`, `desktop-test`, `swift-conformance`, `kotlin-conformance`, `ios-host`, `android-host`), uniformly.

A single value (not per-job tuned) is deliberate: it satisfies "no per-job drift" literally, is one documented constant rather than six numbers to justify, and the timeout is a **runaway safety cap, not a performance target** — its only job is to kill a hang well under the 6h default. Being generous relative to real durations is correct; a fast job that hangs still dies in 30 min instead of 6 h.

`30` is grounded in the observed durations from the last green run (warm caches): the slowest job is `cargo test` at **~5m14s**; the rest are ≤ ~2 min. `30` gives ~6× headroom over the slowest observed run — comfortable even for a cold cargo cache (a full-workspace release rebuild of the crypto crates) — while capping runaway at 30 min.

**The value is provisional.** It is empirical and should be re-evaluated against live CI once real (including cold-cache) runs are observed; tuning it is a trivial one-line follow-up. The design commits to *a uniform cap*, not permanently to the number `30`.

### Change 3 — Pin `rust-test`'s macOS matrix leg

Change the matrix `os: [ubuntu-latest, macos-latest]` → `os: [ubuntu-latest, macos-26]` so **no** nondeterministic `macos-latest` label survives anywhere in the file (Goal 3). `rust-test`'s macOS leg is Rust-only, so it needs no `setup-xcode` — only the deterministic image. (This is a scope expansion beyond #424-as-filed, which named only the two Swift jobs; included because leaving one `macos-latest` label behind would re-open the same nondeterminism class the issue exists to close.)

### Job matrix after the change

| Job | `runs-on` | `setup-xcode` 26.5 | `timeout-minutes` |
|---|---|:---:|:---:|
| `rust-test` (ubuntu leg) | `ubuntu-latest` | — | 30 |
| `rust-test` (macos leg) | `macos-26` ⬅ | — | 30 |
| `desktop-test` | `ubuntu-latest` | — | 30 |
| `swift-conformance` | `macos-26` ⬅ | ✓ ⬅ | 30 |
| `kotlin-conformance` | `ubuntu-latest` | — | 30 |
| `ios-host` | `macos-26` | ✓ ⬅ | 30 |
| `android-host` | `ubuntu-latest` | — | 30 |

The stale forward-reference in the `ios-host` comment ("#424 tracks pinning the remaining macOS job") is updated to note #424 is resolved by this change.

## Verification strategy

CI-config changes cannot be fully exercised locally — runner-image selection and `setup-xcode` behaviour only exist on GitHub-hosted runners. The verification is therefore staged:

- **Locally verifiable:** YAML well-formedness; that the two Swift suites still pass under Xcode 26.5 (`swift test` in both `ios/SecretaryDeviceUnlock` and `ios/SecretaryVaultAccess` on the dev machine, which runs 26.5) — proving the pin targets a toolchain the code actually builds under. The Rust/desktop/Kotlin jobs are behaviourally unchanged, so their local commands remain the existing ones.
- **CI-only (the real gate):** that `swift-conformance` + `ios-host` are green on `macos-26` with `setup-xcode` selecting 26.5; that `rust-test (macos-26)` is green; and that every job's run summary shows the 30-minute timeout in effect. This is confirmed on the PR's own Actions run.

### Acceptance criteria

- [ ] `swift-conformance` and `ios-host` each run a pinned `maxim-lobanov/setup-xcode@<SHA> # v1.7.0` step selecting `xcode-version: '26.5'`, and both run on `macos-26`.
- [ ] `rust-test`'s macOS matrix leg runs on `macos-26`; **no** `macos-latest` string remains anywhere in `test.yml`.
- [ ] **Every** job in `test.yml` sets `timeout-minutes` (uniform value).
- [ ] All action pins are by commit SHA with a version comment; no existing job's behaviour (commands, working-dir, matrix semantics) changes beyond the runner/timeout hardening.
- [ ] Live CI green on the PR: `swift-conformance`, `ios-host`, `rust-test (macos-26)` all pass on the pinned image + Xcode.
- [ ] The `ios-host` comment's stale "#424 tracks…" forward-reference is updated.

## Risks

- **`macos-26` drops Xcode 26.5 in a future image refresh.** Then `setup-xcode` hard-fails — loud, never a false green. Resolution: bump the `xcode-version` string (and re-verify the Swift literals compile under the new toolchain, or apply the deferred `UInt64` hardening). This is the intended deliberate-bump behaviour, identical in spirit to the pinned kotlin snap.
- **`30` too tight on a genuinely cold cargo cache.** Low: `rust-cache` restores from the base branch, so a total miss is rare, and a from-scratch release build of the workspace is well under 30 min on GitHub runners. If a real run clips it, the value is bumped (it is explicitly provisional). The failure mode is a loud timeout, not a silent wrong result.
- **`setup-xcode` v1.7.0 SHA freshness.** Pinned to `ed7a3b1fda3918c0306d1b724322adc0b8cc0a90` (v1.7.0); a future bump is deliberate (`snap`/release lookup), consistent with repo discipline.
- **Scope creep.** Guarded: the change touches only `test.yml`; other workflows and the deferred code-hygiene/emulator items are explicit non-goals.

## Rollout

Single PR off `feature/ci-hardening-424`. The macOS-image/Xcode-pin behaviour is proven on the PR's own Actions run (the only place it *can* be proven). No README/ROADMAP change — internal CI infrastructure, no user-facing feature (consistent with #288/#289/#423, none of which appear in README/ROADMAP).
