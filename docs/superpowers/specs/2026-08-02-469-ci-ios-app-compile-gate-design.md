# Design — #469: CI compile gate for the iOS app target

**Issue:** [#469](https://github.com/hherb/secretary/issues/469)
**Date:** 2026-08-02
**Scope:** one CI workflow file. No Swift, Rust, script, or on-disk-format change.

## Problem

Nothing in CI compiles `ios/SecretaryApp`.

| Workflow / job | What it covers |
|---|---|
| `macos-host.yml` → `run-macos-tests.sh` | pure host packages, xcframework build, `SecretaryKit` macOS host test, **`SecretaryMac.app`** compile |
| `test.yml` → `ios-host` | `swift test` on the two FFI-free host packages only |
| `ios-tsan.yml` | TSan run |
| *(nothing)* | **`ios/SecretaryApp`** |

`ios/scripts/run-ios-tests.sh` step 5 does build the iOS app, but that script is not wired into any workflow. So every iOS app-target source file — `SettingsScreen.swift`, `VaultBrowseScreen.swift`, `RecordEditScreen.swift`, and eleven others — is compile-gated only by a developer remembering to run `build-app.sh` locally.

This is the file class most prone to failing in a way host tests cannot catch. One extra modifier on `VaultBrowseScreen.body` has previously tripped *"unable to type-check in reasonable time"* (`xcodebuild` exit 65) — a hard compile failure with no unit-test or runtime signal ([[project_secretary_ios_swiftui_typecheck_limit]]). PR #468 changed `SettingsScreen.swift` and relied entirely on a local build for that proof.

Surfaced by the PR #468 review. Pre-existing, not introduced there.

## Prior art

`macos-host.yml` (#437) is the pattern: a standalone, path-gated, `macos-26`-pinned workflow that runs a local acceptance runner verbatim, mirroring `ios-tsan.yml`. It exists precisely because a heavy macOS-only build should not gate `test.yml`'s jobs, which must run on every PR.

Its cost profile is the key fact for this design: **`run-macos-tests.sh` step 2 runs `build-xcframework.sh`, which cross-compiles four Apple triples including both iOS simulator slices** (`aarch64-apple-ios-sim`, `x86_64-apple-ios`). The job also already `brew install xcodegen`s for `build-macos-app.sh`.

So every prerequisite an iOS app compile needs is already paid for in that job.

## Approach: one step in `macos-host.yml`

Add a second step after the existing runner:

```yaml
- name: build-app.sh (iOS app compile proof, #469)
  run: bash ios/scripts/build-app.sh
```

### Why ordering is load-bearing

`build-app.sh` starts with:

```bash
if [[ ! -d "$XCFRAMEWORK" ]]; then
    echo "==> Secretary.xcframework not found — running build-xcframework.sh first"
    bash "$SCRIPT_DIR/build-xcframework.sh"
fi
```

Placed **after** `run-macos-tests.sh`, that branch is not taken — the framework is on disk with the iOS simulator slices already in it, so the step reduces to `xcodegen generate` + one signing-free `xcodebuild build`, roughly 1–2 minutes.

Placed **before**, the fallback fires and the job pays the four-triple cross-compile twice. The step order is therefore a correctness-of-cost property, not a stylistic preference, and the workflow comment must say so or a future edit will reorder it.

### Why not the alternatives

- **Append as step 5 of `run-macos-tests.sh`** (considered, rejected). It would keep the job a single verbatim command and give local runs the gate for free. But `run-macos-tests.sh` is documented as the *D.5.1 macOS acceptance* entry point; building an iOS app inside it makes the name lie, and `build-app.sh` would then be invoked from two runners (`run-ios-tests.sh` already ends with it). Each script keeps one purpose instead.
- **A separate path-gated workflow** (issue option 2, rejected). It would duplicate the multi-minute four-triple cross-compile in a second macOS job for zero additional safety.
- **Add it to `test.yml`'s `ios-host` job** (rejected). That job is deliberately FFI-free — no cargo, no rust-cache, no xcframework — so it would have to build the framework from cold on every PR, including PRs touching no Apple code at all.

### Also changed

- **Workflow `name:` and job `name:`.** Currently `macOS host` / `SecretaryKit macOS host + app compile`, where "app" means `SecretaryMac` alone. With two apps compiled, the existing name is actively misleading. Concretely:

  | | before | after |
  |---|---|---|
  | workflow `name:` | `macOS host` | `macOS host + app compile` |
  | job `name:` | `SecretaryKit macOS host + app compile` | `SecretaryKit macOS host + macOS/iOS app compile` |

  The workflow **filename** stays `macos-host.yml` — it is referenced by the path gate's own `paths:` entry and by the `concurrency.group`, and renaming it would churn both for no gain.
- **Header comment.** Records what is now covered, the ordering rationale above, and the `#469` reference — matching the file's existing convention of explaining *why* each pin and gate exists.

### Explicitly unchanged

| Thing | Why |
|---|---|
| Path gate (`ios/** + ffi/** + core/** + the workflow file`) | already covers `ios/SecretaryApp/Sources/**` |
| `timeout-minutes: 45` | one warm `xcodebuild build` against a 45-minute cap |
| `brew install xcodegen` step | already present for `build-macos-app.sh`; `build-app.sh` needs the same binary |
| `runs-on: macos-26` + `setup-xcode 26.5` pins | the #424 toolchain-determinism fix; untouched |
| `ios/scripts/*` | no script change at all |
| `run-macos-tests.sh` | stays the D.5.1 macOS acceptance runner |

## Testing

A CI gate has the same vacuity hazard as a test that asserts nothing: a green run proves nothing unless the gate has been observed *failing* on a known-bad input. This repo already applies that discipline elsewhere — `ffi/scripts/check-lean-binding.sh --self-test` fires its matcher against a known-positive control (`secretary-cli`) before a clean run is trusted.

So the gate is proven red-before-green, at both the command level and the CI level:

| # | Action | Proves |
|---|---|---|
| 1 | `bash ios/scripts/build-app.sh` on the unmodified branch | baseline: the command passes on good code |
| 2 | Introduce an undefined-symbol reference in `ios/SecretaryApp/Sources/SettingsScreen.swift`; re-run | the command is a real gate, not a no-op returning 0 |
| 3 | Push PR commit 1 **with the break still present**; observe `macos-host` red **on the new step** | the CI wiring fires — the issue's literal acceptance criterion |
| 4 | Push commit 2 reverting the break; observe green | no false positive; the gate passes clean code |

**Why an undefined symbol** rather than a syntax error or a deliberate type-check timeout: a syntax error proves less (any tool catches it), and a type-check-ceiling repro is slow and nondeterministic. An undefined symbol fails in the type-checker — the realistic failure class here — deterministically and fast. `SettingsScreen.swift` is the file that surfaced #469, so it is the honest target.

**Step 3 must fail on the new step specifically**, not merely somewhere in the job. A break in `SettingsScreen.swift` cannot affect `run-macos-tests.sh` (that runner never compiles the iOS app target), so a red run whose failing step is the earlier one would indicate a different problem and invalidate the proof.

### Local build prerequisites

`build-xcframework.sh` emits **three** gitignored artifacts, and a fresh worktree has none of them:

1. `ios/Secretary.xcframework/`
2. `ios/SecretaryKit/Sources/SecretaryKit/secretary.swift` — the generated uniffi bindings
3. `ios/SecretaryKit/Tests/SecretaryKitTests/Resources/` — the staged golden-vault fixtures

Seeding only (1) fails the build with `cannot find type 'VaultError' / 'OpenVaultOutput' in scope`, because (2) is where those generated types live. All three must be present.

The local artifacts are regenerated from the branch's own commit rather than reused from an older build, so the mutation check in step 2 runs against current bindings.

An earlier draft of this spec asserted the artifacts could safely be reused because every `core/`/`ffi/` change since they were built was "test-only". That was wrong — `#449`/`#451` moved test-support code through **non-test** source files in `ffi/secretary-ffi-bridge` and `ffi/secretary-ffi-uniffi`. The `.udl` was untouched, which is a reason to *expect* stable bindings but not a verification of it. So the bindings were regenerated at `0ecc5db` and byte-compared against the 2026-07-16 copy: **identical**. The reuse would in fact have been harmless — but that is now a checked fact rather than an inference from a false premise.

CI builds all three from cold on every run regardless, and steps 3–4 above are the authoritative proof.

## Files

| File | Change |
|---|---|
| `.github/workflows/macos-host.yml` | +1 step, 2 `name:` edits, header comment |
| `docs/superpowers/specs/2026-08-02-469-ci-ios-app-compile-gate-design.md` | this spec |
| `docs/superpowers/plans/2026-08-02-469-ci-ios-app-compile-gate.md` | implementation plan |
| `docs/handoffs/2026-08-02-469-ci-ios-app-compile-gate-shipped.md` + `NEXT_SESSION.md` | baton |

`ios/SecretaryApp/Sources/SettingsScreen.swift` is touched **transiently** by test steps 2–3 and reverted in step 4. It must not differ from `main` in the merged result.

## Acceptance

- [ ] `macos-host.yml` contains a `build-app.sh` step placed after the `run-macos-tests.sh` step.
- [ ] Workflow + job names name both compiled apps.
- [ ] `actionlint` clean on the edited workflow.
- [ ] Local: `build-app.sh` exits 0 on the unmodified branch, and non-zero with a compiler diagnostic on the deliberately-broken one.
- [ ] CI: a `macos-host` run is observed **red on the new step** with the break present, and green after it is reverted.
- [ ] `git diff main... -- ios/ core/ ffi/` is empty in the final branch state.

## Non-goals

- **#464 (CodeQL Swift analysis).** Needs the same macOS xcframework build, but is a separate, larger slice: a `build-mode: manual` Swift leg, a matrix-leg-vs-separate-workflow decision, and triage of the first batch of public Swift alerts over Keychain / Secure-Enclave / FFI secret-marshalling code. Kept separate by decision. This slice does make #464 cheaper: it answers "which schemes to analyze" for the iOS app and proves the build recipe.
- **A durable `--self-test` mode for the compile gate.** Considered; rejected as over-engineering. It would need a deliberately-broken fixture checked into the repo plus a whole extra `xcodebuild` per invocation, to guard a failure mode that is loud rather than silent.
- **Running the iOS app's *tests* in CI.** There is no iOS app test target ([#417](https://github.com/hherb/secretary/issues/417)). This slice buys compile coverage only — it does not make `SettingsScreen.swift` render-tested, and the ~3 lines of view glue #459 left uncovered stay uncovered.
- **Android app compile coverage.** Out of scope; `:app` is built by its own Gradle jobs.
- **Re-tuning `timeout-minutes`.** Provisional since #437; revisit against live durations once a few runs exist, not here.
