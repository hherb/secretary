# NEXT_SESSION.md — `cargo audit` green again: RUSTSEC-2026-0385 (`ctutils`, constant-time) cleared

Branch `fix/audit-ctutils-tokio`, worktree `.worktrees/audit-ctutils`, base
`abb0d91e` (`main`).

**Why this slice and not the contact_card baton's "what's next":** the
previous handoff (`2026-09-22-token-compare-contact-card-shipped.md`) was
already fully merged as #698. Starting state showed the weekly
`Dependency audit` red on `main` since 2026-10-26, carrying a
vulnerability-class constant-time advisory in the crypto core. Ranked by
blast radius, that came first.

---

## (1) What shipped

| SHA | What |
|---|---|
| `439e56e2` | `Cargo.lock` bump + `.cargo/audit.toml` entry + side-channel memo + ROADMAP + this handoff |

PR: [#708](https://github.com/hherb/secretary/pull/708).

- **`ctutils` 0.4.2 → 0.4.8** (RUSTSEC-2026-0385, non-constant-time mask
  generation and `u128` comparisons; patched ≥ 0.4.4). Transitive via
  `ml-dsa 0.1.0-rc.8`. Lockfile-only; no manifest change.
- **`tokio` 1.52.3 → 1.54.1** (RUSTSEC-2026-0386, `AsyncFd::new` I/O-safety
  unsoundness; patched ≥ 1.53.3). Desktop-only, via `tauri`/`reqwest`. The
  repo has no `AsyncFd` call site.
- **`clipboard-win` 5.4.1 → 5.4.3** (5.4.1 yanked). Windows desktop only,
  via `arboard`.
- **`basic-toml` (RUSTSEC-2026-0374, unmaintained) ACCEPTED** in
  `.cargo/audit.toml` with rationale + exit criteria. Build-time only:
  `askama_derive` → `askama` → `uniffi_bindgen` → `uniffi_build` → `uniffi`
  `[build-dependencies]` of `secretary-ffi-uniffi`. `cargo tree -i
  basic-toml -e normal --target all` prints nothing. No patched version
  exists, and the newest `askama_derive` (0.16.1) still requires `^0.1.1`.
- **Lockfile side effect, measured:** unlocking `tokio` (at any patched
  version: 1.53.3, 1.54.0 and 1.54.1 all behave the same) re-points 12
  packages' `windows-sys` dependency among the five ALREADY-locked
  `windows-sys` versions (count stays 5). No other package version moves;
  Windows-target lock lines only (Windows is not a primary target).
- `docs/manual/contributors/side-channel-audit-internal.md`: records the
  advisory and tells the external reviewer to treat transitive CT crates
  (`ctutils`, `subtle`) as upstream surface.
- `ROADMAP.md`: one dated line under the side-channel audit item.
- **Filed [#707](https://github.com/hherb/secretary/issues/707):** a failing
  scheduled audit alerts nobody (the root cause of the two-week gap).

### Gates (this session, in the worktree)

```
cargo audit --deny warnings                                     — 0
cargo test --release --locked --workspace                       — 0 (2,251 passed, 103 binaries, 0 failed)
```

The ML-DSA-65 NIST KATs (`core/tests/sig.rs`, `ml_dsa_65_kat.json`) ran
inside that suite: `ml_dsa_65_nist_keygen_kat`, `_siggen_kat` and
`_sigver_kat` all ok. Clippy/rustdoc/guards were not re-run: no `.rs` or
manifest file changed, only `Cargo.lock`, and the suite above recompiled
against it.

---

## (2) What is next

1. **#707: alert on a red scheduled audit.** Acceptance: a final
   `if: failure() && github.event_name == 'schedule'` step opens or comments
   on one open `audit`-labelled issue (idempotent); `actionlint` clean; proven
   by a `workflow_dispatch` dry run with an injected failure.
2. **#709: 20 open Dependabot npm advisories** (desktop + browser
   extension; `devalue`/`source-map-js`/`vite` rated high). `devalue` rides
   in via `svelte`, whose runtime ships in the desktop bundle, so check
   reachability before dismissing anything as dev-only. pnpm only.
3. Then resume the conformance backlog the previous baton listed
   (`docs/handoffs/2026-09-22-token-compare-contact-card-shipped.md` §6):
   #641 (`bundle_file` / `vault_toml` token comparison), #693 (spec: card
   report order), plus the filed review residuals #699–#705. **#700**
   (nothing pins a target's membership in `TOKEN_COMPARED_TARGETS`) is the
   one with real teeth.
4. Housekeeping: #659 is fixed in code (der 0.8.2, PR #656) but still open
   on the tracker; close it.

## (3) Open decisions / risks

- `basic-toml` acceptance is a risk decision on build tooling, re-checked on
  every uniffi bump (exit criteria in `.cargo/audit.toml`).
- `ml-dsa` stays a release candidate (`0.1.0-rc.8`); its CT helper crates
  are where this advisory landed. No exact pin was added for `ctutils`: it is
  transitive, the committed lockfile plus `--locked` CI already fix it, and
  `cargo audit` would flag a regression.
- Open Dependabot PR #706 (vite 6.4.3 → 6.4.4, desktop dev dep) is untouched.

## (4) How to resume

```bash
cd /Users/hherb/src/secretary/.worktrees/audit-ctutils
pwd && git branch --show-current            # fix/audit-ctutils-tokio
git fetch origin && git log --oneline HEAD..origin/main
cargo audit --deny warnings
cargo test --release --locked --workspace
```

## (5) Where this document lives

This file. `NEXT_SESSION.md` at the repo root is a symlink to it,
retargeted in the same commit as this file's creation.
