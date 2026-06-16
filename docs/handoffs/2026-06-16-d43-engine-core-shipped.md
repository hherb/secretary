# D.4.3 — origin-matching engine: security core shipped, integration pending ⏳

**Session date:** 2026-06-16. Track: **D.4 browser autofill** (handoff in
`NEXTSESSION_BROWSER_PLUGIN.md`, not the `NEXT_SESSION.md` symlink). This was a
**browser-free** session (work done from a hospital computer; the real-browser
smoke waits for the user's Mac).

**Status:** ⏳ **partial** on branch `claude/intelligent-davinci-hriple`. The
**pure, security-critical core of D.4.3 (tasks 1–4) is complete, pinned, and
CI-gated.** The vault **integration (task 5)** is deliberately deferred behind
an architectural decision (below) that needs a human call. **Purely additive**
under `browser/` + `docs/`.

## (1) What shipped this session (browser-free)

Beyond D.4.3, this session also closed two D.4 side-quests:
- **`browser/host-manifest/install-dev.sh`** — turnkey build+install of the host
  manifest so the user's later real-browser smoke is copy-paste.
- **Headless extension tests** (`browser/extension`, vitest + mocked chrome) —
  and they **caught a real bug**: `background.ts` imported `./messaging`
  extensionless, which a Chrome MV3 **module service worker would fail to load**;
  fixed to `./messaging.js`. This would have broken the on-Mac smoke.

### D.4.3 tasks 1–4 (the security core)

| Task | Deliverable | Commit |
|---|---|---|
| plan | D.4.3 origin-matching plan (PSL decision, contract, 6 tasks) | `6c8b648` |
| **1** | `origin.rs` — `parse_origin` → `ParsedOrigin` (scheme, ASCII/punycode host, normalized port, `is_https`, `is_idn`, per-label `mixed_script`) | `6ba2cfb` |
| **2+3** | `origin_match.rs` — `decide(top, frame, stored, binding)` → `MatchDecision`; HTTPS-only, top-frame-governs, exact_origin + registrable_domain (PSL `psl::domain_str`, `=2.1.137` exact-pinned) | `155ad01` |
| **4** | `tests/data/origin_match_kat.json` (24 vectors) + `tests/origin_match_kat.rs` replay | `1996a5b` |

**Acceptance:** `cargo test -p secretary-browser-host` green (origin 9 + engine
16 + KAT replay 2 + the D.4.1/4.2 suite); `cargo clippy … -D warnings` clean;
`#![forbid(unsafe_code)]` holds.

### The engine (what review should focus on)

`origin_match::decide` is pure (no I/O, no vault, no `chrome`). Rules, all
required to fill (else refuse with a typed `MatchReason`):
1. **HTTPS-only** — both top + frame `https`; `data:`/`about:`/`file:` parse to
   no-host → refuse.
2. **Top-frame governs** — frame must match top under the binding; cross-origin
   (exact) / cross-site (registrable) iframe → refuse.
3. **Origin match** — stored must match frame under the binding.

Bindings: `exact_origin` (scheme+host+port, default-port-normalized);
`registrable_domain` (eTLD+1 via PSL — subdomains share, **`github.io` private
suffix does NOT cross-fill**, bare-IP/unknown-TLD falls back to exact host, never
a suffix shortcut). Matching runs on the **normalized ASCII host**, so an IDN
homograph cannot match the real domain; `mixed_script` rides along for the
D.4.4 dialog.

**PSL is exact-pinned** (`psl = "=2.1.137"`): the embedded list is baked into
the crate version, so the pin pins the list; a bump moves match boundaries and
is a deliberate, reviewed change (design §12 invariant 8; `tempfile =3.27.0`
discipline).

## (2) ⛔ The task-5 decision (needs a human call)

Making `per_fill_count` **origin-aware** means: open the casual vault (already
done), then for each block **decrypt → enumerate records → read the URL field +
the `d4_origin_binding` from the record `unknown` map → run `decide` → count
fills**. The blocker: the only higher-level "decrypt a block to its records"
helper, **`decrypt_block_plaintext(identity, manifest, block_uuid)`, lives in the
FFI *bridge*** (`ffi/secretary-ffi-bridge/src/record/orchestration.rs`), not in
core. Core only exposes the low-level `decrypt_block(...)` (which needs sender +
reader card fingerprints, key bundles, X25519/ML-KEM secrets explicitly).

So the host needs one of:

| Option | Cost | Notes |
|---|---|---|
| **A. Depend on `secretary-ffi-bridge`** | Pulls `secretary-cli` (sync machinery) into the host | Contradicts the D.4.2 decision to depend on `secretary-core` only; biggest dep surface |
| **B. Reimplement block-decrypt orchestration** in the host from core primitives | Re-derives keys/fingerprints | Violates "reuse, don't reimplement"; error-prone on the crypto path — **not recommended** |
| **C. Lift a `read_block_records`-style helper into `secretary-core`** as a `pub fn` over `OpenVault` | A small, reviewed **core API addition** (composition of existing primitives — not new crypto) | Cleanest reuse; keeps the host on `secretary-core` only; **recommended**, but it's a core-surface change that wants explicit sign-off |

**Recommendation: C** — add `secretary_core::vault::read_block_records(&OpenVault,
block_uuid) -> Result<Vec<Record>, _>` (or `read_all_records(&OpenVault)`)
composing the existing decrypt path, then the host stays `secretary-core`-only
and origin-matches over real records. This is the one open decision; I did not
make it unilaterally while you were away.

Also for task 5: which record field holds the credential origin? (the design
calls it "an ordinary login-record field" — likely a `url` field). The golden
vault may need a crafted login record with a URL field + `d4_origin_binding` for
the integration test.

## (2a) Post-review hardening — page-level gate on the count path

Review of the PR flagged that `per_fill_count` was reached **without any
origin/HTTPS check** — safe today only because the content script is
`https://example.com/*`-scoped, but a latent count-leak the moment that
broadens. Fixed without waiting on the §2 decision: `Context::answer_query` now
runs a **page-level gate** (`origin_match::page_affordance_allowed`, rules 1+2 —
HTTPS-only + top-frame-governs) before opening the vault, returning `count: 0`
on a non-HTTPS page or a cross-origin iframe. HTTPS is derived from the **parsed**
origins, not the extension's advisory `https` flag. A `page_gate_agrees_with_decide`
test pins the gate to `decide` so they can't drift. This is **rules 1+2 only**;
the per-credential, origin-aware count (rule 3) is still task 5 below.

## (3) What remains in D.4.3

- **Task 5** — origin-aware `per_fill_count`: thread the query origins
  (`top_origin`/`frame_origin`) into the open+count, read each record's URL +
  `d4_origin_binding` (record `unknown` map, default = helper-local
  `default_binding`), run `decide`, count fills. Needs the §2 decision first.
  Add `default_binding: OriginBinding` to `HostConfig`.
- **Task 6** — docs + repoint `NEXTSESSION_BROWSER_PLUGIN.md` → D.4.4; mark
  D.4.3 shipped.

## (4) Guardrails still holding

No socket; manifest-bound ID; never-panic 1 MiB framing; per-fill open is the
same `open_vault(Unlocker::DeviceSecret)` verify-before-decrypt; no key material
between fills; **no secrets cross the channel** (only a count); PSL exact-pinned;
KAT is the contract (never relax a vector); `#![forbid(unsafe_code)]` + clippy
`-D warnings` clean. The engine never fills a cross-origin iframe and is
HTTPS-only (design §12 invariant 5).

## (5) Exact commands to resume

```bash
cargo test  --release -p secretary-browser-host           # engine + KAT + suite
cargo test  --release -p secretary-browser-host --test origin_match_kat
cargo clippy --release --workspace --exclude secretary-desktop --tests --bins -- -D warnings
# real-browser smoke (on the Mac): browser/host-manifest/install-dev.sh --ext-id <ID>
```
