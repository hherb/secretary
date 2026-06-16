# D.4.3 — Origin-matching engine (implementation plan)

**Date:** 2026-06-16
**Status:** Plan (pending implementation)
**Sub-project:** D.4 (browser autofill), third slice — **the security-critical one**
**Design:** [2026-06-15-d4-browser-autofill-design.md](2026-06-15-d4-browser-autofill-design.md) §5, §6, §12
**Builds on:** [D.4.2 per-fill open](2026-06-16-d42-per-fill-open-plan.md)
**Scope:** the helper-side **origin-matching engine** — given a query's
`(top_origin, frame_origin, https)` and a credential's stored origin + binding,
decide **fill vs refuse** — gated by a **pinned `origin_match_kat.json`** corpus,
and make `per_fill_count` **origin-aware**. Still returns only a *count*;
credential injection + the native confirmation dialog are D.4.4.

## 1. Why this slice earns the most review

Origin matching is the most-exploited surface in password managers (subdomain
confusion, shared-suffix hosting, cross-origin iframes, IDN look-alikes). Per
the design it gets the project's **KAT discipline**: a pinned corpus of
`(top_origin, frame_origin, stored_origin, binding) → {fill | refuse}` vectors,
replayed in Rust (and ideally cross-checked clean-room). All matching runs in
the **helper**, never in a content script (design §12 invariant 5).

## 2. Resolved decisions

1. **Bindings** (design §5, §10.6.5): `registrable_domain` (eTLD+1 via PSL) and
   `exact_origin` (scheme+host+port). Per-credential, with a **helper-local
   global default** of `registrable_domain` (already in the D.4.2 config — add a
   `default_binding` field).
2. **PSL crate → `psl` (compile-time embedded list), exact-pinned.** Recommended
   over a vendored `.dat` + `publicsuffix` runtime parse because:
   - The embedded list is baked into the crate version, so **exact-pinning the
     crate version pins the list** — exactly the "versioned, security-critical
     data dependency, deliberate-bump review" the design asks for (mirroring
     `tempfile =3.27.0`). No runtime data-file loading, no startup failure mode.
   - `psl::domain(host)` / `psl::suffix(host)` give eTLD+1 directly, ICANN vs
     private-suffix aware (so `foo.github.io` is its own registrable domain).
   - Pin as `psl = "=X.Y.Z"` with a rationale comment; a bump is a reviewed
     change because it moves match boundaries.
   - *Alternative considered:* vendoring `public_suffix_list.dat` in-repo +
     `publicsuffix` runtime parse gives byte-exact control but adds a load path
     + failure mode for no real gain at this stage. Revisit only if we need a
     list newer/older than any `psl` release.
3. **`origin_binding` storage** (design §6, **zero format change**): read the
   per-record policy from the record-level `unknown` map under the reserved key
   **`d4_origin_binding`** (values `"registrable_domain"` / `"exact_origin"`).
   Absent → the helper-local default. D.4.3 only **reads** it; writing is D.4.5.
   The credential's origin is an ordinary record **field** (the URL field).
4. **Engine is pure.** It takes parsed inputs and returns a decision; no I/O, no
   vault, no `chrome`. This is what the KAT replays and what review focuses on.

## 3. The matching contract (design §5 — each rule a KAT vector)

Inputs: `top_origin`, `frame_origin` (both from the query), `stored_origin` (the
credential's URL field), `binding` (effective: per-record or default).

Decision = **fill** iff ALL hold, else **refuse**:

1. **HTTPS-only.** `frame_origin` (and `top_origin`) scheme is `https`. Refuse
   `http`/`file`/`data`/`blob`/`about`/extension-internal schemes.
2. **Top-frame governs / no cross-origin iframe.** `frame_origin` must match
   `top_origin` under the active binding; if not, **refuse** (D.4.3 has no
   louder per-iframe override yet — that is a later UX add).
3. **Origin match under binding:**
   - `exact_origin` — scheme + host + port of `stored_origin` equals
     `frame_origin` exactly (default ports normalized).
   - `registrable_domain` — eTLD+1(`stored_origin.host`) == eTLD+1(`frame_origin.host`)
     **and both https** (the registrable-domain match still requires §1/§2). A
     host with no registrable domain (bare IP, unknown TLD) never matches under
     this binding — fall back to exact-host equality, never a suffix shortcut.
4. **IDN de-confusion (display-side, recorded in the decision).** The engine
   returns the punycode/ASCII form + a `mixed_script` flag for the dialog (D.4.4)
   to render; matching itself is done on the normalized ASCII host.

No credential-list leak is structural (only a count crosses).

## 4. Layout (additions)

```
browser/secretary-browser-host/
  Cargo.toml                    + psl = "=X.Y.Z" (exact pin, rationale comment), + url
  src/origin.rs                 ParsedOrigin (scheme/host/port, https, ascii host, mixed_script)
  src/origin_match.rs           OriginBinding, MatchDecision, decide() — the pure engine
  src/match_kat.rs              loader + replay test over the pinned corpus
  src/vault.rs                  per_fill_count becomes origin-aware (reads URL field + d4_origin_binding)
  src/config.rs                 + default_binding: OriginBinding
core/tests/data/ … or browser/secretary-browser-host/tests/data/
  origin_match_kat.json         pinned corpus (vectors + expected fill/refuse)
```

(KAT corpus lives under the host crate's `tests/data/` since it is host-specific;
the clean-room cross-check, if added, reads the same JSON.)

## 5. Task breakdown

| Task | Deliverable | Test gate |
|---|---|---|
| **1** | `origin.rs`: parse an origin string into `ParsedOrigin` (scheme, ascii host, port, https flag, mixed-script flag); reject non-hierarchical/opaque schemes. Add `url` dep. | Unit: https/http/file/data parsing; default-port normalization; punycode + mixed-script detection. |
| **2** | `origin_match.rs`: `OriginBinding`, `MatchDecision { fill, reason, display_origin, mixed_script }`, and `decide(top, frame, stored, binding)` implementing §3 rules 1–4 **without PSL** (exact_origin + https-only + top-frame-governs). | Unit: exhaustive rule table for `exact_origin`. |
| **3** | Add `psl = "=X.Y.Z"` (exact pin + comment). Implement `registrable_domain` matching in `decide()` via `psl::domain`; bare-IP / unknown-TLD fall back to exact-host. | Unit: eTLD+1 cases incl. `*.github.io`, `*.co.uk`, IP, unknown TLD. |
| **4** | `origin_match_kat.json` pinned corpus + `match_kat.rs` replay. Vectors cover every §3 rule under both bindings (subdomain, cross-origin iframe, http downgrade, shared-suffix, IDN look-alike). | `cargo test` replays the corpus; **assert vs expected**, no relaxing. |
| **5** | `config.rs`: `default_binding` field (default `registrable_domain`). `vault.rs::per_fill_count`: decrypt blocks, read each record's URL field + `d4_origin_binding` from the record `unknown` map, run `decide`, count fills. | Integration: enrolled golden vault + crafted records → count reflects the query origin (matches vs refuses). |
| **6** | Docs: `browser/README.md` + design pointer; `docs/handoffs/2026-..-d43-shipped.md`; repoint `NEXTSESSION_BROWSER_PLUGIN.md` → D.4.4. Workspace gates green. | clippy `-D warnings`; PSL exact-pin noted. |

Tasks 1–4 are the **pure, self-contained security core** (no vault, no browser)
— the heaviest-reviewed part, fully CI-gated. Task 5 is the vault integration.
Task 6 is docs/handoff.

## 6. Testing strategy

- **Pinned KAT (L1, CI).** `origin_match_kat.json` is the contract; every rule
  is a vector with an expected `{fill|refuse}` + reason. A code change that would
  flip a vector is a deliberate, reviewed corpus edit — never a silent relax
  (CLAUDE.md "Spec is normative … don't fix divergence by changing one side
  silently"). Regenerate only via a documented, human-reviewed diff.
- **PSL pin (CI + review).** `psl` exact-pinned; a bump re-runs the eTLD+1 cases
  and is called out in review (it moves match boundaries).
- **Integration (L2, CI).** Enrolled golden vault + records with crafted URL
  fields/bindings → `per_fill_count` returns the origin-matched count.
- **Clean-room (optional, later).** The same `origin_match_kat.json` can be
  replayed by a stdlib-only Python mirror, extending the repo's
  docs-are-sufficient property to origin matching.

## 7. Definition of Done

1. `cargo test -p secretary-browser-host` (engine unit + KAT replay + integration)
   and `cargo clippy --release --workspace --exclude secretary-desktop --tests --bins -- -D warnings`
   green; `#![forbid(unsafe_code)]` holds.
2. The engine passes the pinned `origin_match_kat.json` (design §12 invariant 5):
   never fills a cross-origin iframe, HTTPS-only, both bindings correct.
3. `per_fill_count` is origin-aware: the count reflects the page, not the whole
   vault.
4. PSL is exact-pinned with a rationale + deliberate-bump review (invariant 8).
5. No on-disk format change — `d4_origin_binding` is read from the record
   `unknown` map (design §6); `golden_vault_001` stays byte-identical.
6. Still no secrets cross the channel — only the count (D.4.4 gates injection).

## 8. What D.4.4 picks up

A host that returns a page-accurate candidate count. D.4.4 adds the genuine user
gesture → the **native** confirmation/picker dialog (outside web content) → a
**single** credential injected into the page DOM — the first slice where any
secret crosses the channel, and only after native approval (design §7).
