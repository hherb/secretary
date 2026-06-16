//! The origin-matching engine (D.4.3) — **the security core**.
//!
//! Pure: given a query's `top_origin` / `frame_origin` and a credential's
//! `stored_origin` + the effective [`OriginBinding`], [`decide`] returns a
//! [`MatchDecision`] of **fill** or **refuse**. No I/O, no vault, no `chrome`.
//! This is what the pinned `origin_match_kat.json` corpus replays and what
//! review focuses on (design §5; threat-model §6).
//!
//! The rules, all of which must hold to fill (else refuse):
//!
//! 1. **HTTPS-only.** Both `top_origin` and `frame_origin` are `https`.
//! 2. **Top-frame governs.** `frame_origin` matches `top_origin` under the
//!    binding — never fill into a cross-origin iframe.
//! 3. **Origin match.** `stored_origin` matches `frame_origin` under the binding
//!    (`exact_origin` = scheme+host+port; `registrable_domain` = same eTLD+1 via
//!    the PSL).
//!
//! Matching runs on the **normalized ASCII host** (so IDN look-alikes can't
//! match); the de-confusion info travels in the decision for the D.4.4 dialog.

use serde::{Deserialize, Serialize};

use crate::origin::{parse_origin, ParsedOrigin};

/// Per-credential (or default) origin-matching policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum OriginBinding {
    /// Match across subdomains of one registrable domain (eTLD+1 via PSL).
    /// The casual-vault default (design §10.6.5).
    #[default]
    RegistrableDomain,
    /// Match scheme + host + port exactly. Tighter; the paranoid choice.
    ExactOrigin,
}

/// Why [`decide`] returned fill or refuse — one per rule, for KAT vectors,
/// logging, and the eventual dialog copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchReason {
    /// All rules held → fill.
    Fill,
    /// Rule 1: the page is not HTTPS.
    NotHttps,
    /// Rule 2: `frame_origin` is a cross-origin iframe relative to `top_origin`.
    CrossOriginIframe,
    /// Rule 3: `stored_origin` does not match `frame_origin` under the binding.
    OriginMismatch,
    /// `frame_origin` or `top_origin` could not be parsed (no host / bad scheme).
    UnparseablePageOrigin,
    /// `stored_origin` could not be parsed.
    UnparseableStoredOrigin,
}

/// The engine's verdict for one (query, credential) pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchDecision {
    /// Whether the credential may be offered for this page.
    pub fill: bool,
    /// The single rule that decided it.
    pub reason: MatchReason,
    /// ASCII host of `frame_origin` for the dialog (empty if unparseable).
    pub display_origin: String,
    /// Whether `frame_origin` is a mixed-script (homograph) host — for the
    /// dialog to flag loudly.
    pub mixed_script: bool,
}

impl MatchDecision {
    fn refuse(reason: MatchReason, frame: Option<&ParsedOrigin>) -> Self {
        Self {
            fill: false,
            reason,
            display_origin: frame.map(|f| f.host.clone()).unwrap_or_default(),
            mixed_script: frame.map(|f| f.mixed_script).unwrap_or(false),
        }
    }
}

/// Decide fill vs refuse for one credential against one page query.
pub fn decide(
    top_origin: &str,
    frame_origin: &str,
    stored_origin: &str,
    binding: OriginBinding,
) -> MatchDecision {
    // Parse the page origins. An unparseable / host-less origin (data:, about:,
    // file:) is an automatic refuse.
    let Ok(frame) = parse_origin(frame_origin) else {
        return MatchDecision::refuse(MatchReason::UnparseablePageOrigin, None);
    };
    let Ok(top) = parse_origin(top_origin) else {
        return MatchDecision::refuse(MatchReason::UnparseablePageOrigin, Some(&frame));
    };

    // Rule 1 — HTTPS-only (both page origins).
    if !frame.is_https() || !top.is_https() {
        return MatchDecision::refuse(MatchReason::NotHttps, Some(&frame));
    }

    // Rule 2 — top-frame governs: never fill into a cross-origin iframe.
    if !origins_match(&top, &frame, binding) {
        return MatchDecision::refuse(MatchReason::CrossOriginIframe, Some(&frame));
    }

    // Rule 3 — the stored credential origin must match the frame under binding.
    let Ok(stored) = parse_origin(stored_origin) else {
        return MatchDecision::refuse(MatchReason::UnparseableStoredOrigin, Some(&frame));
    };
    if !origins_match(&stored, &frame, binding) {
        return MatchDecision::refuse(MatchReason::OriginMismatch, Some(&frame));
    }

    MatchDecision {
        fill: true,
        reason: MatchReason::Fill,
        display_origin: frame.host.clone(),
        mixed_script: frame.mixed_script,
    }
}

/// Page-level affordance gate — rules 1 (HTTPS-only) and 2 (top-frame governs),
/// the subset of [`decide`] that needs **no** stored credential.
///
/// The per-fill count path uses this so an affordance is never surfaced on a
/// non-HTTPS page or inside a cross-origin iframe, even while per-credential
/// origin matching (rule 3 — the bit that makes the *count itself* origin-aware)
/// is still deferred to D.4.3 task 5. HTTPS is derived from the **parsed**
/// origins, never from the extension's advisory `https` flag.
///
/// This mirrors the rule-1 / rule-2 logic in [`decide`]; the
/// `page_gate_agrees_with_decide` test pins the two together so they cannot
/// drift.
pub fn page_affordance_allowed(
    top_origin: &str,
    frame_origin: &str,
    binding: OriginBinding,
) -> bool {
    let (Ok(frame), Ok(top)) = (parse_origin(frame_origin), parse_origin(top_origin)) else {
        return false;
    };
    frame.is_https() && top.is_https() && origins_match(&top, &frame, binding)
}

/// Whether two parsed origins match under `binding`. Used for both the
/// top-vs-frame (rule 2) and stored-vs-frame (rule 3) comparisons.
fn origins_match(a: &ParsedOrigin, b: &ParsedOrigin, binding: OriginBinding) -> bool {
    match binding {
        OriginBinding::ExactOrigin => a.scheme == b.scheme && a.host == b.host && a.port == b.port,
        OriginBinding::RegistrableDomain => {
            match (registrable_domain(&a.host), registrable_domain(&b.host)) {
                // Same eTLD+1 → same site (subdomains included).
                (Some(ra), Some(rb)) => ra == rb,
                // No registrable domain (bare IP, unknown TLD): never use a
                // suffix shortcut — fall back to exact-host equality.
                _ => a.host == b.host,
            }
        }
    }
}

/// The registrable domain (eTLD+1) of an ASCII host, via the embedded PSL.
/// `None` for a bare IP or a host whose TLD is not in the list.
fn registrable_domain(host: &str) -> Option<&str> {
    psl::domain_str(host)
}

#[cfg(test)]
mod tests {
    use super::OriginBinding::{ExactOrigin, RegistrableDomain};
    use super::*;

    fn fills(top: &str, frame: &str, stored: &str, b: OriginBinding) -> bool {
        decide(top, frame, stored, b).fill
    }

    // ── exact_origin ────────────────────────────────────────────────────────

    #[test]
    fn exact_same_origin_fills() {
        assert!(fills(
            "https://example.com",
            "https://example.com",
            "https://example.com",
            ExactOrigin
        ));
    }

    #[test]
    fn exact_subdomain_does_not_fill() {
        // login.example.com is a different exact origin than example.com.
        assert!(!fills(
            "https://login.example.com",
            "https://login.example.com",
            "https://example.com",
            ExactOrigin
        ));
    }

    #[test]
    fn exact_different_port_does_not_fill() {
        assert!(!fills(
            "https://example.com:8443",
            "https://example.com:8443",
            "https://example.com",
            ExactOrigin
        ));
    }

    #[test]
    fn exact_default_port_normalizes() {
        // explicit :443 == implicit default for https.
        assert!(fills(
            "https://example.com:443",
            "https://example.com:443",
            "https://example.com",
            ExactOrigin
        ));
    }

    // ── registrable_domain ──────────────────────────────────────────────────

    #[test]
    fn registrable_subdomain_fills() {
        // stored example.com fills on login.example.com (same eTLD+1).
        assert!(fills(
            "https://login.example.com",
            "https://login.example.com",
            "https://example.com",
            RegistrableDomain
        ));
    }

    #[test]
    fn registrable_co_uk_etld_plus_one() {
        assert!(fills(
            "https://www.example.co.uk",
            "https://www.example.co.uk",
            "https://example.co.uk",
            RegistrableDomain
        ));
    }

    #[test]
    fn registrable_github_io_is_its_own_domain() {
        // a.github.io and b.github.io are DIFFERENT registrable domains
        // (github.io is a PSL private suffix) — must NOT cross-fill.
        assert!(!fills(
            "https://a.github.io",
            "https://a.github.io",
            "https://b.github.io",
            RegistrableDomain
        ));
    }

    #[test]
    fn registrable_different_site_does_not_fill() {
        assert!(!fills(
            "https://example.com",
            "https://example.com",
            "https://evil.com",
            RegistrableDomain
        ));
    }

    // ── rule 1: https-only ──────────────────────────────────────────────────

    #[test]
    fn http_page_refuses() {
        let d = decide(
            "http://example.com",
            "http://example.com",
            "http://example.com",
            ExactOrigin,
        );
        assert!(!d.fill);
        assert_eq!(d.reason, MatchReason::NotHttps);
    }

    #[test]
    fn non_http_schemes_refuse() {
        for page in ["file:///x", "data:text/html,x", "about:blank"] {
            let d = decide(page, page, "https://example.com", RegistrableDomain);
            assert!(!d.fill, "{page} must refuse");
            assert_eq!(d.reason, MatchReason::UnparseablePageOrigin);
        }
    }

    // ── rule 2: top-frame governs ───────────────────────────────────────────

    #[test]
    fn cross_origin_iframe_refuses_exact() {
        // page is example.com, but the frame is evil.com → refuse.
        let d = decide(
            "https://example.com",
            "https://evil.com",
            "https://evil.com",
            ExactOrigin,
        );
        assert!(!d.fill);
        assert_eq!(d.reason, MatchReason::CrossOriginIframe);
    }

    #[test]
    fn cross_site_iframe_refuses_registrable() {
        let d = decide(
            "https://example.com",
            "https://evil.com",
            "https://example.com",
            RegistrableDomain,
        );
        assert!(!d.fill);
        assert_eq!(d.reason, MatchReason::CrossOriginIframe);
    }

    #[test]
    fn same_site_subdomain_iframe_allowed_registrable() {
        // top example.com, frame login.example.com (same eTLD+1), stored
        // example.com → fills under registrable_domain.
        let d = decide(
            "https://example.com",
            "https://login.example.com",
            "https://example.com",
            RegistrableDomain,
        );
        assert!(d.fill, "got {d:?}");
    }

    #[test]
    fn subdomain_iframe_refused_exact() {
        // under exact_origin a subdomain iframe is cross-origin.
        let d = decide(
            "https://example.com",
            "https://login.example.com",
            "https://login.example.com",
            ExactOrigin,
        );
        assert!(!d.fill);
        assert_eq!(d.reason, MatchReason::CrossOriginIframe);
    }

    // ── rule 3 + homograph ──────────────────────────────────────────────────

    #[test]
    fn stored_unparseable_refuses() {
        let d = decide(
            "https://example.com",
            "https://example.com",
            "not a url",
            ExactOrigin,
        );
        assert!(!d.fill);
        assert_eq!(d.reason, MatchReason::UnparseableStoredOrigin);
    }

    #[test]
    fn homograph_frame_does_not_match_real_stored() {
        // Cyrillic-а spoof of example.com must not match the real example.com.
        let spoof = "https://ex\u{0430}mple.com";
        let d = decide(spoof, spoof, "https://example.com", RegistrableDomain);
        assert!(!d.fill, "homograph must not match");
        assert!(d.mixed_script, "decision carries the homograph flag");
    }

    // ── page_affordance_allowed (rules 1+2, no stored credential) ────────────

    #[test]
    fn page_gate_allows_https_same_origin() {
        assert!(page_affordance_allowed(
            "https://example.com",
            "https://example.com",
            RegistrableDomain
        ));
    }

    #[test]
    fn page_gate_allows_same_site_subdomain_iframe_registrable() {
        assert!(page_affordance_allowed(
            "https://example.com",
            "https://login.example.com",
            RegistrableDomain
        ));
    }

    #[test]
    fn page_gate_refuses_http_page() {
        assert!(!page_affordance_allowed(
            "http://example.com",
            "http://example.com",
            RegistrableDomain
        ));
    }

    #[test]
    fn page_gate_refuses_cross_origin_iframe() {
        assert!(!page_affordance_allowed(
            "https://example.com",
            "https://evil.com",
            RegistrableDomain
        ));
    }

    #[test]
    fn page_gate_refuses_unparseable_origin() {
        assert!(!page_affordance_allowed(
            "about:blank",
            "about:blank",
            RegistrableDomain
        ));
    }

    /// The gate is the page-level subset (rules 1+2) of `decide`: whenever the
    /// gate refuses, `decide` must also refuse for *any* stored origin (it can
    /// never reach the fill path). This pins the two so they cannot drift.
    #[test]
    fn page_gate_agrees_with_decide() {
        let cases = [
            ("https://example.com", "https://example.com"), // allowed
            ("http://example.com", "http://example.com"),   // not https
            ("https://example.com", "https://evil.com"),    // cross-origin iframe
            ("about:blank", "about:blank"),                 // unparseable
            ("https://example.com", "https://login.example.com"), // same-site iframe
        ];
        for (top, frame) in cases {
            for binding in [ExactOrigin, RegistrableDomain] {
                let gate = page_affordance_allowed(top, frame, binding);
                if !gate {
                    // A refused page can never fill, regardless of stored origin.
                    let d = decide(top, frame, frame, binding);
                    assert!(
                        !d.fill,
                        "gate refused ({top}, {frame}, {binding:?}) but decide filled: {d:?}"
                    );
                }
            }
        }
    }
}
