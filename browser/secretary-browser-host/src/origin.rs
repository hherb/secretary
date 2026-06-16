//! Origin parsing for the matching engine (D.4.3).
//!
//! An origin string (`https://example.com[:port]`) is parsed into a normalized
//! [`ParsedOrigin`]: scheme, **ASCII/punycode** host (lowercased by `url`),
//! known-default-normalized port, and display flags (`is_idn`, `mixed_script`).
//!
//! **Matching is always done on the normalized ASCII host** — an IDN
//! look-alike (`exаmple.com` with a Cyrillic `а`) punycodes to a *different*
//! host than the real `example.com`, so it cannot match. The Unicode/mixed-
//! script info is for the D.4.4 confirmation dialog to render a de-confused
//! target, not for the match decision.

/// A parsed, normalized origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedOrigin {
    /// URL scheme, lowercased (e.g. `"https"`).
    pub scheme: String,
    /// Host in ASCII/punycode form, lowercased (e.g. `"xn--80ak6aa92e.com"`).
    pub host: String,
    /// Port — the explicit port, else the scheme's known default
    /// (443 for https, 80 for http). `None` if neither is known.
    pub port: Option<u16>,
    /// True if any host label is an IDN (`xn--…`) punycode label.
    pub is_idn: bool,
    /// Best-effort homograph flag: the decoded Unicode host mixes more than one
    /// letter script (e.g. Latin + Cyrillic). For display only.
    pub mixed_script: bool,
}

impl ParsedOrigin {
    /// Whether this origin is served over HTTPS.
    pub fn is_https(&self) -> bool {
        self.scheme == "https"
    }
}

/// Why an origin string could not be parsed into a usable origin.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OriginParseError {
    /// The string was not a valid absolute URL.
    #[error("not a valid origin URL: {0}")]
    Invalid(String),
    /// The URL has no host (e.g. `data:`, `about:blank`, `file:///path`).
    #[error("origin has no host")]
    NoHost,
}

/// Parse an origin string into a [`ParsedOrigin`].
///
/// Schemes without a host component (`data:`, `about:`, host-less `file:`)
/// yield [`OriginParseError::NoHost`]; the matching engine treats any parse
/// failure as **refuse**.
pub fn parse_origin(s: &str) -> Result<ParsedOrigin, OriginParseError> {
    let url = url::Url::parse(s).map_err(|e| OriginParseError::Invalid(e.to_string()))?;
    let host = match url.host_str() {
        Some(h) if !h.is_empty() => h.to_string(),
        _ => return Err(OriginParseError::NoHost),
    };
    let is_idn = host.split('.').any(|label| label.starts_with("xn--"));
    let mixed_script = is_idn && decoded_mixes_scripts(&host);
    Ok(ParsedOrigin {
        scheme: url.scheme().to_string(),
        host,
        port: url.port_or_known_default(),
        is_idn,
        mixed_script,
    })
}

/// Letter scripts we distinguish for homograph detection. The classic homograph
/// vectors mix Latin with Cyrillic or Greek look-alikes; other scripts are
/// lumped as `Other` (still counts as a distinct script).
#[derive(PartialEq, Eq, Hash, Clone, Copy)]
enum Script {
    Latin,
    Cyrillic,
    Greek,
    Other,
}

/// Classify a character's script, or `None` for non-letters (digits, `-`, `.`),
/// which are common to all scripts and must not trigger a "mixed" verdict.
fn script_of(c: char) -> Option<Script> {
    if !c.is_alphabetic() {
        return None;
    }
    match c {
        'a'..='z' | 'A'..='Z' => Some(Script::Latin),
        '\u{0400}'..='\u{04FF}' | '\u{0500}'..='\u{052F}' => Some(Script::Cyrillic),
        '\u{0370}'..='\u{03FF}' => Some(Script::Greek),
        _ => Some(Script::Other),
    }
}

/// Decode the punycode host to Unicode and report whether **any single DNS
/// label** mixes more than one letter script. The check is per-label, not
/// whole-host: a Greek second-level label under a Latin `.com` TLD is *not* a
/// homograph (each label is single-script), but `ex<Cyrillic а>mple` is.
fn decoded_mixes_scripts(ascii_host: &str) -> bool {
    let (unicode, _result) = idna::domain_to_unicode(ascii_host);
    unicode.split('.').any(label_mixes_scripts)
}

/// Whether one DNS label mixes more than one letter script.
fn label_mixes_scripts(label: &str) -> bool {
    let mut seen: std::collections::HashSet<Script> = std::collections::HashSet::new();
    for c in label.chars() {
        if let Some(s) = script_of(c) {
            seen.insert(s);
            if seen.len() > 1 {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_https_with_default_port() {
        let o = parse_origin("https://example.com").unwrap();
        assert_eq!(o.scheme, "https");
        assert_eq!(o.host, "example.com");
        assert_eq!(o.port, Some(443));
        assert!(o.is_https());
        assert!(!o.is_idn);
        assert!(!o.mixed_script);
    }

    #[test]
    fn parses_explicit_port() {
        let o = parse_origin("https://example.com:8443").unwrap();
        assert_eq!(o.port, Some(8443));
    }

    #[test]
    fn http_is_not_https() {
        let o = parse_origin("http://example.com").unwrap();
        assert_eq!(o.port, Some(80));
        assert!(!o.is_https());
    }

    #[test]
    fn host_is_lowercased() {
        let o = parse_origin("https://Example.COM").unwrap();
        assert_eq!(o.host, "example.com");
    }

    #[test]
    fn data_and_about_have_no_host() {
        assert_eq!(
            parse_origin("data:text/plain,hi"),
            Err(OriginParseError::NoHost)
        );
        assert_eq!(parse_origin("about:blank"), Err(OriginParseError::NoHost));
    }

    #[test]
    fn hostless_file_url_has_no_host() {
        assert_eq!(
            parse_origin("file:///etc/passwd"),
            Err(OriginParseError::NoHost)
        );
    }

    #[test]
    fn garbage_is_invalid() {
        assert!(matches!(
            parse_origin("not a url"),
            Err(OriginParseError::Invalid(_))
        ));
    }

    #[test]
    fn idn_host_is_punycoded_and_flagged() {
        // Greek "παράδειγμα.com" → an xn-- host. Single-script (Greek) → not mixed.
        let o = parse_origin("https://παράδειγμα.com").unwrap();
        assert!(o.host.starts_with("xn--"), "host = {}", o.host);
        assert!(o.is_idn);
        assert!(!o.mixed_script);
    }

    #[test]
    fn homograph_mixed_script_is_flagged() {
        // "exаmple.com" where the 3rd char is Cyrillic U+0430 (а), the rest Latin.
        let spoof = "ex\u{0430}mple.com";
        let o = parse_origin(&format!("https://{spoof}")).unwrap();
        assert!(
            o.is_idn,
            "a homograph host punycodes to xn-- (host={})",
            o.host
        );
        assert!(
            o.mixed_script,
            "Latin+Cyrillic must be flagged mixed-script"
        );
        // Crucially, it does NOT equal the real example.com host.
        assert_ne!(o.host, "example.com");
    }
}
