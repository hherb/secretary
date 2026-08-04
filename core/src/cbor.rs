//! Data-free classification of `ciborium` codec errors.
//!
//! `ciborium`'s error types implement `Display` as `write!(f, "{:?}", self)` —
//! the **Debug** rendering. `ciborium::de::Error::Semantic(_, String)` and
//! `ciborium::ser::Error::Value(String)` each carry a `serde::de::Error::custom`
//! message, and serde's standard `invalid_type` / `invalid_value` messages embed
//! the offending VALUE. Stringifying such an error into a `core` error variant
//! therefore risks copying decrypted vault plaintext into a message that both
//! platform UIs render and log.
//!
//! Every production `from_reader` call in this crate currently deserializes into
//! `ciborium::value::Value`, which accepts any CBOR item and so cannot raise a
//! value-bearing `Semantic`. **That is a content-traced claim about a
//! third-party crate** — a version bump or a single future typed `from_reader`
//! would invalidate it with no diff near any error definition and no failing
//! test. This module removes the need for the claim: the message is discarded
//! at the boundary, so it cannot reach an error variant regardless of what
//! upstream does.
//!
//! See `docs/superpowers/specs/2026-08-05-474-error-payload-hygiene-design.md`.

use std::fmt;

/// Which upstream codec failure occurred, with no payload of its own.
///
/// A fieldless enum is provably data-free: every value is a compile-time
/// constant, so no runtime content can ride along. This is the same property
/// the Android log guard relies on when it renders a cause chain as
/// fully-qualified type names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CborErrorKind {
    /// The reader or writer returned an I/O error.
    Io,
    /// The byte stream was not well-formed CBOR.
    Syntax,
    /// Nesting exceeded `ciborium`'s recursion limit.
    RecursionLimit,
    /// The decoder rejected a well-formed item on semantic grounds. The
    /// upstream message explaining *which* item is deliberately discarded —
    /// it is the one field in either upstream error that can carry data.
    Semantic,
    /// A value could not be serialized. The upstream description is
    /// discarded for the same reason as [`Self::Semantic`].
    Serialization,
}

impl CborErrorKind {
    /// Fixed human label. `&'static str` by construction.
    fn label(self) -> &'static str {
        match self {
            Self::Io => "CBOR I/O error",
            Self::Syntax => "CBOR syntax error",
            Self::RecursionLimit => "CBOR recursion limit exceeded",
            Self::Semantic => "CBOR semantic error",
            Self::Serialization => "CBOR serialization error",
        }
    }
}

/// A classified `ciborium` failure, carrying no upstream text.
///
/// `offset` is a byte position within the input, kept because it is the single
/// most useful datum when debugging a genuinely corrupt vault.
///
/// **Deliberate residual disclosure:** an offset into decrypted plaintext is a
/// weak length oracle — "duplicate at offset 41" narrows the possible lengths
/// of preceding field names. It is accepted because vault file sizes are
/// already visible on disk to anyone who can read the folder, so the threat
/// model treats plaintext *size* as disclosed. Recorded so the trade is
/// explicit rather than assumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CborFault {
    /// What went wrong.
    pub kind: CborErrorKind,
    /// Byte offset into the input, when the codec reported one.
    pub offset: Option<usize>,
}

impl fmt::Display for CborFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.offset {
            Some(off) => write!(f, "{} at byte offset {off}", self.kind.label()),
            None => write!(f, "{}", self.kind.label()),
        }
    }
}

/// Classify a decode error, discarding any upstream message.
///
/// Generic over the reader's I/O error type because `ciborium::de::Error<E>`
/// is — which is exactly why these were stringified originally (see the
/// pre-existing note on `RecordError::CborEncode`). Projecting to a
/// non-generic `CborFault` sidesteps that without `#[from]`.
pub fn classify_de<E>(e: &ciborium::de::Error<E>) -> CborFault {
    use ciborium::de::Error;
    match e {
        Error::Io(_) => CborFault {
            kind: CborErrorKind::Io,
            offset: None,
        },
        Error::Syntax(off) => CborFault {
            kind: CborErrorKind::Syntax,
            offset: Some(*off),
        },
        // The `String` is intentionally not bound — see the module doc.
        Error::Semantic(off, _) => CborFault {
            kind: CborErrorKind::Semantic,
            offset: *off,
        },
        Error::RecursionLimitExceeded => CborFault {
            kind: CborErrorKind::RecursionLimit,
            offset: None,
        },
    }
}

/// Classify an encode error, discarding any upstream description.
pub fn classify_ser<E>(e: &ciborium::ser::Error<E>) -> CborFault {
    use ciborium::ser::Error;
    match e {
        Error::Io(_) => CborFault {
            kind: CborErrorKind::Io,
            offset: None,
        },
        // The `String` is intentionally not bound — see the module doc.
        Error::Value(_) => CborFault {
            kind: CborErrorKind::Serialization,
            offset: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_de_maps_syntax_to_kind_and_offset() {
        let e: ciborium::de::Error<std::io::Error> = ciborium::de::Error::Syntax(41);
        let fault = classify_de(&e);
        assert_eq!(fault.kind, CborErrorKind::Syntax);
        assert_eq!(fault.offset, Some(41));
    }

    #[test]
    fn classify_de_maps_recursion_limit() {
        let e: ciborium::de::Error<std::io::Error> = ciborium::de::Error::RecursionLimitExceeded;
        let fault = classify_de(&e);
        assert_eq!(fault.kind, CborErrorKind::RecursionLimit);
        assert_eq!(fault.offset, None);
    }

    #[test]
    fn classify_de_maps_io() {
        let e: ciborium::de::Error<std::io::Error> =
            ciborium::de::Error::Io(std::io::Error::other("disk on fire"));
        let fault = classify_de(&e);
        assert_eq!(fault.kind, CborErrorKind::Io);
        assert_eq!(fault.offset, None);
    }

    /// THE test this module exists for. `Semantic`'s `String` is the only
    /// data-bearing field in either upstream error, and serde's standard
    /// `invalid_type` message embeds the offending VALUE. It must not survive
    /// classification, must not appear in `Display`, and must not appear in
    /// `Debug` either — `Debug` is what `{:?}` in an assertion message prints.
    #[test]
    fn classify_de_discards_the_semantic_message() {
        const MARKER: &str = "amex-cvv-4111111111111111";
        let e: ciborium::de::Error<std::io::Error> =
            ciborium::de::Error::Semantic(Some(7), MARKER.to_string());

        let fault = classify_de(&e);

        assert_eq!(fault.kind, CborErrorKind::Semantic);
        assert_eq!(fault.offset, Some(7), "the offset is deliberately kept");
        assert!(
            !format!("{fault}").contains(MARKER),
            "Display leaked the semantic message: {fault}"
        );
        assert!(
            !format!("{fault:?}").contains(MARKER),
            "Debug leaked the semantic message: {fault:?}"
        );
    }

    #[test]
    fn classify_ser_discards_the_value_message() {
        const MARKER: &str = "ex-wife-lawyer-password";
        let e: ciborium::ser::Error<std::io::Error> =
            ciborium::ser::Error::Value(MARKER.to_string());

        let fault = classify_ser(&e);

        assert_eq!(fault.kind, CborErrorKind::Serialization);
        assert!(!format!("{fault}").contains(MARKER));
        assert!(!format!("{fault:?}").contains(MARKER));
    }

    #[test]
    fn classify_ser_maps_io() {
        let e: ciborium::ser::Error<std::io::Error> =
            ciborium::ser::Error::Io(std::io::Error::other("nope"));
        assert_eq!(classify_ser(&e).kind, CborErrorKind::Io);
    }

    #[test]
    fn display_renders_offset_when_present_and_omits_it_when_absent() {
        let with = CborFault {
            kind: CborErrorKind::Syntax,
            offset: Some(12),
        };
        assert_eq!(format!("{with}"), "CBOR syntax error at byte offset 12");

        let without = CborFault {
            kind: CborErrorKind::RecursionLimit,
            offset: None,
        };
        assert_eq!(format!("{without}"), "CBOR recursion limit exceeded");
    }
}
