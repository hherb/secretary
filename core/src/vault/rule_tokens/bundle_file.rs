//! [`BundleFileError::rule_token`] (#641).
//!
//! Lives here rather than in `unlock/bundle_file.rs` for consistency with its
//! three siblings: every `rule_token()` impl sits in `rule_tokens/` beside a
//! second, independent declaration of its mapping in `tests/`.

use crate::unlock::bundle_file::BundleFileError;
use crate::vault::manifest::RuleToken;

impl BundleFileError {
    /// Which rule this rejection is reporting, as a language-neutral token
    /// shared with `conformance.py` (#641).
    ///
    /// **Exhaustive by construction**: a new variant fails to compile until
    /// it is classified, for the reason
    /// [`RecordError::rule_token`](crate::vault::record::RecordError::rule_token)
    /// gives.
    ///
    /// The §3 envelope is a fixed binary layout read by offset, so every
    /// fault but the version is a container fault. The split matches
    /// [`BlockError::rule_token`](crate::vault::block::BlockError::rule_token)'s
    /// §6.1 envelope arms: a wrong format version is `unsupported_version`
    /// (a reader of a later format would accept the file), anything else is
    /// `container_malformed`.
    pub fn rule_token(&self) -> RuleToken {
        match self {
            BundleFileError::UnsupportedFormatVersion(_) => RuleToken::UnsupportedVersion,
            BundleFileError::Truncated { .. }
            | BundleFileError::TrailingBytes { .. }
            | BundleFileError::BadMagic { .. }
            | BundleFileError::UnsupportedFileKind(_)
            | BundleFileError::WrapLengthMismatch { .. } => RuleToken::ContainerMalformed,
        }
    }
}
