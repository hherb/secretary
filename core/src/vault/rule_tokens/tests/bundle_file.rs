//! Which token each `BundleFileError` variant carries.

use crate::unlock::bundle_file::BundleFileError;
use crate::vault::manifest::RuleToken;

/// `BundleFileError`'s variant count. A new variant is a compile error in the
/// exhaustive match below first, and a failure of this count second.
const BUNDLE_FILE_ERROR_VARIANTS: usize = 6;

fn every_variant_and_its_token() -> Vec<(BundleFileError, RuleToken)> {
    use RuleToken as T;
    vec![
        (
            BundleFileError::Truncated { offset: 0 },
            T::ContainerMalformed,
        ),
        (
            BundleFileError::TrailingBytes { offset: 0 },
            T::ContainerMalformed,
        ),
        (BundleFileError::BadMagic { got: 0 }, T::ContainerMalformed),
        (
            BundleFileError::UnsupportedFormatVersion(2),
            T::UnsupportedVersion,
        ),
        (
            BundleFileError::UnsupportedFileKind(2),
            T::ContainerMalformed,
        ),
        (
            BundleFileError::WrapLengthMismatch {
                field: "wrap_pw",
                expected: 32,
                declared: 0,
            },
            T::ContainerMalformed,
        ),
    ]
}

#[test]
fn every_bundle_file_error_variant_carries_its_declared_token() {
    let rows = every_variant_and_its_token();
    for (err, want) in &rows {
        assert_eq!(err.rule_token(), *want, "variant {err:?}");
    }

    // Exhaustive: a seventh variant is a COMPILE error here.
    for (err, _) in &rows {
        match err {
            BundleFileError::Truncated { .. }
            | BundleFileError::TrailingBytes { .. }
            | BundleFileError::BadMagic { .. }
            | BundleFileError::UnsupportedFormatVersion(_)
            | BundleFileError::UnsupportedFileKind(_)
            | BundleFileError::WrapLengthMismatch { .. } => (),
        }
    }

    let distinct: std::collections::HashSet<_> = rows
        .iter()
        .map(|(e, _)| std::mem::discriminant(e))
        .collect();
    assert_eq!(
        distinct.len(),
        BUNDLE_FILE_ERROR_VARIANTS,
        "the table covers {} of the {BUNDLE_FILE_ERROR_VARIANTS} BundleFileError variants",
        distinct.len()
    );
}
