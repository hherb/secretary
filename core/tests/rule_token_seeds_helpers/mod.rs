//! The committed single-fault seeds for the token-compared `record`,
//! `block_file` (#641) and `contact_card` (#691, #694) replay targets, and
//! the ONE table the generator and the label-binding check both read.
//!
//! **Why generated.** CI replays only committed inputs. Before #641 these
//! two targets held four, all ACCEPTING, so a strict token comparison on
//! them would have compared nothing in CI.
//!
//! **Why label-bound.** A corpus whose bytes are not bound to their labels
//! can collapse silently (#614's review measured it). A seed's file name is
//! DERIVED from its row, and the check regenerates every row and requires the
//! committed bytes to match, so a label and its bytes cannot disagree.
//!
//! **Why each seed plants ONE fault.** `docs/vault-format.md` §6.1/§6.3 fix
//! no report order for `record`/`block_file`, and `docs/crypto-design.md` §6
//! fixes none for `contact_card` either (#618's lesson, restated for the
//! card); a committed row must not pin an order the spec leaves open. A
//! planted fault can have a downstream consequence — an `undefined` value
//! also fails the re-encode — but both implementations meet the planted
//! fault first.

use std::path::PathBuf;

use secretary_core::vault::manifest::RuleToken;

pub mod block_file;
pub mod contact_card;
pub mod record;

/// One committed seed.
pub struct SeedCase {
    /// The replay target whose seed directory holds this file.
    pub target: &'static str,
    /// The rule BOTH decoders must name for this seed.
    pub token: RuleToken,
    /// What was planted, as a file-name-safe label unique within `token`.
    pub shape: &'static str,
    /// The Rust error VARIANT the decoder must raise, as its `Debug` name.
    ///
    /// The token alone is coarser than the check a shape names. Nine
    /// `container_malformed` shapes span seven `BlockError` variants, so a
    /// raise site that names a sibling variant, or a plant that drifts onto a
    /// sibling's fault, still names the row's token: swapping
    /// `SigEdWrongLength` for `Truncated` reds only this column (PR #673
    /// review). Section RTS pins the Python half by class name, where deleting
    /// the `sig_ed_len` check had left every token check green.
    pub variant: &'static str,
    /// Build the seed from the target's committed accepting base.
    pub plant: fn(&[u8]) -> Vec<u8>,
}

/// How the Rust decoder rejected a seed.
#[derive(Debug, PartialEq)]
pub struct RustRejection {
    pub token: RuleToken,
    /// The error's `Debug` variant name, e.g. `BadMagic`.
    pub variant: String,
}

/// Separates a seed's token from its shape in its file name. No token and no
/// accepting base file name contains it.
pub const LABEL_SEPARATOR: &str = "__";

/// A seed's file extension. The replay reads every file in the directory
/// whatever its extension; this only makes the files recognisable.
const SEED_EXTENSION: &str = "bin";

impl SeedCase {
    pub fn file_name(&self) -> String {
        format!(
            "{}{LABEL_SEPARATOR}{}.{SEED_EXTENSION}",
            self.token.as_str(),
            self.shape
        )
    }

    pub fn path(&self) -> PathBuf {
        seed_dir(self.target).join(self.file_name())
    }

    pub fn bytes(&self) -> Vec<u8> {
        (self.plant)(&base(self.target))
    }
}

/// `core/fuzz/seeds/<target>/`.
pub fn seed_dir(target: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz/seeds")
        .join(target)
}

/// The committed ACCEPTING input each target's seeds are planted into.
pub fn base(target: &str) -> Vec<u8> {
    let name = match target {
        "block_file" => "golden.bin",
        "record" => "login.cbor",
        "contact_card" => "with_sigs.cbor",
        other => panic!("no seed base for target {other}"),
    };
    let path = seed_dir(target).join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read seed base {}: {e}", path.display()))
}

/// How the Rust decoder rejects `bytes`, or `None` if it accepts.
///
/// A copy of the decode → re-encode pipeline
/// `differential_replay_helpers::rust_decoder` runs for the target. Nothing
/// ties the two together: `rust_decoder` belongs to the `differential_replay`
/// test target, which requires the `differential-replay` feature and which
/// this target does not import, so a change to one arm must be mirrored in
/// the other by hand.
pub fn rust_rejection(target: &str, bytes: &[u8]) -> Option<RustRejection> {
    use secretary_core::identity::card::ContactCard;
    use secretary_core::vault::{block, record};
    match target {
        "block_file" => block::decode_block_file(bytes)
            .and_then(|f| block::encode_block_file(&f))
            .err()
            .map(|e| RustRejection {
                token: e.rule_token(),
                variant: variant_name(&e),
            }),
        "record" => record::decode(bytes)
            .and_then(|r| record::encode(&r))
            .err()
            .map(|e| RustRejection {
                token: e.rule_token(),
                variant: variant_name(&e),
            }),
        "contact_card" => ContactCard::from_canonical_cbor(bytes)
            .and_then(|c| c.to_canonical_cbor())
            .err()
            .map(|e| RustRejection {
                token: e.rule_token(),
                variant: variant_name(&e),
            }),
        other => panic!("no Rust decoder for target {other}"),
    }
}

/// The variant name a derived `Debug` prints first: `BadMagic { .. }` and
/// `CborDecode(..)` give `BadMagic` and `CborDecode`.
fn variant_name(error: &impl std::fmt::Debug) -> String {
    format!("{error:?}")
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect()
}

/// Every case, in a stable order.
pub fn all_cases() -> Vec<SeedCase> {
    let mut cases = block_file::cases();
    cases.extend(record::cases());
    cases.extend(contact_card::cases());
    cases
}
