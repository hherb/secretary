//! The Rust half of the replay: decode one corpus input, re-encode it, and on
//! rejection carry the rule token `differential_replay_full_corpus` compares.
//!
//! Split out of `differential_replay.rs` (#649) as the mirror of
//! [`super::python_bridge`], and because it is the other part #641 edits:
//! giving a target a token means filling `token` in that target's arm below.

/// A Rust-side rejection: the token `differential_replay` compares, plus the
/// `Debug` rendering for the failure message.
///
/// `token` is `None` only for targets whose error type has no `rule_token()`
/// yet (#641). For a token-compared target a `None` here is a harness
/// failure, never agreement.
pub struct RustRejection {
    pub token: Option<&'static str>,
    pub detail: String,
}

/// Re-encode one fuzz-corpus input through the Rust decoder for that target.
///
/// Returns [`SecretBytes`](secretary_core::crypto::secret::SecretBytes), not
/// `Vec<u8>`. The `"record"` arm's output is a canonical re-encoding of a
/// decrypted record — every field value it holds — and `record::encode`
/// returns `SecretBytes` by construction as of #558/#565 precisely so that
/// no caller can hold it unwrapped. Unwrapping here with
/// `.expose().to_vec()` to satisfy the old `Vec<u8>` signature would
/// reintroduce exactly the buffer that change eliminates, in a harness whose
/// whole job is replaying a corpus of decoded records — so the wrapper is
/// threaded through the signature instead.
///
/// Five of the other six arms wrap too — `manifest_body`, added later, is
/// the second arm that does not, for the reason its own comment below
/// gives. Their outputs are not decrypted plaintext
/// (a `ContactCard` is the artifact handed to other users; the three `*_file`
/// encoders emit on-disk forms whose bodies are already AEAD ciphertext), so
/// wrapping them buys nothing directly — but a uniform return type keeps the
/// one arm that *does* matter from being the odd one out, which is how it
/// came to be unwrapped in the first place.
pub fn rust_decode(
    target: &str,
    bytes: &[u8],
) -> Result<secretary_core::crypto::secret::SecretBytes, RustRejection> {
    use secretary_core::crypto::secret::SecretBytes;
    use secretary_core::*;
    match target {
        "vault_toml" => {
            let s = std::str::from_utf8(bytes).map_err(|e| RustRejection {
                token: None,
                detail: format!("utf8: {}", e),
            })?;
            unlock::vault_toml::decode(s)
                .map(|_| SecretBytes::new(Vec::new())) // crash-only target; no roundtrip compare
                .map_err(|e| RustRejection {
                    token: None,
                    detail: format!("{:?}", e),
                })
        }
        "record" => vault::record::decode(bytes)
            .and_then(|r| vault::record::encode(&r))
            .map_err(|e| RustRejection {
                token: Some(e.rule_token().as_str()),
                detail: format!("{:?}", e),
            }),
        "contact_card" => identity::card::ContactCard::from_canonical_cbor(bytes)
            .and_then(|c| c.to_canonical_cbor())
            .map(SecretBytes::new)
            .map_err(|e| RustRejection {
                token: Some(e.rule_token().as_str()),
                detail: format!("{:?}", e),
            }),
        "bundle_file" => unlock::bundle_file::decode(bytes)
            .map(|f| SecretBytes::new(unlock::bundle_file::encode(&f)))
            .map_err(|e| RustRejection {
                token: None,
                detail: format!("{:?}", e),
            }),
        // NOTE: this arm fills `token`, but `manifest_file` is in
        // `NOT_TOKEN_COMPARED_TARGETS`, so the value is only ever printed in a
        // failure message — it is a diagnostic, not coverage. #640 explains why
        // the target cannot be compared and #641 tracks the other five.
        "manifest_file" => vault::manifest::decode_manifest_file(bytes)
            .and_then(|f| vault::manifest::encode_manifest_file(&f))
            .map(SecretBytes::new)
            .map_err(|e| RustRejection {
                token: Some(e.rule_token().as_str()),
                detail: format!("{:?}", e),
            }),
        // Unlike `manifest_file` above, `encode_manifest` already returns
        // `SecretBytes` (the manifest *body*, §4.2/§4.3, is decrypted
        // plaintext) — so this arm needs no `SecretBytes::new` wrap, the
        // same reason the "record" arm above has none.
        "manifest_body" => vault::manifest::decode_manifest(bytes)
            .and_then(|m| vault::manifest::encode_manifest(&m))
            .map_err(|e| RustRejection {
                token: Some(e.rule_token().as_str()),
                detail: format!("{:?}", e),
            }),
        "block_file" => vault::block::decode_block_file(bytes)
            .and_then(|f| vault::block::encode_block_file(&f))
            .map(SecretBytes::new)
            .map_err(|e| RustRejection {
                token: Some(e.rule_token().as_str()),
                detail: format!("{:?}", e),
            }),
        _ => panic!("unknown target {}", target),
    }
}
