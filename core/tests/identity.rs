//! Identity integration tests: Contact Card encoding / signing / verification
//! (`docs/crypto-design.md` §6) and the 16-byte fingerprint with its hex and
//! mnemonic presentations (§6.1).
//!
//! Every KAT here cites where its expected value came from. The card / sigs
//! KAT ([`canonical_cbor_byte_kat`]) and the fingerprint KAT
//! ([`fingerprint_kat`]) are the cross-language conformance contract: they
//! are cross-verified against Python `cbor2` (RFC 8949 reference encoder) and
//! the `blake3` Python library, so any clean-room implementation that wants
//! to interop must produce these bytes byte-for-byte.

use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

use secretary_core::crypto::sig::{generate_ed25519, generate_ml_dsa_65, SigError};
use secretary_core::identity::card::{CardError, ContactCard, CARD_VERSION_V1};
use secretary_core::identity::fingerprint::{fingerprint, hex_form, mnemonic_form, Fingerprint};

// ---------------------------------------------------------------------------
// KAT card construction
//
// The same fixed card is rebuilt by Python (see `tests/data/build_kat.py` —
// or rather, the recipe inlined in the session brief that produced
// `card_kat.cbor`). Patterns chosen so that each field is distinguishable in
// a hex dump and exercises a different CBOR length-prefix arm (16, 32, 64,
// 1184, 1952, 3309 bytes).
// ---------------------------------------------------------------------------

fn kat_card() -> ContactCard {
    ContactCard {
        card_version: CARD_VERSION_V1,
        contact_uuid: {
            let mut a = [0u8; 16];
            for (i, b) in a.iter_mut().enumerate() {
                *b = i as u8;
            }
            a
        },
        display_name: "Alice Example".to_string(),
        x25519_pk: {
            let mut a = [0u8; 32];
            for (i, b) in a.iter_mut().enumerate() {
                *b = 0x20 + (i as u8);
            }
            a
        },
        ml_kem_768_pk: (0..1184).map(|i| ((i * 7) % 256) as u8).collect(),
        ed25519_pk: {
            let mut a = [0u8; 32];
            for (i, b) in a.iter_mut().enumerate() {
                *b = 0x80 + (i as u8);
            }
            a
        },
        ml_dsa_65_pk: (0..1952).map(|i| ((i * 13 + 5) % 256) as u8).collect(),
        created_at_ms: 1_714_060_800_000,
        self_sig_ed: [0x55; 64],
        self_sig_pq: (0..3309).map(|i| ((i * 3 + 1) % 256) as u8).collect(),
    }
}

/// Canonical CBOR bytes of [`kat_card`], produced by the Python `cbor2` 5.x
/// reference encoder with insertion-order key emission and shortest-form
/// integer / length encoding. See `docs/crypto-design.md` §6 for the wire
/// shape; `card.rs` module docs for the project's canonicalization rules.
const KAT_CARD_CBOR: &[u8] = include_bytes!("data/card_kat.cbor");

/// Canonical CBOR bytes of `kat_card()` with the two `self_sig_*` fields
/// excluded — i.e., the byte string the §8 hybrid signature commits to
/// (before the §1.3 `TAG_CARD_SIG` role prefix is prepended by `sig::sign`).
const KAT_CARD_PRE_SIG_CBOR: &[u8] = include_bytes!("data/card_kat_signed.cbor");

// ---------------------------------------------------------------------------
// 1. Encode/decode round-trip
// ---------------------------------------------------------------------------

#[test]
fn canonical_cbor_roundtrip() {
    let card = kat_card();
    let bytes = card.to_canonical_cbor().expect("encode");
    let parsed = ContactCard::from_canonical_cbor(&bytes).expect("decode");
    assert_eq!(parsed, card);
}

// ---------------------------------------------------------------------------
// 2. Byte-level KAT — pins our canonical CBOR encoder to the Python `cbor2`
//    reference. Mismatch == encoder drift; do not silence without
//    investigating which side is right.
// ---------------------------------------------------------------------------

#[test]
fn canonical_cbor_byte_kat() {
    let card = kat_card();
    let bytes = card.to_canonical_cbor().expect("encode");
    assert_eq!(
        bytes.as_slice(),
        KAT_CARD_CBOR,
        "canonical CBOR encoding diverges from the Python cbor2 reference",
    );
}

// ---------------------------------------------------------------------------
// 3. signed_bytes excludes the two sig fields — pins the §6 self-signature
//    "without sig fields" rule.
// ---------------------------------------------------------------------------

#[test]
fn signed_bytes_excludes_sig_fields() {
    let mut card = kat_card();
    let with_55 = card.signed_bytes().expect("signed_bytes");
    // Same card, distinguishably different sig fields.
    card.self_sig_ed = [0xAA; 64];
    for (i, b) in card.self_sig_pq.iter_mut().enumerate() {
        *b = (((i * 5) + 7) % 256) as u8;
    }
    let with_aa = card.signed_bytes().expect("signed_bytes");
    assert_eq!(
        with_55, with_aa,
        "signed_bytes must not depend on self_sig_* fields",
    );

    // Also pin against the Python-computed reference for the same card.
    assert_eq!(with_55.as_slice(), KAT_CARD_PRE_SIG_CBOR);
}

// ---------------------------------------------------------------------------
// 4. Sign + verify round-trip with real keypairs
// ---------------------------------------------------------------------------

#[test]
fn card_self_sign_verify_roundtrip() {
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let (ed_sk, ed_pk) = generate_ed25519(&mut rng);
    let (pq_sk, pq_pk) = generate_ml_dsa_65(&mut rng);

    let mut card = kat_card();
    card.ed25519_pk = ed_pk;
    card.ml_dsa_65_pk = pq_pk.as_bytes().to_vec();

    card.sign(&ed_sk, &pq_sk).expect("sign");
    card.verify_self().expect("verify_self");
}

// ---------------------------------------------------------------------------
// 5. Mutating an embedded pk *after* signing breaks verify. Surfaces the
//    specific Ed25519 variant from `SigError`.
// ---------------------------------------------------------------------------

#[test]
fn card_self_verify_fails_on_pk_mismatch() {
    let mut rng = ChaCha20Rng::from_seed([11u8; 32]);
    let (ed_sk, ed_pk) = generate_ed25519(&mut rng);
    let (pq_sk, pq_pk) = generate_ml_dsa_65(&mut rng);

    let mut card = kat_card();
    card.ed25519_pk = ed_pk;
    card.ml_dsa_65_pk = pq_pk.as_bytes().to_vec();
    card.sign(&ed_sk, &pq_sk).expect("sign");

    // Flip a byte in `ml_kem_768_pk`. That field is part of `signed_bytes`
    // but is not the Ed25519 key itself, so verification proceeds past the
    // `EdVerifyingKey::from_bytes` parse step and rejects at the actual
    // signature check — yielding `Ed25519VerifyFailed` deterministically.
    //
    // (Mutating `ed25519_pk` directly would also work in principle, but
    // most random byte flips in an Ed25519-encoded point land on
    // not-on-curve bytes, which surface as `InvalidKeyLength` from the
    // dalek parse step. Choosing a non-key field gives a stable failure
    // mode without losing the "embedded data was tampered with" intent.)
    card.ml_kem_768_pk[0] ^= 0xFF;

    let err = card.verify_self().expect_err("verify_self should fail");
    assert!(
        matches!(
            err,
            CardError::SigVerifyFailed(SigError::Ed25519VerifyFailed)
        ),
        "expected Ed25519VerifyFailed, got {err:?}",
    );
}

// ---------------------------------------------------------------------------
// 5a. Counterpart to test #5: force the ML-DSA-65 verify branch to be the one
//     that rejects, by giving the card a `ml_dsa_65_pk` that does not match
//     the secret key actually used to sign. Ed25519 keys are kept consistent
//     so that Ed25519 verifies first (and succeeds), exposing the PQ branch
//     as the rejecting one. Without this test, a regression that silently
//     skipped the PQ branch in `card.verify_self` would still pass test #5.
// ---------------------------------------------------------------------------

#[test]
fn card_self_verify_fails_on_pq_pk_mismatch() {
    let mut rng = ChaCha20Rng::from_seed([19u8; 32]);
    let (ed_sk, ed_pk) = generate_ed25519(&mut rng);
    let (pq_sk_a, _pq_pk_a) = generate_ml_dsa_65(&mut rng);
    let (_pq_sk_b, pq_pk_b) = generate_ml_dsa_65(&mut rng);

    let mut card = kat_card();
    card.ed25519_pk = ed_pk;
    // Embed pk_b in the card; sign with sk_a. The pq sig will be valid for
    // the message-bytes-including-pk_b (sign is over `signed_bytes()`), but
    // verifying against pk_b rejects — sk_a's verifying key is pk_a.
    card.ml_dsa_65_pk = pq_pk_b.as_bytes().to_vec();
    card.sign(&ed_sk, &pq_sk_a).expect("sign");

    let err = card.verify_self().expect_err("verify_self should fail");
    assert!(
        matches!(
            err,
            CardError::SigVerifyFailed(SigError::MlDsa65VerifyFailed)
        ),
        "expected MlDsa65VerifyFailed, got {err:?}",
    );
}

// ---------------------------------------------------------------------------
// 6. Reject non-v1 cards on parse.
// ---------------------------------------------------------------------------

#[test]
fn card_invalid_version_rejected() {
    let mut card = kat_card();
    card.card_version = 2;
    let bytes = card.to_canonical_cbor().expect("encode");
    let err = ContactCard::from_canonical_cbor(&bytes).expect_err("decode");
    assert!(
        matches!(err, CardError::InvalidVersion),
        "expected InvalidVersion, got {err:?}",
    );
}

// ---------------------------------------------------------------------------
// 6a. Reject non-canonical CBOR on import.
//
// The §6.1 fingerprint is over canonical bytes; if we tolerated non-canonical
// inputs, a peer's published fingerprint could silently desynchronize from a
// locally-recomputed one (parse → re-canonicalize → fingerprint differs).
// Reject on import so OOB verification is meaningful.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 6b. Parser hardening — exercise the `set_once`, `take_*`, and unknown-field
//     branches of `from_canonical_cbor`. Each branch existed before and was
//     reachable in principle, but had no test coverage. A regression that
//     dropped any of these guards would let attackers smuggle data past the
//     decoder.
// ---------------------------------------------------------------------------

#[test]
fn card_parse_rejects_duplicate_keys() {
    use ciborium::Value;
    // Two `display_name` entries; the rest of the map is irrelevant — the
    // parser's `set_once` guard fires on the second occurrence and returns
    // before checking field completeness.
    let entries: Vec<(Value, Value)> = vec![
        (
            Value::Text("display_name".into()),
            Value::Text("Alice".into()),
        ),
        (
            Value::Text("display_name".into()),
            Value::Text("Bob".into()),
        ),
    ];
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&Value::Map(entries), &mut buf).expect("encode");

    let err = ContactCard::from_canonical_cbor(&buf).expect_err("must reject");
    assert!(
        matches!(err, CardError::CborDecode(ref s) if s.contains("duplicate")),
        "expected duplicate-field decode error, got {err:?}",
    );
}

#[test]
fn card_parse_rejects_wrong_field_type() {
    use ciborium::Value;
    // `card_version` arriving as a text string instead of an integer.
    let entries: Vec<(Value, Value)> = vec![(
        Value::Text("card_version".into()),
        Value::Text("not a number".into()),
    )];
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&Value::Map(entries), &mut buf).expect("encode");

    let err = ContactCard::from_canonical_cbor(&buf).expect_err("must reject");
    assert!(
        matches!(err, CardError::CborDecode(ref s) if s.contains("unsigned integer")),
        "expected wrong-type decode error, got {err:?}",
    );
}

#[test]
fn card_parse_rejects_unknown_field() {
    use ciborium::Value;
    // An extra key the spec doesn't define. Decoder must reject — accepting
    // unknown fields would let attackers smuggle data through the canonical
    // re-encoding (or, worse, define a future field that diverges across
    // implementations).
    let entries: Vec<(Value, Value)> = vec![
        (
            Value::Text("card_version".into()),
            Value::Integer(1u64.into()),
        ),
        (
            Value::Text("rogue_field".into()),
            Value::Text("payload".into()),
        ),
    ];
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&Value::Map(entries), &mut buf).expect("encode");

    let err = ContactCard::from_canonical_cbor(&buf).expect_err("must reject");
    assert!(
        matches!(err, CardError::CborDecode(ref s) if s.contains("unknown card field")),
        "expected unknown-field decode error, got {err:?}",
    );
}

#[test]
fn card_from_canonical_cbor_rejects_non_canonical_input() {
    use ciborium::Value;
    let card = kat_card();
    // §6 listing order — NOT canonical (canonical is bytewise lexicographic
    // by encoded key, which puts shorter keys first: x25519_pk (9 chars)
    // sorts before card_version (12 chars)).
    let entries: Vec<(Value, Value)> = vec![
        (
            Value::Text("card_version".into()),
            Value::Integer(u64::from(card.card_version).into()),
        ),
        (
            Value::Text("contact_uuid".into()),
            Value::Bytes(card.contact_uuid.to_vec()),
        ),
        (
            Value::Text("display_name".into()),
            Value::Text(card.display_name.clone()),
        ),
        (
            Value::Text("x25519_pk".into()),
            Value::Bytes(card.x25519_pk.to_vec()),
        ),
        (
            Value::Text("ml_kem_768_pk".into()),
            Value::Bytes(card.ml_kem_768_pk.clone()),
        ),
        (
            Value::Text("ed25519_pk".into()),
            Value::Bytes(card.ed25519_pk.to_vec()),
        ),
        (
            Value::Text("ml_dsa_65_pk".into()),
            Value::Bytes(card.ml_dsa_65_pk.clone()),
        ),
        (
            Value::Text("created_at".into()),
            Value::Integer(card.created_at_ms.into()),
        ),
        (
            Value::Text("self_sig_ed".into()),
            Value::Bytes(card.self_sig_ed.to_vec()),
        ),
        (
            Value::Text("self_sig_pq".into()),
            Value::Bytes(card.self_sig_pq.clone()),
        ),
    ];
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&Value::Map(entries), &mut buf).expect("encode");

    let canonical = card.to_canonical_cbor().expect("canonical encode");
    assert_ne!(
        buf, canonical,
        "test setup error: §6-order bytes must differ from canonical bytes",
    );

    let err = ContactCard::from_canonical_cbor(&buf).expect_err("must reject");
    assert!(
        matches!(err, CardError::NonCanonicalCbor),
        "expected NonCanonicalCbor, got {err:?}",
    );
}

// ---------------------------------------------------------------------------
// 7. Fingerprint KAT — pins the §6.1 BLAKE3-keyed-hash construction against
//    the Python `blake3` reference.
//
//    fp = BLAKE3-keyed-hash(
//        key   = SHA-256("secretary-v1-fingerprint")[..32],
//        input = canonical_cbor(complete_card_including_sigs),
//        out_len = 16,
//    )
// ---------------------------------------------------------------------------

#[test]
fn fingerprint_kat() {
    let card = kat_card();
    let bytes = card.to_canonical_cbor().expect("encode");
    let fp = fingerprint(&bytes);
    let expected: Fingerprint = [
        0x58, 0xa2, 0xa2, 0x1a, 0x4b, 0x8f, 0x8f, 0x57, 0xd3, 0xd1, 0x09, 0xf5, 0x37, 0x8d, 0xa4,
        0xa4,
    ];
    assert_eq!(fp, expected);
}

// ---------------------------------------------------------------------------
// 8. Hex-form KAT — pins lowercase, 4-hex-char groups, single-space
//    separator, 39 chars total.
// ---------------------------------------------------------------------------

#[test]
fn fingerprint_hex_form_kat() {
    // Fixed input chosen for human readability of the formatted output.
    let fp: Fingerprint = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    let s = hex_form(&fp);
    assert_eq!(s, "0001 0203 0405 0607 0809 0a0b 0c0d 0e0f");
    assert_eq!(s.len(), 39);

    // All-zero and all-one boundary cases — the latter checks no off-by-one
    // in group separation at the tail.
    assert_eq!(
        hex_form(&[0u8; 16]),
        "0000 0000 0000 0000 0000 0000 0000 0000",
    );
    assert_eq!(
        hex_form(&[0xffu8; 16]),
        "ffff ffff ffff ffff ffff ffff ffff ffff",
    );
}

// ---------------------------------------------------------------------------
// 9. Mnemonic-form KAT — pins the non-standard 12-word BIP-39 encoding.
//    Cross-verified against Python `mnemonic` package's English wordlist
//    plus our own 11-bit MSB-first reader.
// ---------------------------------------------------------------------------

#[test]
fn fingerprint_mnemonic_kat() {
    // Same input as the hex KAT.
    let fp: Fingerprint = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    let m = mnemonic_form(&fp);
    assert_eq!(
        m,
        "abandon amount liar amount expire adjust cage candy arch gather drum bulk",
    );

    // All-zero → all "abandon" (BIP-39 wordlist[0]). Important boundary case.
    assert_eq!(
        mnemonic_form(&[0u8; 16]),
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
    );

    // All-one boundary: bits 121..127 = 1111111 (= 0x7f), bits 128..131 = 0
    // (the read-only-128-bits zero-pad), so word 11 = 0b11111110000 = 0x7f0
    // = 2032 = "wrap". Word 0..10 see all-ones in their 11-bit windows
    // (= 0x7ff = 2047 = "zoo"). Mismatch here means the bit-reading
    // direction or the zero-padding got flipped.
    assert_eq!(
        mnemonic_form(&[0xffu8; 16]),
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrap",
    );

    // KAT card's own fingerprint → its mnemonic. Cross-verified against
    // Python `mnemonic` package + the canonical-CBOR-encoded KAT card.
    let fp_card: Fingerprint = [
        0x58, 0xa2, 0xa2, 0x1a, 0x4b, 0x8f, 0x8f, 0x57, 0xd3, 0xd1, 0x09, 0xf5, 0x37, 0x8d, 0xa4,
        0xa4,
    ];
    assert_eq!(
        mnemonic_form(&fp_card),
        "flavor bench make novel wedding program exercise cancel vivid round hard elite",
    );
}

// ---------------------------------------------------------------------------
// 10. Different cards → different fingerprints (sanity).
// ---------------------------------------------------------------------------

#[test]
fn fingerprint_changes_with_card() {
    let mut a = kat_card();
    let mut b = kat_card();
    b.display_name = "Bob Example".to_string();

    let fp_a = fingerprint(&a.to_canonical_cbor().expect("encode"));
    let fp_b = fingerprint(&b.to_canonical_cbor().expect("encode"));
    assert_ne!(fp_a, fp_b, "differing display_name must change fingerprint");

    // Also check changing only contact_uuid is detected.
    a.contact_uuid[0] ^= 0xFF;
    let fp_a_mut = fingerprint(&a.to_canonical_cbor().expect("encode"));
    let fp_kat = fingerprint(KAT_CARD_CBOR);
    assert_ne!(fp_a_mut, fp_kat);
}

// ---------------------------------------------------------------------------
// 11. The fingerprint hashes the sig fields too (i.e., includes the full
//     §6 wire form, not just signed_bytes). Pins §6.1 "complete_card_
//     including_sigs".
//
//     We do NOT call sign() here — we just stuff distinguishable byte
//     patterns into both sig fields. The sigs would not verify; the test
//     only checks that the fingerprint sees them.
// ---------------------------------------------------------------------------

#[test]
fn fingerprint_includes_sigs() {
    let a = kat_card();
    let mut b = kat_card();

    // a: default KAT sig values (0x55..., (3i+1) % 256...)
    // b: visibly distinct sig values
    b.self_sig_ed = [0xAA; 64];
    for (i, byte) in b.self_sig_pq.iter_mut().enumerate() {
        *byte = (((i * 5) + 7) % 256) as u8;
    }

    let fp_a = fingerprint(&a.to_canonical_cbor().expect("encode"));
    let fp_b = fingerprint(&b.to_canonical_cbor().expect("encode"));
    assert_ne!(
        fp_a, fp_b,
        "fingerprint must depend on self_sig_* fields (per §6.1)",
    );

    // signed_bytes() must NOT see the sig fields, by contrast — already
    // covered by `signed_bytes_excludes_sig_fields`. Re-assert here as a
    // smoke check that the two functions diverge on the same input.
    assert_eq!(
        a.signed_bytes().expect("signed_bytes"),
        b.signed_bytes().expect("signed_bytes"),
        "signed_bytes must NOT depend on self_sig_* fields",
    );
}
