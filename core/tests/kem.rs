//! Hybrid-KEM integration tests (`docs/crypto-design.md` §7).
//!
//! KATs come in three layers:
//!   1. Underlying primitives — RFC 7748 X25519 vector, ML-KEM-768
//!      deterministic round-trip — these prove the wrapped crates work as
//!      expected.
//!   2. Pure helpers — `transcript` (BLAKE3) and `derive_wrap_key` (HKDF)
//!      cross-verified against independent Python implementations.
//!   3. End-to-end — round-trip plus five tampering negatives that pin the
//!      §7.2 binding properties.

use ml_kem::{array::Array, EncapsulateDeterministic, EncodedSizeUser, KemCore, MlKem768, B32};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

mod common;
use common::{load_kat, HybridKemKat, X25519Kat};

use secretary_core::crypto::kem::{
    decap, derive_wrap_key, encap, generate_ml_kem_768, generate_x25519, transcript, HybridWrap,
    KemError, MlKem768Public, MlKem768Secret, ML_KEM_768_CT_LEN, ML_KEM_768_PK_LEN,
    ML_KEM_768_SK_LEN, ML_KEM_768_SS_LEN,
};
use secretary_core::crypto::secret::Sensitive;

// ---------------------------------------------------------------------------
// Tiny hex helper (mirrors the one in tests/kdf.rs — no external dep).
// ---------------------------------------------------------------------------

fn hex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd-length hex string");
    let mut out = Vec::with_capacity(s.len() / 2);
    for chunk in s.as_bytes().chunks(2) {
        out.push((nib(chunk[0]) << 4) | nib(chunk[1]));
    }
    out
}

fn nib(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("non-hex char"),
    }
}

fn hex32(s: &str) -> [u8; 32] {
    let v = hex(s);
    assert_eq!(v.len(), 32, "expected 32-byte hex");
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

// ---------------------------------------------------------------------------
// 1. Underlying X25519 primitive — RFC 7748 §5.2 single-iteration vector.
//
// This is the published test vector for the bare `x25519(k, u)` function. We
// use it indirectly: the `kem` module's `generate_x25519`/`decap` flow uses
// the typed `StaticSecret`/`PublicKey` API, which is documented to be a
// thin wrapper over `x25519` with the same semantics. Pinning the vector
// here proves the underlying crate is wired correctly.
// ---------------------------------------------------------------------------

#[test]
fn x25519_kat_rfc7748() {
    // RFC 7748 §5.2 vectors loaded from tests/data/x25519_kat.json.
    use x25519_dalek::x25519;
    let kat: X25519Kat = load_kat("x25519_kat.json");
    assert!(!kat.vectors.is_empty(), "no X25519 vectors");
    for v in &kat.vectors {
        let k: [u8; 32] = v.k.as_slice().try_into().expect("k = 32 B");
        let u: [u8; 32] = v.u.as_slice().try_into().expect("u = 32 B");
        let expected: [u8; 32] = v.expected.as_slice().try_into().expect("expected = 32 B");
        assert_eq!(x25519(k, u), expected, "vector {}", v.name);
    }
}

// ---------------------------------------------------------------------------
// 2. Underlying ML-KEM-768 primitive — deterministic generate + encap +
//    round-trip, plus size pinning against §14.
//
// The crate exposes a deterministic encap (`encapsulate_deterministic`), so
// repeating the call with the same `(d, z, m)` triple must yield the same
// ciphertext byte-for-byte. We don't pin a literal ciphertext value here
// because cross-verification would require an independent ML-KEM-768
// implementation; the determinism + round-trip + size assertions together
// are strong enough evidence the wrapped crate works as expected. NIST
// FIPS 203 KATs would tighten this further and are a future hardening item.
// ---------------------------------------------------------------------------

#[test]
fn ml_kem_768_deterministic_kat() {
    let d: B32 = Array([0xAAu8; 32]);
    let z: B32 = Array([0xBBu8; 32]);
    let m: B32 = Array([0xCCu8; 32]);

    let (dk, ek) = MlKem768::generate_deterministic(&d, &z);

    // Size pinning against §14.
    let ek_bytes = ek.as_bytes();
    let dk_bytes = dk.as_bytes();
    assert_eq!(ek_bytes.as_slice().len(), ML_KEM_768_PK_LEN);
    assert_eq!(dk_bytes.as_slice().len(), ML_KEM_768_SK_LEN);

    // Deterministic encap.
    let (ct1, ss1) = ek.encapsulate_deterministic(&m).unwrap();
    assert_eq!(ct1.as_slice().len(), ML_KEM_768_CT_LEN);
    assert_eq!(ss1.as_slice().len(), ML_KEM_768_SS_LEN);

    // Same inputs → same outputs (the meaning of "deterministic").
    let (ct2, ss2) = ek.encapsulate_deterministic(&m).unwrap();
    assert_eq!(ct1.as_slice(), ct2.as_slice());
    assert_eq!(ss1.as_slice(), ss2.as_slice());

    // Round-trip.
    use ml_kem::kem::Decapsulate;
    let ss_recv = dk.decapsulate(&ct1).unwrap();
    assert_eq!(ss1.as_slice(), ss_recv.as_slice());
}

// ---------------------------------------------------------------------------
// 3. Transcript KAT — fixed inputs cross-verified against the `blake3`
//    Python package via `uv run --with blake3`.
// ---------------------------------------------------------------------------

#[test]
fn transcript_kat() {
    let sender_fp = [0x01u8; 16];
    let recipient_fp = [0x02u8; 16];
    let ct_x = [0x03u8; 32];
    let ct_pq = vec![0x04u8; 1088];

    let expected = hex32("afe8e32ad55b441369da17fe4c87b84e6ca2a502f732cb6255447e0e0a2cfacc");
    let got = transcript(&sender_fp, &recipient_fp, &ct_x, &ct_pq);
    assert_eq!(got, expected);
}

// ---------------------------------------------------------------------------
// 4. derive_wrap_key KAT — fixed inputs cross-verified against the
//    `cryptography` Python package's HKDF-SHA-256 (independent from the
//    `hkdf` Rust crate this code uses).
// ---------------------------------------------------------------------------

#[test]
fn derive_wrap_key_kat() {
    let ss_x: Sensitive<[u8; 32]> = Sensitive::new([0x05u8; 32]);
    let ss_pq: Sensitive<[u8; 32]> = Sensitive::new([0x06u8; 32]);
    let ct_x = [0x03u8; 32];
    let ct_pq = vec![0x04u8; 1088];
    let sender_pk_bundle = [0x07u8; 16];
    let recipient_pk_bundle = [0x08u8; 16];
    let transcript_h = [0x09u8; 32];

    let expected = hex32("dec63452c0a05b22b7a2765ffe3f2e612c87ad9d09069ce01bc8b8311aae32bb");
    let got = derive_wrap_key(
        &ss_x,
        &ss_pq,
        &ct_x,
        &ct_pq,
        &sender_pk_bundle,
        &recipient_pk_bundle,
        &transcript_h,
    );
    assert_eq!(got.expose()[..], expected[..]);
}

// ---------------------------------------------------------------------------
// 5–10: end-to-end round-trip and tampering negatives.
//
// Helper: build a fully populated recipient setup from a seeded RNG. Returns
// the keypair pair plus the canonical fingerprints and pk-bundle bytes used
// in encap/decap. Real-world callers will source these from the bundle and
// signature modules; for KEM-level tests we just use distinguishable opaque
// bytes.
// ---------------------------------------------------------------------------

struct Recipient {
    fp: [u8; 16],
    pk_bundle: Vec<u8>,
    x_sk: Sensitive<[u8; 32]>,
    x_pk: [u8; 32],
    pq_sk: MlKem768Secret,
    pq_pk: MlKem768Public,
}

fn make_recipient(seed: u64, fp_byte: u8, bundle_byte: u8) -> Recipient {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let (x_sk, x_pk) = generate_x25519(&mut rng);
    let (pq_sk, pq_pk) = generate_ml_kem_768(&mut rng);
    Recipient {
        fp: [fp_byte; 16],
        // Opaque bundle bytes — KEM module never parses these (see §7.2).
        // Pretend they're canonical CBOR of the four pk fields.
        pk_bundle: vec![bundle_byte; 64],
        x_sk,
        x_pk,
        pq_sk,
        pq_pk,
    }
}

fn fresh_block_content_key(seed: u64) -> Sensitive<[u8; 32]> {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    use rand_core::RngCore;
    let mut k = [0u8; 32];
    rng.fill_bytes(&mut k);
    Sensitive::new(k)
}

fn do_encap(
    rng_seed: u64,
    sender: &Recipient,
    recipient: &Recipient,
    block_uuid: &[u8; 16],
    bck: &Sensitive<[u8; 32]>,
) -> HybridWrap {
    let mut rng = ChaCha20Rng::seed_from_u64(rng_seed);
    encap(
        &mut rng,
        &sender.fp,
        &recipient.fp,
        &sender.pk_bundle,
        &recipient.pk_bundle,
        &recipient.x_pk,
        &recipient.pq_pk,
        block_uuid,
        bck,
    )
    .expect("encap should succeed against well-formed inputs")
}

#[test]
fn hybrid_kem_roundtrip() {
    let sender = make_recipient(101, 0xA1, 0xB1);
    let recipient = make_recipient(202, 0xA2, 0xB2);
    let block_uuid = [0x11u8; 16];
    let bck = fresh_block_content_key(303);

    let wrap = do_encap(404, &sender, &recipient, &block_uuid, &bck);

    // Sanity: wrap field sizes.
    assert_eq!(wrap.ct_x.len(), 32);
    assert_eq!(wrap.ct_pq.len(), ML_KEM_768_CT_LEN);
    assert_eq!(wrap.nonce_w.len(), 24);
    assert_eq!(wrap.ct_w.len(), 32 + 16); // K + Poly1305 tag

    let recovered = decap(
        &wrap,
        &sender.fp,
        &recipient.fp,
        &sender.pk_bundle,
        &recipient.pk_bundle,
        &recipient.x_sk,
        &recipient.pq_sk,
        &block_uuid,
    )
    .expect("decap should round-trip the same K");

    assert_eq!(recovered.expose(), bck.expose());
}

#[test]
fn hybrid_kem_wrong_recipient_fails() {
    let sender = make_recipient(101, 0xA1, 0xB1);
    let recipient_a = make_recipient(202, 0xA2, 0xB2);
    let recipient_b = make_recipient(303, 0xA3, 0xB3); // different keys *and* fp/bundle
    let block_uuid = [0x22u8; 16];
    let bck = fresh_block_content_key(404);

    let wrap = do_encap(505, &sender, &recipient_a, &block_uuid, &bck);

    // Recipient B cannot decap a wrap addressed to recipient A. We pass B's
    // fp/bundle/sks throughout, which is what a wrong recipient would
    // actually try.
    let err = decap(
        &wrap,
        &sender.fp,
        &recipient_b.fp,
        &sender.pk_bundle,
        &recipient_b.pk_bundle,
        &recipient_b.x_sk,
        &recipient_b.pq_sk,
        &block_uuid,
    )
    .expect_err("wrong recipient must fail");
    assert!(matches!(err, KemError::AeadFailure(_)), "got {err:?}");
}

#[test]
fn hybrid_kem_tampered_ct_x_fails() {
    let sender = make_recipient(101, 0xA1, 0xB1);
    let recipient = make_recipient(202, 0xA2, 0xB2);
    let block_uuid = [0x33u8; 16];
    let bck = fresh_block_content_key(606);

    let mut wrap = do_encap(707, &sender, &recipient, &block_uuid, &bck);
    wrap.ct_x[0] ^= 0x01;

    let err = decap(
        &wrap,
        &sender.fp,
        &recipient.fp,
        &sender.pk_bundle,
        &recipient.pk_bundle,
        &recipient.x_sk,
        &recipient.pq_sk,
        &block_uuid,
    )
    .expect_err("tampered ct_x must fail");
    assert!(matches!(err, KemError::AeadFailure(_)), "got {err:?}");
}

#[test]
fn hybrid_kem_tampered_ct_pq_fails() {
    let sender = make_recipient(101, 0xA1, 0xB1);
    let recipient = make_recipient(202, 0xA2, 0xB2);
    let block_uuid = [0x44u8; 16];
    let bck = fresh_block_content_key(808);

    let mut wrap = do_encap(909, &sender, &recipient, &block_uuid, &bck);
    wrap.ct_pq[0] ^= 0x01;

    let err = decap(
        &wrap,
        &sender.fp,
        &recipient.fp,
        &sender.pk_bundle,
        &recipient.pk_bundle,
        &recipient.x_sk,
        &recipient.pq_sk,
        &block_uuid,
    )
    .expect_err("tampered ct_pq must fail");
    assert!(matches!(err, KemError::AeadFailure(_)), "got {err:?}");
}

#[test]
fn hybrid_kem_tampered_pk_bundle_fails() {
    // The §7.2 binding property: changing either pk_bundle (without changing
    // the underlying KEM keys) still produces a different wrap key, hence
    // AEAD failure.
    let sender = make_recipient(101, 0xA1, 0xB1);
    let recipient = make_recipient(202, 0xA2, 0xB2);
    let block_uuid = [0x55u8; 16];
    let bck = fresh_block_content_key(1010);

    let wrap = do_encap(1111, &sender, &recipient, &block_uuid, &bck);

    let mut tampered_recipient_bundle = recipient.pk_bundle.clone();
    tampered_recipient_bundle[0] ^= 0x01;

    let err = decap(
        &wrap,
        &sender.fp,
        &recipient.fp,
        &sender.pk_bundle,
        &tampered_recipient_bundle,
        &recipient.x_sk,
        &recipient.pq_sk,
        &block_uuid,
    )
    .expect_err("tampered recipient_pk_bundle must fail (proves §7.2 binding)");
    assert!(matches!(err, KemError::AeadFailure(_)), "got {err:?}");
}

// ---------------------------------------------------------------------------
// Section 7.2 binding — symmetric counterpart to `hybrid_kem_tampered_pk_bundle
// _fails`. The HKDF input includes BOTH `sender_pk_bundle` and
// `recipient_pk_bundle`; tampering with either must reject. Without this test
// an implementation that only mixed `recipient_pk_bundle` into the HKDF
// input would silently break sender-side §7.2 binding.
// ---------------------------------------------------------------------------

#[test]
fn hybrid_kem_tampered_sender_pk_bundle_fails() {
    let sender = make_recipient(101, 0xA1, 0xB1);
    let recipient = make_recipient(202, 0xA2, 0xB2);
    let block_uuid = [0xAAu8; 16];
    let bck = fresh_block_content_key(2020);

    let wrap = do_encap(2121, &sender, &recipient, &block_uuid, &bck);

    let mut tampered_sender_bundle = sender.pk_bundle.clone();
    tampered_sender_bundle[0] ^= 0x01;

    let err = decap(
        &wrap,
        &sender.fp,
        &recipient.fp,
        &tampered_sender_bundle,
        &recipient.pk_bundle,
        &recipient.x_sk,
        &recipient.pq_sk,
        &block_uuid,
    )
    .expect_err("tampered sender_pk_bundle must fail (proves §7.2 binding)");
    assert!(matches!(err, KemError::AeadFailure(_)), "got {err:?}");
}

// ---------------------------------------------------------------------------
// §7 step 3 transcript binds both fingerprints. Tamper either → wrap key
// derived by decap differs from the one encap used → AEAD rejects. Without
// these tests an implementation that dropped either fingerprint from the
// transcript hash would still pass.
// ---------------------------------------------------------------------------

#[test]
fn hybrid_kem_tampered_sender_fingerprint_fails() {
    let sender = make_recipient(101, 0xA1, 0xB1);
    let recipient = make_recipient(202, 0xA2, 0xB2);
    let block_uuid = [0xBBu8; 16];
    let bck = fresh_block_content_key(3030);

    let wrap = do_encap(3131, &sender, &recipient, &block_uuid, &bck);

    let mut tampered_sender_fp = sender.fp;
    tampered_sender_fp[0] ^= 0x01;

    let err = decap(
        &wrap,
        &tampered_sender_fp,
        &recipient.fp,
        &sender.pk_bundle,
        &recipient.pk_bundle,
        &recipient.x_sk,
        &recipient.pq_sk,
        &block_uuid,
    )
    .expect_err("tampered sender fingerprint must fail (transcript binding)");
    assert!(matches!(err, KemError::AeadFailure(_)), "got {err:?}");
}

#[test]
fn hybrid_kem_tampered_recipient_fingerprint_fails() {
    let sender = make_recipient(101, 0xA1, 0xB1);
    let recipient = make_recipient(202, 0xA2, 0xB2);
    let block_uuid = [0xCCu8; 16];
    let bck = fresh_block_content_key(4040);

    let wrap = do_encap(4141, &sender, &recipient, &block_uuid, &bck);

    let mut tampered_recipient_fp = recipient.fp;
    tampered_recipient_fp[0] ^= 0x01;

    let err = decap(
        &wrap,
        &sender.fp,
        &tampered_recipient_fp,
        &sender.pk_bundle,
        &recipient.pk_bundle,
        &recipient.x_sk,
        &recipient.pq_sk,
        &block_uuid,
    )
    .expect_err("tampered recipient fingerprint must fail (transcript binding)");
    assert!(matches!(err, KemError::AeadFailure(_)), "got {err:?}");
}

// ---------------------------------------------------------------------------
// FIPS 203 ML-KEM implicit rejection: a malformed `ct_pq` produces a
// pseudorandom shared secret rather than an error. The right end-to-end
// behaviour is that the wrong shared secret derives a wrong wrap key and the
// AEAD tag fails — i.e., we see `KemError::AeadFailure`, never
// `KemError::MlKemDecapsFailed`. Pinning this distinguishes "AEAD caught it"
// from "ML-KEM crashed" — a regression that flipped on explicit rejection
// would surface here and be diagnostically clearer than `tampered_ct_pq_fails`
// alone, which only asserts "some kind of AeadFailure."
// ---------------------------------------------------------------------------

#[test]
fn hybrid_kem_ml_kem_implicit_rejection_flows_to_aead_failure() {
    let sender = make_recipient(101, 0xA1, 0xB1);
    let recipient = make_recipient(202, 0xA2, 0xB2);
    let block_uuid = [0xDDu8; 16];
    let bck = fresh_block_content_key(5050);

    let mut wrap = do_encap(5151, &sender, &recipient, &block_uuid, &bck);
    // Wholesale-replace ct_pq with random-looking bytes. ML-KEM-768 implicit
    // rejection means decap returns *some* shared secret, but not the one
    // encap produced — so the AEAD wrap key is wrong, AEAD tag fails.
    for (i, b) in wrap.ct_pq.iter_mut().enumerate() {
        *b = ((i as u32 * 31 + 17) & 0xFF) as u8;
    }

    let err = decap(
        &wrap,
        &sender.fp,
        &recipient.fp,
        &sender.pk_bundle,
        &recipient.pk_bundle,
        &recipient.x_sk,
        &recipient.pq_sk,
        &block_uuid,
    )
    .expect_err("malformed ct_pq must surface as AEAD failure (implicit rejection)");
    // Specifically NOT MlKemDecapsFailed — implicit rejection means ML-KEM
    // returned a value, AEAD caught the divergence.
    assert!(
        matches!(err, KemError::AeadFailure(_)),
        "expected AeadFailure (implicit rejection flowing through), got {err:?}",
    );
}

#[test]
fn hybrid_kem_wrong_block_uuid_fails() {
    let sender = make_recipient(101, 0xA1, 0xB1);
    let recipient = make_recipient(202, 0xA2, 0xB2);
    let block_uuid_a = [0x66u8; 16];
    let block_uuid_b = [0x77u8; 16];
    let bck = fresh_block_content_key(1212);

    let wrap = do_encap(1313, &sender, &recipient, &block_uuid_a, &bck);

    let err = decap(
        &wrap,
        &sender.fp,
        &recipient.fp,
        &sender.pk_bundle,
        &recipient.pk_bundle,
        &recipient.x_sk,
        &recipient.pq_sk,
        &block_uuid_b,
    )
    .expect_err("wrong block_uuid must fail (it's bound in AAD)");
    assert!(matches!(err, KemError::AeadFailure(_)), "got {err:?}");
}

// ---------------------------------------------------------------------------
// Hybrid KEM wire-byte KAT — pins the §7 wrap output for fixed seeds and
// inputs. Loaded from tests/data/hybrid_kem_kat.json. A clean-room
// implementation that wants to interop must reproduce these wire bytes
// byte-for-byte.
// ---------------------------------------------------------------------------

#[test]
fn hybrid_kem_wire_kat() {
    let kat: HybridKemKat = load_kat("hybrid_kem_kat.json");

    let sender_seed: [u8; 32] = kat.sender_seed.as_slice().try_into().expect("seed = 32 B");
    let recipient_seed: [u8; 32] = kat
        .recipient_seed
        .as_slice()
        .try_into()
        .expect("seed = 32 B");
    let encap_seed: [u8; 32] = kat.encap_seed.as_slice().try_into().expect("seed = 32 B");
    let sender_fp: [u8; 16] = kat.sender_fp.as_slice().try_into().expect("fp = 16 B");
    let recipient_fp: [u8; 16] = kat.recipient_fp.as_slice().try_into().expect("fp = 16 B");
    let block_uuid: [u8; 16] = kat.block_uuid.as_slice().try_into().expect("uuid = 16 B");
    let bck_arr: [u8; 32] = kat.bck.as_slice().try_into().expect("bck = 32 B");

    // Recipient generates its own keys; we only need its public half here
    // (encap path). Sender keys are generated to consume the same RNG
    // sequence as a real sender would; we discard the values.
    let mut rng_s = ChaCha20Rng::from_seed(sender_seed);
    let _ = generate_x25519(&mut rng_s);
    let _ = generate_ml_kem_768(&mut rng_s);

    let mut rng_r = ChaCha20Rng::from_seed(recipient_seed);
    let (_r_x_sk, r_x_pk) = generate_x25519(&mut rng_r);
    let (_r_pq_sk, r_pq_pk): (_, MlKem768Public) = generate_ml_kem_768(&mut rng_r);

    let bck = Sensitive::new(bck_arr);
    let mut rng_e = ChaCha20Rng::from_seed(encap_seed);
    let wrap = encap(
        &mut rng_e,
        &sender_fp,
        &recipient_fp,
        &kat.sender_bundle,
        &kat.recipient_bundle,
        &r_x_pk,
        &r_pq_pk,
        &block_uuid,
        &bck,
    )
    .expect("encap");

    assert_eq!(
        wrap.ct_x.as_slice(),
        kat.expected_wire.ct_x,
        "ct_x mismatch"
    );
    assert_eq!(wrap.ct_pq, kat.expected_wire.ct_pq, "ct_pq mismatch");
    assert_eq!(
        wrap.nonce_w.as_slice(),
        kat.expected_wire.nonce_w,
        "nonce_w mismatch"
    );
    assert_eq!(wrap.ct_w, kat.expected_wire.ct_w, "ct_w mismatch");
}
