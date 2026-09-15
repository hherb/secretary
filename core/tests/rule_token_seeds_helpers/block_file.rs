//! Single-fault `block_file` seeds, planted into
//! `core/fuzz/seeds/block_file/golden.bin` (1 vector-clock entry, 1
//! recipient).
//!
//! Section boundaries come from the real decoders (`decode_header`,
//! `decode_recipient_table`) rather than hand-counted offsets, so a change to
//! the base cannot silently move a planted fault onto a different field. The
//! sort and repeat shapes splice in a two- or three-entry table. That leaves
//! the AAD and signature stale, which neither decoder checks on this target.
//!
//! **Why three-entry tables too, faulted at BOTH pairs.** With two entries a
//! full adjacent scan and a check of the first pair alone are the same
//! function, so a reader checking only `ids[0]` against `ids[1]` stayed
//! conformant against every seed. The `*_second_pair` shapes plant their one
//! fault at the SECOND adjacent pair — disorder with no repeat, or a repeat in
//! otherwise ascending order — the lesson #608's review drew for the
//! manifest's arrays. That alone left the mirror open: every table was then
//! faulted at its LAST pair, so a reader checking only the last pair passed
//! all eight (PR #673 review). The `*_first_pair_of_three` shapes fault the
//! first of three.

use std::mem::size_of;

use secretary_core::crypto::sig::{ED25519_SIG_LEN, ML_DSA_65_SIG_LEN};
use secretary_core::identity::fingerprint::Fingerprint;
use secretary_core::vault::block::{
    decode_header, decode_recipient_table, FILE_KIND_BLOCK, RECIPIENT_ENTRY_LEN,
};
use secretary_core::vault::manifest::RuleToken;
use secretary_core::version::{FORMAT_VERSION, SUITE_ID};

use super::SeedCase;

// §6.1 header prefix: magic (u32), format_version (u16), suite_id (u16),
// file_kind (u16), in that order.
const MAGIC_AT: usize = 0;
const FORMAT_VERSION_AT: usize = size_of::<u32>();
const SUITE_ID_AT: usize = FORMAT_VERSION_AT + size_of::<u16>();
const FILE_KIND_AT: usize = SUITE_ID_AT + size_of::<u16>();
/// Every table count and signature length prefix is a u16.
const U16_LEN: usize = size_of::<u16>();
/// device_uuid (16) || counter (u64).
const VECTOR_CLOCK_ENTRY_LEN: usize = size_of::<Fingerprint>() + size_of::<u64>();
/// author_fingerprint || sig_ed_len || sig_ed || sig_pq_len || sig_pq.
const SIG_SUFFIX_LEN: usize =
    size_of::<Fingerprint>() + U16_LEN + ED25519_SIG_LEN + U16_LEN + ML_DSA_65_SIG_LEN;
/// Two entries whose leading id bytes are these compare strictly, whatever
/// the rest of the id holds.
const LOW_LEAD: u8 = u8::MIN;
const HIGH_LEAD: u8 = u8::MAX;
/// Strictly between the two above, so `[LOW, HIGH, MID]` ascends at its first
/// adjacent pair and descends at its second, and `[MID, LOW, HIGH]` the
/// reverse, with no two ids equal.
const MID_LEAD: u8 = u8::MAX / 2;
/// A byte appended past the signature suffix.
const TRAILING_BYTE: u8 = 0;

/// Where golden.bin's variable sections sit.
struct Layout {
    vc_count_at: usize,
    vc_entries_at: usize,
    vc_len: usize,
    recipient_count_at: usize,
    recipients_at: usize,
    recipients_len: usize,
    sig_suffix_at: usize,
}

fn layout(base: &[u8]) -> Layout {
    let (header, after_header) = decode_header(base).expect("golden block header decodes");
    let header_end = base.len() - after_header.len();
    let vc_len = header.vector_clock.len() * VECTOR_CLOCK_ENTRY_LEN;
    let (recipients, _) =
        decode_recipient_table(after_header).expect("golden recipient table decodes");
    Layout {
        vc_count_at: header_end - vc_len - U16_LEN,
        vc_entries_at: header_end - vc_len,
        vc_len,
        recipient_count_at: header_end,
        recipients_at: header_end + U16_LEN,
        recipients_len: recipients.len() * RECIPIENT_ENTRY_LEN,
        sig_suffix_at: base.len() - SIG_SUFFIX_LEN,
    }
}

fn put_u16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + U16_LEN].copy_from_slice(&value.to_be_bytes());
}

fn u16_of(value: usize) -> u16 {
    u16::try_from(value).expect("the value fits its u16 wire field")
}

/// `base` with the u16-counted table at `count_at` replaced by `entries`.
fn with_table(
    base: &[u8],
    count_at: usize,
    entries_at: usize,
    old_len: usize,
    entries: &[Vec<u8>],
) -> Vec<u8> {
    let mut out = base[..count_at].to_vec();
    out.extend_from_slice(&u16_of(entries.len()).to_be_bytes());
    for entry in entries {
        out.extend_from_slice(entry);
    }
    out.extend_from_slice(&base[entries_at + old_len..]);
    out
}

fn with_lead_byte(entry: &[u8], lead: u8) -> Vec<u8> {
    let mut e = entry.to_vec();
    e[0] = lead;
    e
}

/// `[low, high, mid]`: out of order at the second adjacent pair only.
fn disordered_at_second_pair(entry: &[u8]) -> [Vec<u8>; 3] {
    [
        with_lead_byte(entry, LOW_LEAD),
        with_lead_byte(entry, HIGH_LEAD),
        with_lead_byte(entry, MID_LEAD),
    ]
}

/// `[low, high, high]`: ascending, but repeated at the second adjacent pair.
fn repeated_at_second_pair(entry: &[u8]) -> [Vec<u8>; 3] {
    [
        with_lead_byte(entry, LOW_LEAD),
        with_lead_byte(entry, HIGH_LEAD),
        with_lead_byte(entry, HIGH_LEAD),
    ]
}

/// `[mid, low, high]`: out of order at the first adjacent pair only.
fn disordered_at_first_pair(entry: &[u8]) -> [Vec<u8>; 3] {
    [
        with_lead_byte(entry, MID_LEAD),
        with_lead_byte(entry, LOW_LEAD),
        with_lead_byte(entry, HIGH_LEAD),
    ]
}

/// `[low, low, high]`: ascending, but repeated at the first adjacent pair.
fn repeated_at_first_pair(entry: &[u8]) -> [Vec<u8>; 3] {
    [
        with_lead_byte(entry, LOW_LEAD),
        with_lead_byte(entry, LOW_LEAD),
        with_lead_byte(entry, HIGH_LEAD),
    ]
}

fn vector_clock_entry(base: &[u8], l: &Layout) -> Vec<u8> {
    base[l.vc_entries_at..l.vc_entries_at + VECTOR_CLOCK_ENTRY_LEN].to_vec()
}

fn recipient_entry(base: &[u8], l: &Layout) -> Vec<u8> {
    base[l.recipients_at..l.recipients_at + RECIPIENT_ENTRY_LEN].to_vec()
}

fn bad_magic(base: &[u8]) -> Vec<u8> {
    let mut b = base.to_vec();
    b[MAGIC_AT] ^= u8::MAX;
    b
}

fn wrong_file_kind(base: &[u8]) -> Vec<u8> {
    let mut b = base.to_vec();
    put_u16(&mut b, FILE_KIND_AT, FILE_KIND_BLOCK + 1);
    b
}

fn unsupported_format_version(base: &[u8]) -> Vec<u8> {
    let mut b = base.to_vec();
    put_u16(&mut b, FORMAT_VERSION_AT, FORMAT_VERSION + 1);
    b
}

fn unsupported_suite_id(base: &[u8]) -> Vec<u8> {
    let mut b = base.to_vec();
    put_u16(&mut b, SUITE_ID_AT, SUITE_ID + 1);
    b
}

/// Ends one byte into `vault_uuid`.
fn truncated_header(base: &[u8]) -> Vec<u8> {
    base[..FILE_KIND_AT + U16_LEN + 1].to_vec()
}

/// Ends halfway through the first recipient entry.
fn truncated_recipient_table(base: &[u8]) -> Vec<u8> {
    let l = layout(base);
    base[..l.recipients_at + RECIPIENT_ENTRY_LEN / 2].to_vec()
}

fn zero_recipients(base: &[u8]) -> Vec<u8> {
    let l = layout(base);
    with_table(
        base,
        l.recipient_count_at,
        l.recipients_at,
        l.recipients_len,
        &[],
    )
}

fn wrong_sig_ed_len(base: &[u8]) -> Vec<u8> {
    let l = layout(base);
    let mut b = base.to_vec();
    put_u16(
        &mut b,
        l.sig_suffix_at + size_of::<Fingerprint>(),
        u16_of(ED25519_SIG_LEN - 1),
    );
    b
}

fn wrong_sig_pq_len(base: &[u8]) -> Vec<u8> {
    let l = layout(base);
    let mut b = base.to_vec();
    put_u16(
        &mut b,
        l.sig_suffix_at + size_of::<Fingerprint>() + U16_LEN + ED25519_SIG_LEN,
        u16_of(ML_DSA_65_SIG_LEN - 1),
    );
    b
}

/// Ends halfway through `sig_pq`.
fn truncated_signature_suffix(base: &[u8]) -> Vec<u8> {
    base[..base.len() - ML_DSA_65_SIG_LEN / 2].to_vec()
}

fn trailing_bytes(base: &[u8]) -> Vec<u8> {
    let mut b = base.to_vec();
    b.push(TRAILING_BYTE);
    b
}

fn unsorted_vector_clock(base: &[u8]) -> Vec<u8> {
    let l = layout(base);
    let entry = vector_clock_entry(base, &l);
    let entries = [
        with_lead_byte(&entry, HIGH_LEAD),
        with_lead_byte(&entry, LOW_LEAD),
    ];
    with_table(base, l.vc_count_at, l.vc_entries_at, l.vc_len, &entries)
}

fn repeated_vector_clock(base: &[u8]) -> Vec<u8> {
    let l = layout(base);
    let entry = vector_clock_entry(base, &l);
    with_table(
        base,
        l.vc_count_at,
        l.vc_entries_at,
        l.vc_len,
        &[entry.clone(), entry],
    )
}

fn unsorted_recipients(base: &[u8]) -> Vec<u8> {
    let l = layout(base);
    let entry = recipient_entry(base, &l);
    let entries = [
        with_lead_byte(&entry, HIGH_LEAD),
        with_lead_byte(&entry, LOW_LEAD),
    ];
    with_table(
        base,
        l.recipient_count_at,
        l.recipients_at,
        l.recipients_len,
        &entries,
    )
}

fn repeated_recipients(base: &[u8]) -> Vec<u8> {
    let l = layout(base);
    let entry = recipient_entry(base, &l);
    with_table(
        base,
        l.recipient_count_at,
        l.recipients_at,
        l.recipients_len,
        &[entry.clone(), entry],
    )
}

fn vector_clock_with(base: &[u8], table: fn(&[u8]) -> [Vec<u8>; 3]) -> Vec<u8> {
    let l = layout(base);
    let entries = table(&vector_clock_entry(base, &l));
    with_table(base, l.vc_count_at, l.vc_entries_at, l.vc_len, &entries)
}

fn recipients_with(base: &[u8], table: fn(&[u8]) -> [Vec<u8>; 3]) -> Vec<u8> {
    let l = layout(base);
    let entries = table(&recipient_entry(base, &l));
    with_table(
        base,
        l.recipient_count_at,
        l.recipients_at,
        l.recipients_len,
        &entries,
    )
}

fn vector_clock_disordered_at_second_pair(base: &[u8]) -> Vec<u8> {
    vector_clock_with(base, disordered_at_second_pair)
}

fn vector_clock_repeated_at_second_pair(base: &[u8]) -> Vec<u8> {
    vector_clock_with(base, repeated_at_second_pair)
}

fn recipients_disordered_at_second_pair(base: &[u8]) -> Vec<u8> {
    recipients_with(base, disordered_at_second_pair)
}

fn recipients_repeated_at_second_pair(base: &[u8]) -> Vec<u8> {
    recipients_with(base, repeated_at_second_pair)
}

fn vector_clock_disordered_at_first_pair(base: &[u8]) -> Vec<u8> {
    vector_clock_with(base, disordered_at_first_pair)
}

fn vector_clock_repeated_at_first_pair(base: &[u8]) -> Vec<u8> {
    vector_clock_with(base, repeated_at_first_pair)
}

fn recipients_disordered_at_first_pair(base: &[u8]) -> Vec<u8> {
    recipients_with(base, disordered_at_first_pair)
}

fn recipients_repeated_at_first_pair(base: &[u8]) -> Vec<u8> {
    recipients_with(base, repeated_at_first_pair)
}

pub fn cases() -> Vec<SeedCase> {
    let case = |token: RuleToken,
                shape: &'static str,
                variant: &'static str,
                plant: fn(&[u8]) -> Vec<u8>| SeedCase {
        target: "block_file",
        token,
        shape,
        variant,
        plant,
    };
    use RuleToken::{ArraySortOrder, ContainerMalformed, RepeatedArrayValue, UnsupportedVersion};
    vec![
        case(ContainerMalformed, "bad_magic", "BadMagic", bad_magic),
        case(ContainerMalformed, "wrong_file_kind", "WrongFileKind", wrong_file_kind),
        case(ContainerMalformed, "truncated_header", "Truncated", truncated_header),
        case(
            ContainerMalformed,
            "truncated_recipient_table",
            "Truncated",
            truncated_recipient_table,
        ),
        case(ContainerMalformed, "zero_recipients", "EmptyRecipientList", zero_recipients),
        case(ContainerMalformed, "wrong_sig_ed_len", "SigEdWrongLength", wrong_sig_ed_len),
        case(ContainerMalformed, "wrong_sig_pq_len", "SigPqWrongLength", wrong_sig_pq_len),
        case(
            ContainerMalformed,
            "truncated_signature_suffix",
            "Truncated",
            truncated_signature_suffix,
        ),
        case(ContainerMalformed, "trailing_bytes", "TrailingBytes", trailing_bytes),
        case(
            UnsupportedVersion,
            "format_version",
            "UnsupportedFormatVersion",
            unsupported_format_version,
        ),
        case(UnsupportedVersion, "suite_id", "UnsupportedSuiteId", unsupported_suite_id),
        case(ArraySortOrder, "vector_clock", "VectorClockNotSorted", unsorted_vector_clock),
        case(ArraySortOrder, "recipients", "RecipientsNotSorted", unsorted_recipients),
        case(
            ArraySortOrder,
            "vector_clock_second_pair",
            "VectorClockNotSorted",
            vector_clock_disordered_at_second_pair,
        ),
        case(
            ArraySortOrder,
            "recipients_second_pair",
            "RecipientsNotSorted",
            recipients_disordered_at_second_pair,
        ),
        case(
            ArraySortOrder,
            "vector_clock_first_pair_of_three",
            "VectorClockNotSorted",
            vector_clock_disordered_at_first_pair,
        ),
        case(
            ArraySortOrder,
            "recipients_first_pair_of_three",
            "RecipientsNotSorted",
            recipients_disordered_at_first_pair,
        ),
        case(
            RepeatedArrayValue,
            "vector_clock",
            "VectorClockDuplicateDevice",
            repeated_vector_clock,
        ),
        case(RepeatedArrayValue, "recipients", "DuplicateRecipient", repeated_recipients),
        case(
            RepeatedArrayValue,
            "vector_clock_second_pair",
            "VectorClockDuplicateDevice",
            vector_clock_repeated_at_second_pair,
        ),
        case(
            RepeatedArrayValue,
            "recipients_second_pair",
            "DuplicateRecipient",
            recipients_repeated_at_second_pair,
        ),
        case(
            RepeatedArrayValue,
            "vector_clock_first_pair_of_three",
            "VectorClockDuplicateDevice",
            vector_clock_repeated_at_first_pair,
        ),
        case(
            RepeatedArrayValue,
            "recipients_first_pair_of_three",
            "DuplicateRecipient",
            recipients_repeated_at_first_pair,
        ),
    ]
}
