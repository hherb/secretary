"""Section RTS's check-2 class tables: the Python class each committed
`block_file`, `bundle_file` and `contact_card` seed must be rejected with,
keyed by file stem.

Split out of `rule_token_seeds.py` in the PR #720 review, which would have
taken that module past the 500-line threshold. It defines no `section*`
driver; `rule_token_seeds.py` reads `_SEED_CLASSES` and `_NO_CLASS_TABLE`,
and the module docstring there says why a class is pinned per seed.
"""

from __future__ import annotations


# Check 2: the Python class every `block_file` seed must be rejected with,
# keyed by file stem.  Default-deny: a seed missing here is an issue.  A
# truncation is what `cursor.take` raises, the bare `ParseError`.
_BLOCK_FILE_CLASSES: dict[str, str] = {
    "container_malformed__bad_magic": "EnvelopeBadMagic",
    "container_malformed__bad_magic_below": "EnvelopeBadMagic",
    "container_malformed__wrong_file_kind": "EnvelopeWrongFileKind",
    "container_malformed__wrong_file_kind_below": "EnvelopeWrongFileKind",
    "container_malformed__truncated_header": "ParseError",
    "container_malformed__truncated_recipient_table": "ParseError",
    "container_malformed__zero_recipients": "EnvelopeNoRecipients",
    "container_malformed__wrong_sig_ed_len": "EnvelopeEd25519SignatureLength",
    "container_malformed__wrong_sig_ed_len_above": "EnvelopeEd25519SignatureLength",
    "container_malformed__wrong_sig_pq_len": "EnvelopeMlDsaSignatureLength",
    "container_malformed__wrong_sig_pq_len_above": "EnvelopeMlDsaSignatureLength",
    "container_malformed__aead_ct_len_exceeds_file": "ParseError",
    "container_malformed__truncated_signature_suffix": "ParseError",
    "container_malformed__trailing_bytes": "EnvelopeTrailingBytes",
    "unsupported_version__format_version": "UnsupportedEnvelopeVersion",
    "unsupported_version__format_version_below": "UnsupportedEnvelopeVersion",
    "unsupported_version__suite_id": "UnsupportedEnvelopeVersion",
    "unsupported_version__suite_id_below": "UnsupportedEnvelopeVersion",
    "array_sort_order__vector_clock": "EnvelopeSortOrder",
    "array_sort_order__recipients": "EnvelopeSortOrder",
    "array_sort_order__vector_clock_second_pair": "EnvelopeSortOrder",
    "array_sort_order__recipients_second_pair": "EnvelopeSortOrder",
    "array_sort_order__vector_clock_first_pair_of_three": "EnvelopeSortOrder",
    "array_sort_order__recipients_first_pair_of_three": "EnvelopeSortOrder",
    "repeated_array_value__vector_clock": "EnvelopeRepeatedValue",
    "repeated_array_value__recipients": "EnvelopeRepeatedValue",
    "repeated_array_value__vector_clock_second_pair": "EnvelopeRepeatedValue",
    "repeated_array_value__recipients_second_pair": "EnvelopeRepeatedValue",
    "repeated_array_value__vector_clock_first_pair_of_three": "EnvelopeRepeatedValue",
    "repeated_array_value__recipients_first_pair_of_three": "EnvelopeRepeatedValue",
}

# Check 2: the Python class every `bundle_file` seed must be rejected with
# (#641). Twelve of the fourteen seeds share `container_malformed`, so a raise
# demoted to the bare `ParseError` -- or moved onto a sibling class -- keeps
# its token, and only the class tells it from a truncation. (A DELETED
# `wrap_*_ct_len` check is not the risk: the parse reads a fixed-width field
# next, so the seed is accepted, which the verdict check already reds.)
_BUNDLE_FILE_CLASSES: dict[str, str] = {
    "container_malformed__bad_magic": "EnvelopeBadMagic",
    "container_malformed__bad_magic_below": "EnvelopeBadMagic",
    "container_malformed__wrong_file_kind": "EnvelopeWrongFileKind",
    "container_malformed__truncated_header": "ParseError",
    "container_malformed__wrap_pw_ct_len": "EnvelopeWrapLength",
    "container_malformed__wrap_rec_ct_len": "EnvelopeWrapLength",
    "container_malformed__wrong_file_kind_below": "EnvelopeWrongFileKind",
    "container_malformed__wrap_pw_ct_len_below": "EnvelopeWrapLength",
    "container_malformed__wrap_rec_ct_len_below": "EnvelopeWrapLength",
    "container_malformed__truncated_bundle_ct": "ParseError",
    "container_malformed__bundle_ct_len_exceeds_file": "ParseError",
    "container_malformed__trailing_bytes": "EnvelopeTrailingBytes",
    "unsupported_version__format_version": "UnsupportedEnvelopeVersion",
    "unsupported_version__format_version_below": "UnsupportedEnvelopeVersion",
}

# Check 2 (CRITICAL, fix round 1): the Python class every `contact_card`
# seed must be rejected with, keyed by file stem -- the same default-deny
# discipline `_BLOCK_FILE_CLASSES` gives `block_file`, and for the identical
# reason: `wrong_type` is carried by both `CardWrongType` and
# `CardDisplayNameTooLong`, `malformed_cbor` by both `cbor_faults.MalformedCbor`
# and `cbor_faults.NestingTooDeep`, and `rule4_tag_or_float` entirely by
# `scanner.NonCanonicalItem` (a token check alone cannot tell those apart).
# Before this table, no `contact_card` seed had its Python class checked at
# all -- `_seed_issues`'s class branch fired only `elif target ==
# "block_file"`. Measured cost: repointing `codec/card.py`'s
# `raise CardDisplayNameTooLong(...)` at `CardWrongType` -- deleting
# crypto-design §6's 4096-byte `display_name` bound as a named check --
# left BOTH blocking CI gates (`clean-room conformance`, the gated
# differential replay) green.
_CONTACT_CARD_CLASSES: dict[str, str] = {
    "malformed_cbor__two_byte_simple": "MalformedCbor",
    "malformed_cbor__nested_indefinite_chunk": "MalformedCbor",
    "malformed_cbor__truncated": "MalformedCbor",
    "rule4_tag_or_float__bignum_wide": "NonCanonicalItem",
    "wrong_type__not_a_map": "CardWrongType",
    "wrong_type__non_text_key": "CardWrongType",
    "wrong_type__created_at_text": "CardWrongType",
    "wrong_type__x25519_pk_short": "CardWrongType",
    "wrong_type__display_name_over_cap": "CardDisplayNameTooLong",
    "wrong_type__card_version_text": "CardWrongType",
    "wrong_type__card_version_over_u8": "CardWrongType",
    "wrong_type__card_version_negative": "CardWrongType",
    "wrong_type__created_at_negative": "CardWrongType",
    "missing_field__no_x25519_pk": "CardMissingField",
    "duplicate_map_key__repeated_created_at": "CardDuplicateKey",
    "unknown_field__extra_key": "CardUnknownField",
    "unsupported_version__card_version_two": "CardUnsupportedVersion",
    "non_canonical_unclassified__trailing_bytes": "CardNonCanonical",
    "non_canonical_unclassified__non_shortest_created_at": "CardNonCanonical",
}

# Check 2's per-target class table, keyed by target name (fix round 1): one
# lookup instead of an `elif target == ...` per target, so another
# class-checked target is one dict entry, not a new branch.
#
# DEFAULT-DENY ACROSS TARGETS (#698 review, C2).  This was a bare
# `_SEED_CLASSES.get(target)` whose `None` meant "skip every class assertion
# for this target", so renaming or mistyping one key silently switched off all
# 17 `contact_card` class checks AND `block_file`'s 23 -- restoring the exact
# false green this table was added to close -- while the PASS line, which
# reported seeds LISTED and never classes CHECKED, stayed byte-identical.  A
# target may now be absent only by being declared absent, with its reason.
_SEED_CLASSES: dict[str, dict[str, str]] = {
    "block_file": _BLOCK_FILE_CLASSES,
    "bundle_file": _BUNDLE_FILE_CLASSES,
    "contact_card": _CONTACT_CARD_CLASSES,
}

# Targets deliberately without a class table, each with the reason it needs
# none.  A target in neither mapping is a FAILURE, not a skip.
_NO_CLASS_TABLE: dict[str, str] = {
    "record": (
        "its 37 labelled seeds map one to one onto their tokens (measured), "
        "so a class name would restate the token check"
    ),
}
