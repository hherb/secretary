# `manifest_body` differential regressions

Inputs committed here replay through `core/tests/differential_replay.rs` on
every run under the `differential-replay` feature. `corpus_dirs` picks up
everything in this directory, so a file added here needs no code change.

## `arraysort_plus_indefinite.bin` (#621)

A manifest body that is BOTH out of array sort order and carries an
indefinite-length item — spliced from `arraysort__vector_clock` and
`top__rule2_indefinite_map`, which share a baseline.

```
Rust    -> NonCanonicalEncoding { cause: ArraySortOrder }  -> array_sort_order
Python  -> NonCanonicalItem rule=2                          -> rule2_indefinite_length
```

Both reject, both are conformant, and the tokens differ. It is here as the
**positive control for the tolerance rule** (#634): `docs/vault-format.md`
§4.2 declares the order of the array sort disciplines against §6.2 rules 1-3
unspecified, because the two reader designs §4.2 admits detect them at
different points. `tokens_agree` therefore accepts this pair, and deleting
that tolerance reds this input.

Do NOT "fix" the divergence by making one implementation report the other's
rule. Doing so would require one architecture to detect a rule at a point its
design cannot reach, which is what §4.2's paragraph exists to prevent.
