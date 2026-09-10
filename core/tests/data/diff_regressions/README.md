# Differential-replay regression corpus

Each subdirectory here (`vault_toml/`, `record/`, `contact_card/`,
`bundle_file/`, `manifest_file/`, `manifest_body/`, `block_file/`) is one
target's committed corpus of long-running regression inputs, consumed by
`core/tests/differential_replay.rs`'s `differential_replay_full_corpus`
(gated behind the `differential-replay` Cargo feature). Per
[`docs/manual/contributors/differential-replay-protocol.md`](../../../../docs/manual/contributors/differential-replay-protocol.md),
"If the disagreement is sticky and you need a long-running regression
artefact, drop the offending input as a file in
`core/tests/data/diff_regressions/<target>/<descriptive-name>.bin` and
commit it." — this is that drop location.

## Nothing but corpus bytes and `.gitkeep` may live in a `<target>/` directory

`corpus_dirs` (`core/tests/differential_replay_helpers/corpus.rs`) returns
each of these subdirectories, one per target, and
`differential_replay_full_corpus`'s walk is a plain, non-recursive
`fs::read_dir` over whatever it finds there. **Every file it sees is fed to
both decoders as raw input bytes for that target — the only filename it
skips is `.gitkeep`, matched literally.** There is no extension filter.

This bit #634's own fixture: a `README.md` committed alongside
`manifest_body/arraysort_plus_indefinite.bin` was decoded by both languages
as manifest-body bytes, and because its rejection carried no rule token on
the Python side, the harness reported a failure rather than the disagreement
the fixture exists to demonstrate. Do not repeat this. Documentation for a
`<target>/` directory's fixtures belongs at THIS level (i.e. in this file),
never inside the directory the walker scans. A directory that carries no
regression fixture yet holds only a `.gitkeep`, for the same reason.

This file itself sits one level above every `<target>/` directory, so it is
never joined onto a target path (`corpus_dirs` always calls
`.join(target)`) and is never read by the loop above.

## `manifest_body/arraysort_plus_indefinite.bin` (#621, #634)

A manifest body that is BOTH out of array sort order and carries an
indefinite-length item — spliced from the fuzz seeds `arraysort__vector_clock`
and `top__rule2_indefinite_map`, which share a baseline.

```
Rust    -> NonCanonicalEncoding { cause: ArraySortOrder }  -> array_sort_order
Python  -> NonCanonicalItem rule=2                          -> rule2_indefinite_length
```

Both reject, both are conformant, and the tokens differ. It is here as the
**positive control for the tolerance rule** (#634): `docs/vault-format.md`
§4.2 declares the order of the array sort disciplines against §6.2 rules 1-3
unspecified, because the two reader designs §4.2 admits detect them at
different points. `tokens_agree`
(`core/tests/differential_replay.rs`) therefore accepts this pair, and
deleting that tolerance reds this input — before this fixture existed, the
tolerance had no witness among committed bytes and the comparison passed
vacuously.

Do NOT "fix" the divergence by making one implementation report the other's
rule. Doing so would require one architecture to detect a rule at a point its
design cannot reach, which is what §4.2's paragraph exists to prevent.
