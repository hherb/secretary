# ADR 0004 — Block = unit of encryption AND sharing, holding 1+ records

**Status:** Accepted (2026-04-25)
**Supersedes:** none
**Superseded by:** none

## Context

The vault must support:
- Encrypting groups of records as units (so changing one record does not require re-encrypting the whole vault).
- Sharing individual records or groups of records with other users (e.g., a family member).
- Sync conflict granularity that doesn't produce whole-vault conflicts on every edit.

Three sub-questions follow:
- Is "a record" or "a group of records" the storage unit?
- Are sharing units distinct from storage units?
- Who decides group membership — the user, or the system algorithmically?

Alternatives considered:

1. **One block per record.** Maximum sync granularity. Reveals exact record count to the cloud-folder host. Sharing per-record is natural. Many tiny files; potentially thousands.
2. **User-defined groups, blocks ≠ records.** User creates groups for organization; storage and sharing are separate concerns and can each have their own granularity.
3. **Algorithmic bucketing.** Records hashed into N fixed buckets. Hides count partially. Bucket assignment is automatic, so user-controlled sharing semantics break.
4. **One block = one user-defined group of 1+ records, AND blocks are also the unit of sharing.**

## Decision

Adopt option 4. A *block* is:
- the unit of encryption (one *Block Content Key* per block),
- the unit of sharing (one set of recipients per block),
- a user-defined collection of 1 or more records.

A record always lives in exactly one block. "Single-record sharing" is just "a block with one record." User-defined groups are "blocks with several records." This collapses what would otherwise be three concepts (storage units, sharing units, organizational groups) into one.

Cross-cutting *tags* may be added later as a separate metadata mechanism that doesn't affect storage. They live on individual records.

## Consequences

**Positive:**
- Simpler core: one schema, one merge algorithm, one share mechanism.
- The user's mental model is straightforward: "this folder of records" maps directly to "this file on disk." Sharing maps to "send this file."
- Sync conflicts are scoped to one block at a time, which the user understands as "the folder I was editing on my phone."
- Per-block crypto-suite migration is naturally supported — old blocks under suite v1 coexist with new blocks under suite v2.
- Block boundaries are user-controlled, so users with strong preferences (one block per record) can configure that, while users wanting fewer files (one block per category) get that.

**Negative:**
- Concurrent edits to records in the same block produce a block-level conflict, requiring CRDT-style record-level merge. Implementation is more complex than file-per-record (where conflicts simply do not arise).
- Moving a record between blocks is non-trivial: decrypt source, encrypt new record in target, delete from source — three writes that must complete or be rolled back.
- A block shared with someone gives that recipient access to *every* record in the block. Splitting / reorganizing blocks becomes a sharing decision: "if I add this record to Family-block, my family now sees it." UI must make this consequence obvious.

**Risks:**
- Users may create very large blocks (hundreds of records), making conflict-resolution UI cumbersome. Mitigation: warn at e.g. 100 records per block, suggesting splitting. (No hard limit; users can override.)
- The "block name in plaintext within encrypted manifest" decision means users with sensitive block names (e.g., "Affair") have no defense if the manifest is ever decrypted, but this is consistent with the rest of the data — if the manifest decrypts, everything decrypts. Not a meaningful additional leak.

## Revisit when

- User research on the deployed product shows confusion about the block / record / sharing relationship. May warrant a UX rethink (separating "share this record" from "this record's storage block") that keeps the underlying format unchanged.
- A v2 format that supports cross-cutting tags as a first-class concept would not need to revisit this ADR — tags are additive.
