# 11. Rollback resistance and integrity

Up to now we've talked mostly about confidentiality — keeping ciphertext from being read. This chapter is about a subtler family of attacks where the attacker may not be able to read your data but *can* meddle with which version of it you see. They are particularly relevant for Secretary because the cloud-folder host is a fully trusted-not-to-snoop adversary, but it can absolutely choose what bytes to give you back.

## The kinds of attacks that don't involve reading

Imagine an attacker who controls your Dropbox folder. They cannot decrypt your vault — confidentiality holds. But they can:

- **Replace** a block file with an older valid version of the same block, hoping to undo a recent change.
- **Replace** the manifest with an older valid version, which would re-add a contact you just removed or restore a block you just deleted.
- **Delete** files entirely, causing data loss.
- **Insert** files that look like they belong but don't.
- **Show** different files to different devices (Alice's laptop sees one thing, her phone sees another), creating a fork in your vault.

None of these attacks require reading the ciphertext. They're attacks on the *state* of your vault, not its contents. And classical encryption doesn't defend against any of them — encrypting the bytes more thoroughly doesn't help when the attacker is choosing *which* encrypted bytes to show you.

A useful analogy: imagine your important documents are in a filing cabinet at a hotel concierge desk. Each document is in a sealed, tamper-evident envelope (encryption + AEAD). The concierge cannot open envelopes, but the concierge can:

- Hand you yesterday's signed contract instead of today's.
- Hand you a completely different person's contract instead of your own.
- Quietly remove a document and pretend it never existed.
- Hand your business partner a different version of the same contract than they hand you.

The cryptographic equivalents are: [rollback](13-glossary.md#rollback), substitution, deletion, and [equivocation](13-glossary.md#equivocation). Each needs its own defense.

## Defense 1: Authenticated state through the manifest

Secretary's first line of defense is the *[Manifest](13-glossary.md#manifest)*. The manifest is the encrypted, signed top-level index of the vault. It says, in effect:

> The current vault contains exactly these blocks: block A with fingerprint X, block B with fingerprint Y, block C with fingerprint Z. It was last written by device D at time T. The vault-level vector clock is V.

The manifest is encrypted (so the attacker can't read it) and *signed* (so the attacker can't tamper with it without detection). Reading any block from the vault is a two-step process:

1. Read the manifest. Verify the signature. Decrypt and read the block list.
2. Read the named block from disk. Compute its fingerprint and compare with the fingerprint recorded in the manifest. If they don't match, reject.

This handles substitution and deletion immediately:

- **Substitution.** If the attacker replaces block file `block-A.dat` with a different file (or with an older valid version of `block-A.dat`), the new file's fingerprint won't match the one recorded in the manifest. The block is rejected.
- **Deletion of a block.** If the attacker removes `block-A.dat` entirely, the manifest still references it. Secretary detects the missing file and surfaces a "vault has been tampered with" warning.
- **Insertion.** If the attacker adds a stray file `block-Q.dat` that isn't listed in the manifest, Secretary ignores it. Files in `blocks/` not enumerated in the manifest are simply not part of the vault.

The manifest is the source of truth. If the manifest says X, X is what the vault contains.

## Defense 2: Rollback at the manifest level

The manifest itself can be rolled back: the attacker substitutes an older valid manifest in place of the current one. The older manifest is still signed (correctly, by you, in the past), so its signature verifies. But it represents a stale state of the vault — perhaps one in which a contact you removed yesterday is still listed, or a block you marked sensitive is missing.

Defending against this requires *something the attacker cannot produce*: a notion of "newer" that the attacker can't fake.

Secretary's mechanism is a **vault-level [vector clock](13-glossary.md#vector-clock)**. The manifest carries a map of `device_uuid → counter`, with one entry per device that has ever modified the vault. Each device increments its own counter when it writes a manifest update. So the vector clock evolves like:

- Day 1: Alice writes a manifest from her laptop. Vector clock: `{laptop: 1}`.
- Day 2: Alice writes from her phone. Vector clock: `{laptop: 1, phone: 1}`.
- Day 3: Alice writes from her laptop again. Vector clock: `{laptop: 2, phone: 1}`.

Each device also keeps, locally, the *highest vector clock it has ever seen* for each vault. This local "high-water mark" is stored in the OS keystore (so it shares the device's tamper resistance) and persists across application restarts.

When a device loads a manifest:

- If the manifest's clock is **at-or-above** the highest seen (component-wise: each component ≥ the corresponding stored component) → accept and update the high-water mark.
- If the manifest's clock is **strictly below** the highest seen → reject as rollback. The UI offers an explicit "I'm restoring from a backup; accept anyway" override.
- If the manifest's clock is **concurrent** (some components higher, some lower) → trigger a merge. The merged manifest's clock is the component-wise max plus one for the merging device.

The result is that an attacker who substitutes an older manifest is detected: the older manifest's clock is dominated by the highest-seen, and the manifest is rejected. The defense is local to each device — the high-water mark is on-device — but each device collectively makes rollback impossible to slip past.

A useful way to think about vector clocks: each device is a witness, and the vector clock is each witness's count of how many times *they* have seen the vault change. The component-wise comparison answers "have I ever seen something newer than this?" If yes, the proposed manifest is older and is rejected.

## Defense 3: Rollback at the per-block level

The same logic applies one level down. Each block file carries its own vector clock, and devices track the highest block-clock seen per (vault, block). An attacker who substitutes an older block file is detected because the older block's clock is dominated.

Combined with the manifest-level fingerprint check, this is overdetermined: substituting a block requires the manifest to also reference the older fingerprint, which requires the manifest to also be rolled back, which requires the manifest's clock to also be older — and the high-water marks make any such rollback visible.

## Limitations: forking and equivocation

There's one rollback-adjacent attack the system *cannot* prevent, only detect. If the cloud-folder host is malicious enough to *equivocate* — to serve Alice's laptop one consistent version of the vault and Alice's phone a *different* consistent version — both versions might be valid (correctly signed by Alice, with non-decreasing vector clocks). The vault has effectively forked, and neither device can tell from its own observations alone.

Detection happens on the next sync. When Alice's laptop and phone next see each other (via the shared folder), each sees a vector clock from the other that is concurrent (incomparable) with its own. Concurrent vector clocks trigger Secretary's merge logic, and during the merge Alice gets a "your vault has forked into two versions" prompt. She can review both and pick a side.

Prevention would require a synchronisation server with a global ordering — exactly the architectural choice Secretary explicitly rejected. Detection-only is the price of being server-free, and it's an acceptable price because the attack requires the cloud-folder host to be actively malicious, not just compromised, and detection happens within the next sync window.

## Why this is a CRDT problem

The data structure that makes all this work is called a **[CRDT](13-glossary.md#crdt)** — Conflict-free Replicated Data Type. The key property is that any two devices, given any two states of the vault, can deterministically merge them into a single agreed-on state, without any coordination. The merge is *commutative* (`merge(A, B) == merge(B, A)`), *associative* (`merge(A, merge(B, C)) == merge(merge(A, B), C)`), and *[idempotent](13-glossary.md#idempotent)* (`merge(A, A) == A`).

These three properties together mean that no matter what order devices observe each other's changes, they all converge on the same final state. There's no "primary" device, no conflict-resolution server, no last-write-wins-and-hope-for-the-best. Just deterministic merge logic that always agrees.

The price is some on-disk overhead: vector clocks, per-field timestamps, *[tombstones](13-glossary.md#tombstone)* (markers that record deletions), and a mechanism Secretary calls the *[death clock](13-glossary.md#death-clock)* that propagates tombstone information across replicas to ensure deletions cannot be silently undone. The full mechanism is in [crypto-design.md §11](../../../crypto-design.md); the user-visible result is "edits and deletes from any of your devices show up correctly on all of them, even when you've been editing offline on multiple devices simultaneously, and even when one of those devices was offline for a while."

## A worked example

To make this concrete: imagine you delete a record on your laptop while offline. Separately, your phone (also offline) edits the same record. Both devices come online and sync to the shared folder.

What happens:

1. Each device writes its updated block to the cloud folder. Both blocks have the same UUID; the vector clocks are now concurrent (laptop's is `{laptop: 5}`, phone's is `{phone: 3}`, neither dominates).
2. The first device to load the other's update detects the concurrency and runs the merge.
3. The merge looks at the deleted record on one side and the edited record on the other. The death-clock mechanism (chapter 11 of [crypto-design.md](../../../crypto-design.md)) ensures that if the deletion and edit are at the *same* logical time, deletion wins — the "tombstone-on-tie" rule. If the edit happens *after* the deletion (the edit's timestamp is higher than the deletion's), the edit is treated as a deliberate undelete and the record is resurrected. (See also [last-writer-wins](13-glossary.md#last-writer-wins).)
4. The resulting merged block has a new vector clock that dominates both inputs, and the manifest is updated to point to the merged block.

All without a server, all deterministically, and all such that any two devices doing the merge in any order produce identical bytes.

## Summary

- Cryptographic encryption alone doesn't protect against an attacker who controls *which* ciphertext you see.
- Secretary's manifest is signed and binds fingerprints of every block, defeating substitution, insertion, and deletion at the block level.
- Vector clocks plus per-device "highest seen" state defeat rollback at both the block and manifest level.
- Equivocation (the cloud host showing different state to different devices) cannot be prevented but is detected within the next sync.
- The merge logic is a CRDT — commutative, associative, idempotent — so all devices converge on the same state without a central coordinator.

The next chapter is the most important one: what cryptography (and Secretary specifically) cannot do.
