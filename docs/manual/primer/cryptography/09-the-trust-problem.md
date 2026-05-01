# 9. The trust problem

Cryptography reduces every secrecy problem to a key problem. If you have the right key, you can read; if you don't, you can't. This chapter is about a question cryptography cannot answer on its own: **how do you know you have the right public key for the person you think you're talking to?**

This is the single hardest problem in decentralised cryptographic systems. It's the reason secure messaging apps have "verify safety number" features. It's the reason https web browsing works at all (it depends on a global infrastructure of certificate authorities). It's the reason PGP, despite being sound cryptography, never reached mass adoption. And it's the one place in Secretary where the design hands the problem back to you and asks for a few minutes of careful work.

## Why the problem exists

Imagine Alice wants to share a vault block with her sister Bob. Alice has Bob's *Contact Card*, which contains Bob's public keys. Alice encrypts the block under those public keys and writes it to a shared cloud folder.

Now consider an attacker — call them Eve — who controls the cloud folder, or the email Alice received the card by, or any other channel through which the card travelled. Eve replaces Bob's real card with a card she crafted herself: same name, same display photo, but the public keys belong to *Eve*, not to Bob. Alice imports the card believing it's Bob's. Alice encrypts the block under Eve's keys. Eve, who is sitting on the cloud folder, decrypts everything with her secret keys.

Bob never knew anything happened. Alice never knew anything happened. The cryptography did its job perfectly: the block was encrypted to whoever owned the keys in the card. The problem is that Alice trusted the wrong card.

The cryptographic name for this is a *[Man-in-the-Middle](13-glossary.md#mitm)* (MITM) attack on key exchange. It's not specific to Secretary — every system that relies on public keys faces it. The interesting question is how each system answers it.

## How other systems answer the trust problem

There are three broad answers, and each has well-known downsides.

### Public Key Infrastructure (PKI)

The HTTPS-style answer. A small set of trusted parties — the Certificate Authorities — sign statements like "this public key really belongs to amazon.com." Your operating system or browser ships with a list of trusted CAs (a few hundred of them), and any signature from any one of them is accepted as proof. (See [PKI](13-glossary.md#pki).)

This works at scale, but it puts an enormous amount of trust in the CAs. Any one of them can sign a bogus certificate for any domain, and historically several CAs have been caught doing exactly that — sometimes for state actors, sometimes through carelessness, sometimes through compromise. The Web has added complications (HSTS, certificate transparency logs, key pinning) to mitigate this, but the underlying model still trusts CAs by default.

PKI also costs money to run and requires either a globally-coordinated registry or, in private deployments, a corporate PKI infrastructure. Neither is appropriate for a personal password manager that has no server and no central authority.

### Web of Trust (WoT)

The PGP-style answer. Each user signs the public keys of other users they have personally verified, and trust propagates transitively: if Alice trusts Carol's signing decisions and Carol has signed Bob's key, Alice can extend some trust to Bob's key.

Web of trust is decentralised, which fits Secretary's design philosophy. But in practice it has been a usability disaster. Users find it hard to reason about transitive trust, signing parties are awkward and rare, and the resulting trust graph is sparse and brittle. PGP's WoT failed not because the cryptography was bad but because the trust model was too complicated for ordinary humans to use correctly.

### Trust on First Use (TOFU)

The SSH-style answer. The first time you connect to a server, you accept its public key without verification. You record the key, and on subsequent connections you compare against the recorded key. If it changes, you're warned. (See [TOFU](13-glossary.md#tofu).)

TOFU works well when the relationship has many repeat interactions and the first interaction is unlikely to be attacked (because the attacker would have to be ready and waiting at exactly the right moment). It works less well when the first interaction is *the* sensitive one — which is typically the case when you're sharing a password vault. By the time you'd notice a TOFU warning, the attacker may already have what they wanted.

Secretary deliberately does **not** support TOFU for contact cards. There is no auto-accept, no silent-import, no "accepted on first use." Every card must be imported with explicit user action.

## How Secretary answers it: out-of-band verification

Secretary's answer borrows from Signal, WhatsApp's secure mode, and other modern secure-messaging apps. It's called **[out-of-band verification](13-glossary.md#oob-verification)** (OOB), and it works like this:

1. You and Bob exchange Contact Cards through some channel — email, file transfer, a shared cloud folder, a USB stick. We do *not* assume this channel is secure. Eve could be on it.
2. Each card has a *fingerprint* — a short, human-readable summary of the card's full contents, computed via the BLAKE3 hash function (chapter 3) and presented as either a 12-word mnemonic or a 24-character hex string.
3. You and Bob confirm the fingerprint over a *different* channel from the one used to send the card. A phone call (you read the words to each other), an in-person meeting, a video chat where you both hold up your screens, an exchange of QR codes when you're physically together.
4. If the fingerprints match, you mark Bob's card as `fingerprint-verified`. You can now share blocks with him with high confidence that the keys really belong to him.
5. If the fingerprints don't match, the card has been tampered with somewhere in transit. Don't import it; investigate.

The cryptographic trick is that the fingerprint is *short enough to read aloud* but *long enough that an attacker cannot construct a fake card with a matching fingerprint*. With 16 bytes (128 bits) of fingerprint, an attacker who tries to craft a fake card with the same fingerprint as Bob's real one would need approximately 2^128 attempts — far beyond any conceivable computation. The fingerprint check, done over a channel the attacker can't simultaneously control, is therefore a strong proof.

A useful analogy: the fingerprint is like a phone number that can only belong to one person. If Eve hands Alice a business card with Bob's name on it, Alice phones Bob using a phone number she already trusts (a number from years ago, or his number she got from a family member) and reads the fingerprint on the card. If Bob says "yes, that's my fingerprint," Alice knows the card is Bob's. If Bob says "no, my fingerprint is different," Alice knows Eve substituted the card.

## What "the channel they can't simultaneously control" really means

The strength of OOB verification is that the attacker would need to control *both* channels at the same time. A cloud-folder host (chapter 1's primary adversary) can intercept files but probably can't intercept your phone calls. An email-account compromise can intercept emails but probably can't impersonate Bob's voice or manipulate his end of a video call.

If your threat model includes an adversary who *can* compromise both channels — a sophisticated state-level adversary, say — then OOB verification's strength depends on how many channels you use and how independent they are. In-person verification is the gold standard; verifying over multiple independent channels (phone *and* video, say) is a reasonable second.

For most personal and family use, a phone call is more than enough. Eve cannot simulate Bob's voice on his number while simultaneously sitting on Alice's cloud folder.

## Verification states in Secretary

Each Contact Card in Secretary carries one of two verification states:

- **`unverified`** — the card has been imported but the fingerprint hasn't been checked. Sharing blocks with this contact is allowed but produces a prominent warning. The card *might* be authentic; you just haven't proved it yet.
- **`fingerprint-verified`** — the fingerprint was confirmed via OOB. Sharing is allowed without warnings.

The state is local to your installation and never leaves your device. Bob doesn't know whether you've marked his card as verified; he just knows that you can decrypt the blocks he shares with you.

If a contact's identity is later suspected of compromise, you remove the card entirely. There is no "revoked" state; removed-and-not-re-imported is the same as "I have no card for this person." Future shares with that person require importing a new card and re-verifying its fingerprint.

## Why TOFU is excluded by design

It's worth being explicit about a choice that might surprise users: Secretary's API has no function called "import card from a path I trust" or "auto-discover cards in this shared folder." Every card import requires the user to point at a specific card file or paste specific card text, and the imported card lands in the `unverified` state.

This is intentional. The most dangerous TOFU mistake in a password manager is silent acceptance of a card that subsequently turns out to be the attacker's. By forcing every card import to be explicit and every share to a not-yet-verified contact to produce a warning, Secretary tries to keep the trust decision visible at every step.

The price is some extra friction. The compensation is that there is no scenario in which Secretary "trusts a key" without you having done so first.

## Practical guidance for users

A short distillation of the recommendations:

- Treat every new contact card as unverified until you've checked the fingerprint with the contact themselves over a different channel.
- For high-value sharing, prefer in-person verification (compare on screens, scan QR codes) over phone-call verification.
- If a contact's key changes — they reinstalled, they got a new device — treat the new card as a new card to be verified independently. Don't assume it's the same person just because it claims to be.
- If you ever notice that a contact's fingerprint has changed without explanation, stop sharing and investigate before doing anything else.

The friction is small, and the protection it buys is the difference between cryptographic security and the illusion of cryptographic security.

## Summary

- Cryptography turns secrecy problems into key-management problems. The one cryptography can't solve on its own is "is this the right key?"
- Secretary uses out-of-band verification: each contact card has a fingerprint, and you confirm the fingerprint over a different channel from the one that delivered the card.
- Until verification, the card is `unverified` and sharing produces a warning.
- TOFU is deliberately not supported — every card import is explicit.
- The fingerprint is short enough to read aloud but cryptographically long enough that forgery is infeasible.

The next chapter is about randomness — the unsung foundation of every keyed cryptographic system.
