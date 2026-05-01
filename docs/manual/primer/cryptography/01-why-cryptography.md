# 1. Why cryptography matters here

Before we look at how Secretary protects your data, it's worth being precise about *what* it is protecting and *from whom*. Cryptography is a set of tools, and like all tools, the right way to think about it is in terms of the job it has to do.

## The job

Secretary holds your most sensitive credentials: bank logins, email passwords, recovery keys for cryptocurrency wallets, the WiFi password your nephew really shouldn't have, the SSH key that gets you into the family server, the master password to your other password manager (yes, people do that). Some of these you'll change tomorrow. Some you may need to use, untouched, in 2055.

Secretary also has an unusual goal: it wants to let you *share* some of these with family members, and it wants the sharing to keep working long after you stop being around to manage it. A parent should be able to set up a family vault such that their children can still access shared credentials decades later — without trusting any company to still exist, still be honest, or still be reachable.

That last requirement turns out to be the hard one, and it's why this primer is necessary.

## What "protect" means, concretely

When we say cryptography protects something, we usually mean one or more of the following four things:

- **Confidentiality** — only the intended people can read it. A stranger looking at the encrypted file sees gibberish.
- **Integrity** — nobody can change it without being detected. If someone flips a single bit anywhere in the file, the change is noticed and the file is rejected.
- **Authenticity** — you can prove who wrote it. A block your sister shared with you was actually shared by her, not by someone pretending to be her.
- **Availability** — the data is still there when you need it. (Cryptography helps with this less than people think; mostly availability is a backup problem.)

Secretary aims at the first three. Availability is up to you and your choice of cloud-folder service or backup discipline.

## What you are protecting against

The realistic adversaries we worry about are:

1. **The cloud-folder host you're using.** Dropbox, Google Drive, iCloud Drive, OneDrive, a WebDAV mount on a NAS — whichever folder you point Secretary at, the operator of that service can see every byte. Secretary's design assumes that operator is hostile or compromised; the encrypted vault should reveal nothing useful even with full read/write access to the folder.

2. **A stolen laptop or phone.** Locked, taken at an airport, lost in a taxi. The thief can copy your entire vault folder. Without your master password, they should be unable to make sense of it. Without an enormous amount of computing time *and* your master password's worth of guessing, brute-forcing it should be infeasible.

3. **A future quantum computer.** This is the strange one. Quantum computers don't exist at any useful scale today, but research is steady, and a sufficiently capable quantum computer would break some of the cryptographic algorithms used by every system on the internet. An adversary today can record your encrypted ciphertext from your cloud folder and store it indefinitely, hoping to decrypt it later when quantum computing matures. This is called a *harvest-now-decrypt-later* attack. It is the dominant reason your password manager from 2010 isn't quite good enough anymore for credentials that need to last 30 years.

4. **A person impersonating someone you trust.** When you share a vault block with your sister, you need to be sure that the public key you're encrypting *to* really belongs to her, not to someone in the middle pretending to be her. This is the *authenticity* problem, and it's where cryptography hands the problem back to you and asks you to do a small bit of work yourself (chapter 9).

## What you are *not* protecting against

There are threats Secretary makes no claim about, and you should know which ones up front. They aren't ignored because they don't matter; they're ignored because no software running as a normal application on a normal computer can defend against them. They are part of cryptography's honesty-with-itself: a tool that pretends to do too much is more dangerous than one that says "this is where my reach ends." The full list is in [chapter 12](12-limitations.md), but as a preview:

- Malware running with full privileges on your unlocked computer can read whatever Secretary has decrypted into memory. Cryptography happens at the boundary; once the data is across the boundary, it lives in normal application memory.
- Someone who can force you, by threat or coercion, to type your master password defeats the whole system. There is no clever cryptographic trick around this.
- A flaw in the operating system, a backdoor in the hardware, or a malicious update to one of Secretary's dependencies can compromise the system below the level cryptography operates at.
- An adversary who simply *deletes* your cloud-folder copy isn't trying to read your secrets; they're trying to cause a denial of service. The defense for that is backups, not cryptography.

A useful mental model: cryptography turns a confidentiality / integrity / authenticity problem into a key-management problem. If you keep your keys safe, you keep your data safe. If you don't, no amount of cryptography helps. The whole rest of this primer is, at some level, about how Secretary manages the keys.

## A reading list for this chapter

If you want to dig deeper into the philosophy of what cryptographic systems can and cannot do, the following are accessible:

- *Cryptography Engineering* by Ferguson, Schneier, and Kohno. The first three chapters in particular are a good general framing.
- *The Cryptopals Crypto Challenges* (online). Hands-on, but readable even without doing the exercises.
- The IETF's RFC 7696 ("Guidelines for Cryptographic Algorithm Agility") explains why building in the ability to change algorithms — as Secretary does with its suite-ID mechanism — is itself a security property.

The next chapter starts with the most fundamental distinction in cryptography: the difference between symmetric and asymmetric encryption.
