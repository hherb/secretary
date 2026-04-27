# Hardening security when needed

Secretary's default settings already give you strong protection: your master password is stretched with Argon2id, your identity keys are encrypted at rest with XChaCha20-Poly1305, and your data is post-quantum-hybrid-encrypted to every recipient. For most personal and family use, the defaults are appropriate.

This chapter is for situations where you want to push further — high-value secrets, threat models that include physical device theft or sophisticated forensic recovery, or simply careful operational hygiene. Nothing here is required; everything here is a layered improvement on a baseline that is already meant to be good.

## What Secretary already does for you

When Secretary unlocks your vault, it loads cryptographic keys into memory just long enough to decrypt the data you're working with. The moment those keys are no longer needed, Secretary explicitly **zeroes** the memory that held them — overwriting the bytes with zeros and instructing the compiler not to optimize that overwrite away. The same goes for your master password and your recovery mnemonic: they are scrubbed from RAM as soon as Secretary is done with them. Long-lived material (the per-vault Identity Block Key) survives only as long as your session, and is zeroed when the application exits or the vault is locked.

This handles the in-memory part of the problem completely. There is, however, a layer below the running application that Secretary cannot reach on its own: **what your operating system does with the memory pages Secretary uses.**

## The swap-file concern

Modern operating systems move idle memory pages to disk when RAM gets tight — this is called *swap* (Linux, macOS) or the *paging file* (Windows). If a key was sitting in a memory page that the OS swapped to disk before Secretary got a chance to zero it, the on-disk swap copy still contains that key. After Secretary zeroes the in-RAM copy, the swap copy is unaffected — and it persists on disk until that swap slot is reused.

An adversary with physical access to your unencrypted swap file (laptop theft, drive forensics on a discarded SSD, sophisticated cold-storage attack) could in principle recover keys from there.

The same concern applies, more strongly, to **hibernation**: when a computer hibernates (suspend-to-disk), the *entire* contents of RAM are written to disk. Secretary's in-memory zeroing happens too late for any key that was live at the moment of hibernation.

## What you can do

The good news is that all the meaningful mitigations are layered into the operating system, not into Secretary itself, and most modern systems already do the right thing by default. You just need to verify and, in a few cases, opt in.

### macOS and iOS

- **Swap encryption is on by default** on macOS 10.11 and later, and always-on on iOS. There is nothing to configure.
- **FileVault** (full-disk encryption) is opt-in but recommended for any device holding a Secretary vault. With FileVault on, your swap file is part of an encrypted volume, and even a stolen drive yields no plaintext.
- **Hibernation**: macOS uses "safe sleep" by default — RAM contents are written to an encrypted file (`/var/vm/sleepimage`) on the FileVault volume. Acceptable when FileVault is on; otherwise, consider disabling hibernation.

### Linux

- **Encrypted swap is opt-in** but standard in security-conscious distributions. The cleanest setup is to put swap on a LUKS-encrypted partition (most installers offer this); alternatives include `systemd-cryptsetup`'s ephemeral random-keyed swap, or skipping swap entirely (set `vm.swappiness=0` and have enough RAM, or use ZRAM for compressed in-memory swap).
- **Full-disk encryption** with LUKS is recommended for any device holding a Secretary vault.
- **Hibernation**: requires careful configuration if you have encrypted swap (the kernel needs to resume from the encrypted partition); for high-assurance use, disabling hibernation entirely is simpler.

### Windows

- **BitLocker** (full-disk encryption) is recommended; on Windows 10/11 Pro and Enterprise it's well-integrated. With BitLocker on, the paging file is on the encrypted volume.
- **Paging-file encryption** can be enabled separately even without BitLocker (`fsutil behavior set encryptpagingfile 1`, then reboot).
- **Hibernation**: as above, encrypted only if BitLocker is on. To disable: `powercfg /hibernate off`.

### Android

- Full-device encryption has been mandatory since Android 6.0. Encrypted swap (when present) is part of the encrypted volume. Generally nothing to configure.

## Operational practices

For high-value vaults, a few habits matter as much as the OS settings:

- **Lock the vault when you walk away.** A locked vault has no keys in memory; an unlocked one does, regardless of how good your zeroization is.
- **Don't unlock a high-value vault on devices you don't fully trust.** No amount of memory hygiene helps if a keylogger captures your master password as you type it.
- **Reboot occasionally**, especially after working with sensitive blocks. RAM pages get reused; swap slots get reclaimed; the longer a system runs, the more it accumulates traces.
- **Avoid hibernating immediately after using a high-value vault.** Either lock the vault first, or shut down rather than hibernate.

## Future improvements within Secretary

A planned enhancement is to use the operating system's "lock this page in physical RAM" facility (`mlock` on Unix, `VirtualLock` on Windows) on the small number of pages that hold key material. This would prevent those pages from ever being swapped to disk, eliminating the swap-file concern at the source rather than relying on swap encryption.

This is a focused change and is on the roadmap, but it has trade-offs worth flagging:

- **Page granularity.** Operating systems lock memory in 4 KiB pages; a 32-byte key consumes a whole locked page. Cost in RAM is small but non-zero.
- **Quota limits.** Linux limits unprivileged processes to roughly 64 KiB of locked memory by default (`RLIMIT_MEMLOCK`); we would need to be careful to fit within that without elevated privileges.
- **Hibernation.** Even locked pages are written to disk on hibernation. So `mlock` is complementary to, not a replacement for, the operational practices above.

When this lands, the chapter will be updated; nothing about your existing vaults will change, and you will not need to do anything.

## Threat model boundary

Secretary's defenses assume:

- The operating system is functioning normally and has not been compromised below the user-process boundary (no kernel rootkit, no firmware implant, no malicious hypervisor).
- Disk encryption and swap encryption are configured according to the platform-specific guidance above.
- The user is not under coercion at the moment they unlock the vault.

If your threat model includes adversaries who can defeat all three of those assumptions — for instance, a state-level adversary with physical access and unlimited time — Secretary alone is not the answer; you need an air-gapped device, hardware-token-only authentication, and a great deal more besides. That is outside the scope of what a software-only personal secrets manager can promise.

What Secretary *does* promise, and what the rest of this manual will help you make full use of, is strong protection against the realistic adversaries faced by individuals, families, and small teams: a stolen laptop, a compromised cloud-folder host, a future quantum computer attempting to decrypt material harvested today. The defaults handle those. The hardening in this chapter pushes further, when you want it.
