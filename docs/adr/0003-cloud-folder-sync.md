# ADR 0003 — User-controlled cloud-folder sync; no server operated by us

**Status:** Accepted (2026-04-25)
**Supersedes:** none
**Superseded by:** none

## Context

Secretary needs sync across a user's devices and a way for users to share blocks with family members. The deployment models considered:

1. **Local-only.** Each device holds its own vault. Sync is the user's manual problem.
2. **User-controlled cloud folder.** App writes encrypted files into the user's existing iCloud Drive / Google Drive / Dropbox / OneDrive / WebDAV mount. We never operate a server.
3. **Self-hostable open server** (Bitwarden / Vaultwarden style). Users run a server we provide.
4. **Managed cloud service** we operate.
5. **P2P sync** between user's devices via direct connection or a relay.

The author has stated a strong preference for shipping apps only — never operating a service. AGPL 3.0 with commercial dual licensing further argues against a server we run, since AGPL's network-use clause would force any commercial fork's server to also publish source.

## Decision

Use **option 2: user-controlled cloud-folder storage**, with optional WebDAV for users who prefer self-hosting their own folder.

The vault is a directory of files. The user puts that directory anywhere they want — typically inside a folder synced by their existing cloud provider. Secretary does not operate, recommend, or integrate with any specific cloud provider — anything that presents a folder on the local file system works.

Sharing happens by copying a single block file (with the recipient's wrap added) into a folder both parties have access to. The destination folder is *not* a Secretary-managed structure; it is whatever shared folder the family already uses.

The cloud-folder host is in the *threat model* (see [threat-model §2.1](../threat-model.md#21-cloud-folder-host-in-scope-primary)) — assumed to read every byte and possibly tamper. The format defends against this assumption.

## Consequences

**Positive:**
- Zero infrastructure to operate. No outage management, no rate limiting, no abuse handling, no GDPR data-controller responsibilities.
- Users keep their data on infrastructure they already trust enough for other purposes (their existing cloud).
- AGPL/commercial dual licensing is clean — there is no service, only software.
- Sync conflict resolution happens client-side, where it belongs.
- Self-hosting via WebDAV is automatic — anyone running a WebDAV server (Nextcloud, Synology NAS, etc.) can use it without Secretary needing to know.
- Sharing semantics are intuitive: the user already understands "this folder is shared with my family"; we just put a file in it.

**Negative:**
- File-level cloud sync has long-standing failure modes (Dropbox file-conflict copies, iCloud silent dedup, Google Drive byte-range race). Secretary must tolerate these; the file-by-file format with vector clocks helps but does not eliminate the operational headache for users.
- We cannot send push notifications — there's no server to push from. Sync detection relies on file-system watchers. Mobile platforms restrict file-system watchers in the background, so sync may be on-app-foreground only on mobile.
- We cannot do server-side conflict mediation, server-side validation, or rate limiting. Misbehaving clients cannot be detected.
- Per-record sync efficiency is impossible: even a one-byte change to a record requires re-writing its entire block file. Mitigated by user-defined block sizing — small, frequently-edited blocks are the user's choice.
- Account-recovery features (e.g., "I lost my recovery key, but I can prove identity to a server") are unavailable. The recovery story is necessarily based on user-held credentials only.

**Risks:**
- Some cloud providers throttle high file counts or large numbers of small files. Most users will have well under 1000 blocks; this should not bind.
- WebDAV implementations vary in quality; some have eventual-consistency surprises. Documentation must call out tested WebDAV servers and known-incompatible ones.

## Revisit when

- Significant user feedback indicates the manual-folder model is confusing. A future companion sync server (optional, self-hostable) could be added without changing the format — the protocol would be "fetch/put files," which any HTTP server can do.
- A specific cloud provider exposes hooks (e.g., file-event webhooks) that meaningfully improve sync UX. Probably not worth integrating per provider.
