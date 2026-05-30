// B.4d share_block assertions for the Swift smoke runner.
//
// share_block extends a block's recipient list. v1 single-author: only the
// vault owner can share blocks they authored. The assertions below use
// golden_vault_001 as the owner and golden_vault_002's owner card as
// "Alice" — distinct identities pre-built by the same fixture builder.
//
// NotAuthor is NOT asserted at this layer: reaching it requires staging
// cross-vault manifest content (one vault's manifest must list a block
// authored elsewhere), which open_vault_with_password rejects via
// vault.toml ↔ manifest consistency. Pinned at the bridge unit-test
// layer (`vault_error_not_author_from_core_preserves_fingerprints_as_hex`)
// and the core integration layer
// (`core/tests/share_block.rs::share_block_non_author_rejected`); will
// be exercised end-to-end by Sub-project C's sync layer.

import Foundation

func runShareBlockAsserts(env: SmokeEnv) {
    // Assert 27: share_block happy path — owner saves a block, owner shares
    // with Alice, manifest entry now lists 2 recipients.
    do {
        let aliceBytes = try _aliceCardBytes(env: env)
        let (identity, manifest, tmp) = try _freshWritableVault(env: env)
        defer { identity.wipe() }
        defer { manifest.wipe() }
        defer { try? FileManager.default.removeItem(at: tmp) }

        try saveBlock(
            identity: identity,
            manifest: manifest,
            input: BlockInput(
                blockUuid: shareBlockBlockUuid,
                blockName: "shared",
                records: [
                    RecordInput(
                        recordUuid: shareBlockRecordUuid,
                        recordType: "",
                        tags: [],
                        fields: [FieldInput(name: "k", value: .text(text: "v"))]
                    ),
                ]
            ),
            deviceUuid: shareBlockDeviceUuid,
            nowMs: 1_000
        )
        guard let ownerBytes = try manifest.ownerCardBytes() else {
            check(false, "owner card bytes nil before share")
            exit(1)
        }
        try shareBlock(
            identity: identity,
            manifest: manifest,
            blockUuid: shareBlockBlockUuid,
            existingRecipientCards: [ownerBytes],
            newRecipient: aliceBytes,
            deviceUuid: shareBlockDeviceUuid,
            nowMs: 2_000
        )
        let summary = manifest.findBlock(blockUuid: shareBlockBlockUuid)
        check(
            summary?.recipientUuids.count == 2,
            "share_block insert → manifest grows to 2 recipients (got \(summary?.recipientUuids.count ?? -1))"
        )
    } catch {
        check(false, "share_block happy path threw \(error), expected to succeed")
    }

    // Assert 28: share_block to the same recipient twice → RecipientAlreadyPresent.
    do {
        let aliceBytes = try _aliceCardBytes(env: env)
        let (identity, manifest, tmp) = try _freshWritableVault(env: env)
        defer { identity.wipe() }
        defer { manifest.wipe() }
        defer { try? FileManager.default.removeItem(at: tmp) }

        try saveBlock(
            identity: identity,
            manifest: manifest,
            input: BlockInput(
                blockUuid: shareBlockBlockUuid, blockName: "x", records: []
            ),
            deviceUuid: shareBlockDeviceUuid,
            nowMs: 1_000
        )
        let ownerBytes = try manifest.ownerCardBytes()!
        try shareBlock(
            identity: identity,
            manifest: manifest,
            blockUuid: shareBlockBlockUuid,
            existingRecipientCards: [ownerBytes],
            newRecipient: aliceBytes,
            deviceUuid: shareBlockDeviceUuid,
            nowMs: 2_000
        )
        do {
            try shareBlock(
                identity: identity,
                manifest: manifest,
                blockUuid: shareBlockBlockUuid,
                existingRecipientCards: [ownerBytes, aliceBytes],
                newRecipient: aliceBytes,
                deviceUuid: shareBlockDeviceUuid,
                nowMs: 3_000
            )
            check(false, "duplicate share_block should have thrown VaultError.RecipientAlreadyPresent")
        } catch let e as VaultError {
            if case .RecipientAlreadyPresent = e {
                check(true, "share_block duplicate alice → RecipientAlreadyPresent")
            } else {
                check(false, "duplicate share_block threw wrong VaultError variant: \(e)")
            }
        }
    } catch {
        check(false, "share_block duplicate-recipient setup threw \(error)")
    }

    // Assert 29: share_block with empty existing_recipient_cards while the
    // block has the owner as a recipient → MissingRecipientCard.
    do {
        let aliceBytes = try _aliceCardBytes(env: env)
        let (identity, manifest, tmp) = try _freshWritableVault(env: env)
        defer { identity.wipe() }
        defer { manifest.wipe() }
        defer { try? FileManager.default.removeItem(at: tmp) }

        try saveBlock(
            identity: identity,
            manifest: manifest,
            input: BlockInput(
                blockUuid: shareBlockBlockUuid, blockName: "x", records: []
            ),
            deviceUuid: shareBlockDeviceUuid,
            nowMs: 1_000
        )
        do {
            try shareBlock(
                identity: identity,
                manifest: manifest,
                blockUuid: shareBlockBlockUuid,
                existingRecipientCards: [],
                newRecipient: aliceBytes,
                deviceUuid: shareBlockDeviceUuid,
                nowMs: 2_000
            )
            check(false, "share with empty existing list should have thrown MissingRecipientCard")
        } catch let e as VaultError {
            if case let .MissingRecipientCard(fp) = e {
                check(
                    fp.count == 32,
                    "share_block missing card → MissingRecipientCard(\(fp))"
                )
            } else {
                check(false, "missing-existing-card threw wrong VaultError variant: \(e)")
            }
        }
    } catch {
        check(false, "share_block missing-existing-card setup threw \(error)")
    }

    // Assert 30: share_block with garbage card bytes → CardDecodeFailure.
    do {
        let aliceBytes = try _aliceCardBytes(env: env)
        let (identity, manifest, tmp) = try _freshWritableVault(env: env)
        defer { identity.wipe() }
        defer { manifest.wipe() }
        defer { try? FileManager.default.removeItem(at: tmp) }

        try saveBlock(
            identity: identity,
            manifest: manifest,
            input: BlockInput(
                blockUuid: shareBlockBlockUuid, blockName: "x", records: []
            ),
            deviceUuid: shareBlockDeviceUuid,
            nowMs: 1_000
        )
        let garbage = Data(repeating: 0xff, count: 8)
        do {
            try shareBlock(
                identity: identity,
                manifest: manifest,
                blockUuid: shareBlockBlockUuid,
                existingRecipientCards: [garbage],
                newRecipient: aliceBytes,
                deviceUuid: shareBlockDeviceUuid,
                nowMs: 2_000
            )
            check(false, "garbage existing card should have thrown CardDecodeFailure")
        } catch let e as VaultError {
            if case .CardDecodeFailure = e {
                check(true, "share_block garbage existing → CardDecodeFailure")
            } else {
                check(false, "garbage existing threw wrong VaultError variant: \(e)")
            }
        }
    } catch {
        check(false, "share_block card-decode-failure setup threw \(error)")
    }
}
