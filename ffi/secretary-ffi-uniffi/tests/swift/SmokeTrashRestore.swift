// B.5 trash_block + restore_block assertions for the Swift smoke runner.
//
// Covers the soft-delete + restore lifecycle:
//   - Assert 31: trash + restore round-trip preserves the block payload
//   - Assert 32: trash_block(unknown_uuid) → VaultError.BlockNotFound
//   - Assert 33: restore_block on never-trashed UUID → BlockNotInTrash
//   - Assert 34: restore_block on live UUID (trashed → re-saved) →
//     BlockUuidAlreadyLive

import Foundation

func runTrashRestoreAsserts(env: SmokeEnv) {
    // Assert 31: trash_block + restore_block round-trip preserves the block.
    do {
        let (identity, manifest, tmp) = try _freshWritableVault(env: env)
        defer { identity.wipe() }
        defer { manifest.wipe() }
        defer { try? FileManager.default.removeItem(at: tmp) }

        try saveBlock(
            identity: identity,
            manifest: manifest,
            input: BlockInput(
                blockUuid: b5BlockUuid,
                blockName: "B.5 round-trip",
                records: [
                    RecordInput(
                        recordUuid: b5RecordUuid,
                        recordType: "",
                        tags: [],
                        fields: [
                            FieldInput(name: "title", value: .text(text: "secret"))
                        ]
                    )
                ]
            ),
            deviceUuid: b5DeviceUuid,
            nowMs: 1_000
        )
        try trashBlock(
            identity: identity,
            manifest: manifest,
            blockUuid: b5BlockUuid,
            deviceUuid: b5DeviceUuid,
            nowMs: 2_000
        )
        check(
            manifest.findBlock(blockUuid: b5BlockUuid) == nil,
            "trash_block: BlockEntry dropped from manifest"
        )
        try restoreBlock(
            identity: identity,
            manifest: manifest,
            blockUuid: b5BlockUuid,
            deviceUuid: b5DeviceUuid,
            nowMs: 3_000
        )
        let restored = try readBlock(
            identity: identity, manifest: manifest, blockUuid: b5BlockUuid, includeDeleted: false
        )
        check(
            restored.recordCount() == 1,
            "restore_block: record preserved (got \(restored.recordCount()))"
        )
    } catch {
        check(false, "B.5 round-trip threw \(error)")
    }

    // Assert 32: trash_block(unknown_uuid) → VaultError.BlockNotFound.
    do {
        let (identity, manifest, tmp) = try _freshWritableVault(env: env)
        defer { identity.wipe() }
        defer { manifest.wipe() }
        defer { try? FileManager.default.removeItem(at: tmp) }

        let unknownUuid = Data(repeating: 0xFF, count: 16)
        do {
            try trashBlock(
                identity: identity,
                manifest: manifest,
                blockUuid: unknownUuid,
                deviceUuid: b5DeviceUuid,
                nowMs: 1_000
            )
            check(false, "trash_block(unknown) should have thrown BlockNotFound")
        } catch let e as VaultError {
            if case .BlockNotFound = e {
                check(true, "trash_block unknown → VaultError.BlockNotFound")
            } else {
                check(false, "trash_block unknown threw wrong VaultError: \(e)")
            }
        }
    } catch {
        check(false, "trash_block unknown setup threw \(error)")
    }

    // Assert 33: restore_block on never-trashed UUID → VaultError.BlockNotInTrash.
    do {
        let (identity, manifest, tmp) = try _freshWritableVault(env: env)
        defer { identity.wipe() }
        defer { manifest.wipe() }
        defer { try? FileManager.default.removeItem(at: tmp) }

        let neverTrashedUuid = Data(repeating: 0xEE, count: 16)
        do {
            try restoreBlock(
                identity: identity,
                manifest: manifest,
                blockUuid: neverTrashedUuid,
                deviceUuid: b5DeviceUuid,
                nowMs: 1_000
            )
            check(false, "restore_block(never-trashed) should have thrown BlockNotInTrash")
        } catch let e as VaultError {
            if case .BlockNotInTrash = e {
                check(true, "restore_block never-trashed → VaultError.BlockNotInTrash")
            } else {
                check(false, "restore_block never-trashed threw wrong VaultError: \(e)")
            }
        }
    } catch {
        check(false, "restore_block never-trashed setup threw \(error)")
    }

    // Assert 34: restore_block on live UUID (trashed → re-saved) → BlockUuidAlreadyLive.
    do {
        let (identity, manifest, tmp) = try _freshWritableVault(env: env)
        defer { identity.wipe() }
        defer { manifest.wipe() }
        defer { try? FileManager.default.removeItem(at: tmp) }

        try saveBlock(
            identity: identity,
            manifest: manifest,
            input: BlockInput(
                blockUuid: b5BlockUuid,
                blockName: "v1",
                records: []
            ),
            deviceUuid: b5DeviceUuid,
            nowMs: 1_000
        )
        try trashBlock(
            identity: identity,
            manifest: manifest,
            blockUuid: b5BlockUuid,
            deviceUuid: b5DeviceUuid,
            nowMs: 2_000
        )
        try saveBlock(
            identity: identity,
            manifest: manifest,
            input: BlockInput(
                blockUuid: b5BlockUuid,
                blockName: "v2",
                records: []
            ),
            deviceUuid: b5DeviceUuid,
            nowMs: 3_000
        )
        do {
            try restoreBlock(
                identity: identity,
                manifest: manifest,
                blockUuid: b5BlockUuid,
                deviceUuid: b5DeviceUuid,
                nowMs: 4_000
            )
            check(false, "restore_block on live UUID should have thrown BlockUuidAlreadyLive")
        } catch let e as VaultError {
            if case .BlockUuidAlreadyLive = e {
                check(true, "restore_block live-collision → VaultError.BlockUuidAlreadyLive")
            } else {
                check(false, "restore_block live-collision threw wrong VaultError: \(e)")
            }
        }
    } catch {
        check(false, "restore_block live-collision setup threw \(error)")
    }
}
