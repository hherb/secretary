// Block-CRUD slice assertions for the Swift smoke runner.
//
// Swift mirror of tests/kotlin/SmokeBlockCrud.kt — same seed, same
// pinned UUIDs, same four expectations.  create / rename / move_record
// mutate the on-disk vault — each assert copies golden_vault_001 into a
// per-test tempdir via _freshWritableVault.

import Foundation

func runBlockCrudAsserts(env: SmokeEnv) {
    // Assert: create_block → read_block shows the given name and 0 records.
    do {
        let (identity, manifest, tmp) = try _freshWritableVault(env: env)
        defer { identity.wipe() }
        defer { manifest.wipe() }
        defer { try? FileManager.default.removeItem(at: tmp) }
        try createBlock(
            identity: identity, manifest: manifest,
            blockUuid: blockCrudBlockUuid, blockName: "Secrets",
            deviceUuid: blockCrudDeviceUuid, nowMs: 1_000
        )
        let block = try readBlock(
            identity: identity, manifest: manifest,
            blockUuid: blockCrudBlockUuid, includeDeleted: false
        )
        defer { block.wipe() }
        check(
            block.blockName() == "Secrets" && block.recordCount() == 0,
            "create_block → name=\"\(block.blockName())\" records=\(block.recordCount())"
        )
    } catch {
        check(false, "create_block round-trip threw \(error)")
    }

    // Assert: rename_block → read_block shows new name; records survive.
    do {
        let (identity, manifest, tmp) = try _freshWritableVault(env: env)
        defer { identity.wipe() }
        defer { manifest.wipe() }
        defer { try? FileManager.default.removeItem(at: tmp) }
        try createBlock(
            identity: identity, manifest: manifest,
            blockUuid: blockCrudBlockUuid, blockName: "OldName",
            deviceUuid: blockCrudDeviceUuid, nowMs: 1_000
        )
        // Seed a record into the block so we can verify records survive rename.
        try saveBlock(
            identity: identity, manifest: manifest,
            input: BlockInput(
                blockUuid: blockCrudBlockUuid,
                blockName: "OldName",
                records: [
                    RecordInput(
                        recordUuid: blockCrudSrcRecordUuid,
                        recordType: "login",
                        tags: [],
                        fields: [FieldInput(name: "user", value: .text(text: "bob"))]
                    ),
                ]
            ),
            deviceUuid: blockCrudDeviceUuid, nowMs: 2_000
        )
        try renameBlock(
            identity: identity, manifest: manifest,
            blockUuid: blockCrudBlockUuid, newBlockName: "NewName",
            deviceUuid: blockCrudDeviceUuid, nowMs: 3_000
        )
        let block = try readBlock(
            identity: identity, manifest: manifest,
            blockUuid: blockCrudBlockUuid, includeDeleted: false
        )
        defer { block.wipe() }
        check(
            block.blockName() == "NewName" && block.recordCount() == 1,
            "rename_block → name=\"\(block.blockName())\" records=\(block.recordCount())"
        )
    } catch {
        check(false, "rename_block round-trip threw \(error)")
    }

    // Assert: move_record → target read_block shows the record under
    // newRecordUuid; source read_block (live only) shows it gone.
    do {
        let (identity, manifest, tmp) = try _freshWritableVault(env: env)
        defer { identity.wipe() }
        defer { manifest.wipe() }
        defer { try? FileManager.default.removeItem(at: tmp) }
        try createBlock(
            identity: identity, manifest: manifest,
            blockUuid: blockCrudSrcBlockUuid, blockName: "Source",
            deviceUuid: blockCrudDeviceUuid, nowMs: 1_000
        )
        try createBlock(
            identity: identity, manifest: manifest,
            blockUuid: blockCrudTgtBlockUuid, blockName: "Target",
            deviceUuid: blockCrudDeviceUuid, nowMs: 2_000
        )
        try saveBlock(
            identity: identity, manifest: manifest,
            input: BlockInput(
                blockUuid: blockCrudSrcBlockUuid,
                blockName: "Source",
                records: [
                    RecordInput(
                        recordUuid: blockCrudSrcRecordUuid,
                        recordType: "note",
                        tags: [],
                        fields: [FieldInput(name: "body", value: .text(text: "secret"))]
                    ),
                ]
            ),
            deviceUuid: blockCrudDeviceUuid, nowMs: 3_000
        )
        try moveRecord(
            identity: identity, manifest: manifest,
            sourceBlockUuid: blockCrudSrcBlockUuid,
            targetBlockUuid: blockCrudTgtBlockUuid,
            sourceRecordUuid: blockCrudSrcRecordUuid,
            newRecordUuid: blockCrudNewRecordUuid,
            deviceUuid: blockCrudDeviceUuid, nowMs: 4_000
        )
        let tgt = try readBlock(
            identity: identity, manifest: manifest,
            blockUuid: blockCrudTgtBlockUuid, includeDeleted: false
        )
        defer { tgt.wipe() }
        let src = try readBlock(
            identity: identity, manifest: manifest,
            blockUuid: blockCrudSrcBlockUuid, includeDeleted: false
        )
        defer { src.wipe() }
        check(
            tgt.recordCount() == 1 && src.recordCount() == 0,
            "move_record → target.recordCount=\(tgt.recordCount()) source.liveCount=\(src.recordCount())"
        )
    } catch {
        check(false, "move_record round-trip threw \(error)")
    }

    // Assert: move_record same-block → throws VaultError.InvalidArgument.
    do {
        let (identity, manifest, tmp) = try _freshWritableVault(env: env)
        defer { identity.wipe() }
        defer { manifest.wipe() }
        defer { try? FileManager.default.removeItem(at: tmp) }
        try createBlock(
            identity: identity, manifest: manifest,
            blockUuid: blockCrudBlockUuid, blockName: "SameBlock",
            deviceUuid: blockCrudDeviceUuid, nowMs: 1_000
        )
        do {
            try moveRecord(
                identity: identity, manifest: manifest,
                sourceBlockUuid: blockCrudBlockUuid,
                targetBlockUuid: blockCrudBlockUuid,
                sourceRecordUuid: blockCrudSrcRecordUuid,
                newRecordUuid: blockCrudNewRecordUuid,
                deviceUuid: blockCrudDeviceUuid, nowMs: 2_000
            )
            check(false, "move_record same-block should have thrown InvalidArgument")
        } catch let e as VaultError {
            if case .InvalidArgument = e {
                check(true, "move_record same-block → VaultError.InvalidArgument")
            } else {
                check(false, "move_record same-block threw wrong variant: \(e)")
            }
        }
    } catch {
        check(false, "move_record same-block setup threw \(error)")
    }
}
