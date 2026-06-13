// record-edit slice assertions for the Swift smoke runner.
//
// append/edit/tombstone/resurrect mutate the on-disk vault — each assert
// copies golden_vault_001 into a per-test tempdir via _freshWritableVault.

import Foundation

func runRecordEditAsserts(env: SmokeEnv) {
    func seedBlock(_ identity: UnlockedIdentity, _ manifest: OpenVaultManifest) throws {
        let input = BlockInput(
            blockUuid: recordEditBlockUuid,
            blockName: "Logins",
            records: [
                RecordInput(
                    recordUuid: recordEditRecordUuid,
                    recordType: "login",
                    tags: ["work"],
                    fields: [
                        FieldInput(name: "user", value: .text(text: "alice")),
                        FieldInput(name: "pass", value: .text(text: "hunter2")),
                    ]
                ),
            ]
        )
        try saveBlock(
            identity: identity, manifest: manifest, input: input,
            deviceUuid: recordEditDeviceUuid, nowMs: 1_000
        )
    }

    // Assert: append_record adds a second live record → read_block sees both.
    do {
        let (identity, manifest, tmp) = try _freshWritableVault(env: env)
        defer { identity.wipe() }
        defer { manifest.wipe() }
        defer { try? FileManager.default.removeItem(at: tmp) }
        try seedBlock(identity, manifest)
        let secondUuid = Data(repeating: 0xD3, count: 16)
        try appendRecord(
            identity: identity, manifest: manifest,
            blockUuid: recordEditBlockUuid, recordUuid: secondUuid,
            content: RecordContent(
                recordType: "note", tags: [],
                fields: [FieldInput(name: "body", value: .text(text: "remember"))]
            ),
            deviceUuid: recordEditDeviceUuid, nowMs: 2_000
        )
        let block = try readBlock(identity: identity, manifest: manifest, blockUuid: recordEditBlockUuid)
        defer { block.wipe() }
        check(
            block.recordCount() == 2,
            "append_record → read_block sees 2 records (got \(block.recordCount()))"
        )
    } catch {
        check(false, "append_record round-trip threw \(error)")
    }

    // Assert: edit_record changes "pass" but leaves "user" untouched — the
    // untouched field keeps its prior device_uuid (per-field-clock proof).
    do {
        let (identity, manifest, tmp) = try _freshWritableVault(env: env)
        defer { identity.wipe() }
        defer { manifest.wipe() }
        defer { try? FileManager.default.removeItem(at: tmp) }
        try seedBlock(identity, manifest)
        let editDevice = Data(repeating: 0x09, count: 16)
        try editRecord(
            identity: identity, manifest: manifest,
            blockUuid: recordEditBlockUuid, recordUuid: recordEditRecordUuid,
            content: RecordContent(
                recordType: "login", tags: ["work"],
                fields: [
                    FieldInput(name: "user", value: .text(text: "alice")),   // unchanged
                    FieldInput(name: "pass", value: .text(text: "s3cret!")), // changed
                ]
            ),
            deviceUuid: editDevice, nowMs: 3_000
        )
        let block = try readBlock(identity: identity, manifest: manifest, blockUuid: recordEditBlockUuid)
        defer { block.wipe() }
        let record = block.recordAt(idx: 0)
        let pass = record?.fieldByName(name: "pass")?.exposeText()
        let userDevice = record?.fieldByName(name: "user")?.deviceUuid()
        let passDevice = record?.fieldByName(name: "pass")?.deviceUuid()
        check(
            pass == "s3cret!" && userDevice == recordEditDeviceUuid && passDevice == editDevice,
            "edit_record preserves untouched field clock (pass=\(pass ?? "<nil>"))"
        )
    } catch {
        check(false, "edit_record round-trip threw \(error)")
    }

    // Assert: tombstone flips the record's tombstone() flag to true (the
    // record stays in read_block's projection — read_block surfaces tombstoned
    // records via record.tombstone(), it does NOT filter them out); resurrect
    // flips it back to false.
    do {
        let (identity, manifest, tmp) = try _freshWritableVault(env: env)
        defer { identity.wipe() }
        defer { manifest.wipe() }
        defer { try? FileManager.default.removeItem(at: tmp) }
        try seedBlock(identity, manifest)
        try tombstoneRecord(
            identity: identity, manifest: manifest,
            blockUuid: recordEditBlockUuid, recordUuid: recordEditRecordUuid,
            deviceUuid: recordEditDeviceUuid, nowMs: 4_000
        )
        let afterTombstone = try readBlock(identity: identity, manifest: manifest, blockUuid: recordEditBlockUuid)
        let deadFlag = afterTombstone.recordAt(idx: 0)?.tombstone()
        afterTombstone.wipe()
        try resurrectRecord(
            identity: identity, manifest: manifest,
            blockUuid: recordEditBlockUuid, recordUuid: recordEditRecordUuid,
            deviceUuid: recordEditDeviceUuid, nowMs: 5_000
        )
        let afterResurrect = try readBlock(identity: identity, manifest: manifest, blockUuid: recordEditBlockUuid)
        let liveFlag = afterResurrect.recordAt(idx: 0)?.tombstone()
        afterResurrect.wipe()
        check(
            deadFlag == true && liveFlag == false,
            "tombstone→tombstone()=\(deadFlag.map(String.init) ?? "<nil>") then resurrect→tombstone()=\(liveFlag.map(String.init) ?? "<nil>")"
        )
    } catch {
        check(false, "tombstone/resurrect round-trip threw \(error)")
    }

    // Assert: editing an unknown record uuid → VaultError.RecordNotFound.
    do {
        let (identity, manifest, tmp) = try _freshWritableVault(env: env)
        defer { identity.wipe() }
        defer { manifest.wipe() }
        defer { try? FileManager.default.removeItem(at: tmp) }
        try seedBlock(identity, manifest)
        do {
            try editRecord(
                identity: identity, manifest: manifest,
                blockUuid: recordEditBlockUuid, recordUuid: Data(repeating: 0xFF, count: 16),
                content: RecordContent(recordType: "x", tags: [], fields: []),
                deviceUuid: recordEditDeviceUuid, nowMs: 6_000
            )
            check(false, "edit_record on unknown uuid should have thrown RecordNotFound")
        } catch let e as VaultError {
            if case .RecordNotFound = e {
                check(true, "edit_record unknown uuid → RecordNotFound")
            } else {
                check(false, "edit_record unknown uuid threw wrong variant: \(e)")
            }
        }
    } catch {
        check(false, "edit_record unknown-uuid setup threw \(error)")
    }

    // Assert: wrong-length device_uuid → VaultError.InvalidArgument.
    do {
        let (identity, manifest, tmp) = try _freshWritableVault(env: env)
        defer { identity.wipe() }
        defer { manifest.wipe() }
        defer { try? FileManager.default.removeItem(at: tmp) }
        try seedBlock(identity, manifest)
        do {
            try tombstoneRecord(
                identity: identity, manifest: manifest,
                blockUuid: recordEditBlockUuid, recordUuid: recordEditRecordUuid,
                deviceUuid: Data([0x07, 0x07]), nowMs: 7_000
            )
            check(false, "tombstone_record wrong-length device_uuid should have thrown InvalidArgument")
        } catch let e as VaultError {
            if case .InvalidArgument = e {
                check(true, "tombstone_record wrong-length → InvalidArgument")
            } else {
                check(false, "wrong-length threw wrong variant: \(e)")
            }
        }
    } catch {
        check(false, "wrong-length setup threw \(error)")
    }
}
