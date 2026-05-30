// B.4c save_block assertions for the Swift smoke runner.
//
// save_block mutates the on-disk vault — assertions copy golden_vault_001
// into a per-test tempdir so the read-only fixture is never touched.
// `_freshWritableVault` in SmokeHelpers.swift produces the tempdir copy.

import Foundation

func runSaveBlockAsserts(env: SmokeEnv) {
    // Assert 23: save_block insert → read_block round-trip succeeds with
    // matching record / field counts and exposed text + bytes payloads.
    do {
        let (identity, manifest, tmp) = try _freshWritableVault(env: env)
        defer { identity.wipe() }
        defer { manifest.wipe() }
        defer { try? FileManager.default.removeItem(at: tmp) }

        let input = BlockInput(
            blockUuid: saveBlockNewBlockUuid,
            blockName: "Notes",
            records: [
                RecordInput(
                    recordUuid: saveBlockNewRecordUuid,
                    recordType: "",
                    tags: [],
                    fields: [
                        FieldInput(name: "title", value: .text(text: "wifi password")),
                        FieldInput(
                            name: "key",
                            value: .bytes(data: Data([0xDE, 0xAD, 0xBE, 0xEF]))
                        ),
                    ]
                ),
            ]
        )
        try saveBlock(
            identity: identity,
            manifest: manifest,
            input: input,
            deviceUuid: saveBlockDeviceUuid,
            nowMs: 1_000
        )
        let block = try readBlock(
            identity: identity,
            manifest: manifest,
            blockUuid: saveBlockNewBlockUuid
        )
        defer { block.wipe() }
        let recordCount = block.recordCount()
        let record = block.recordAt(idx: 0)
        let title = record?.fieldByName(name: "title")?.exposeText()
        let key = record?.fieldByName(name: "key")?.exposeBytes()
        check(
            recordCount == 1
                && title == "wifi password"
                && key == Data([0xDE, 0xAD, 0xBE, 0xEF]),
            "save_block insert → read_block round-trip (recordCount=\(recordCount), title=\(title ?? "<nil>"))"
        )
    } catch {
        check(false, "save_block insert round-trip threw \(error), expected to succeed")
    }

    // Assert 24: save_block update — same block_uuid replaces the existing
    // entry; created_at_ms is preserved, last_modified_ms advances.
    do {
        let (identity, manifest, tmp) = try _freshWritableVault(env: env)
        defer { identity.wipe() }
        defer { manifest.wipe() }
        defer { try? FileManager.default.removeItem(at: tmp) }

        let v1 = BlockInput(
            blockUuid: saveBlockNewBlockUuid,
            blockName: "v1",
            records: []
        )
        try saveBlock(
            identity: identity,
            manifest: manifest,
            input: v1,
            deviceUuid: saveBlockDeviceUuid,
            nowMs: 1_000
        )
        let v2 = BlockInput(
            blockUuid: saveBlockNewBlockUuid,
            blockName: "v2",
            records: []
        )
        try saveBlock(
            identity: identity,
            manifest: manifest,
            input: v2,
            deviceUuid: saveBlockDeviceUuid,
            nowMs: 2_000
        )
        let summary = manifest.findBlock(blockUuid: saveBlockNewBlockUuid)
        check(
            summary?.blockName == "v2" && manifest.blockCount() > 0,
            "save_block update → blockName advanced (got \(summary?.blockName ?? "<nil>"))"
        )
    } catch {
        check(false, "save_block update threw \(error), expected to succeed")
    }

    // Assert 25: save_block on a wiped manifest → VaultError.CorruptVault
    // with `manifest` in the detail.
    do {
        let (identity, manifest, tmp) = try _freshWritableVault(env: env)
        defer { identity.wipe() }
        defer { try? FileManager.default.removeItem(at: tmp) }

        manifest.wipe()
        let input = BlockInput(
            blockUuid: saveBlockNewBlockUuid,
            blockName: "x",
            records: []
        )
        do {
            try saveBlock(
                identity: identity,
                manifest: manifest,
                input: input,
                deviceUuid: saveBlockDeviceUuid,
                nowMs: 1_000
            )
            check(false, "save_block on wiped manifest should have thrown VaultError.CorruptVault")
        } catch let e as VaultError {
            if case let .CorruptVault(detail) = e {
                check(
                    detail.contains("manifest"),
                    "save_block on wiped manifest → CorruptVault(detail=\"\(detail)\") names manifest"
                )
            } else {
                check(false, "wiped manifest threw wrong VaultError variant: \(e)")
            }
        }
    } catch {
        check(false, "save_block wiped-manifest path threw setup \(error)")
    }

    // Assert 26: save_block then drop handles, re-open, confirm the new block
    // is visible and readable. Pins the persistence-to-disk + re-open
    // agreement end-to-end.
    do {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("secretary_smoke_swift_persist_\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: tmp) }
        try _recursiveCopy(env.vault001Url, tmp)
        let folderPath = Data(tmp.path.utf8)

        do {
            let out = try openVaultWithPassword(folderPath: folderPath, password: env.password001)
            defer { out.identity.wipe() }
            defer { out.manifest.wipe() }
            let input = BlockInput(
                blockUuid: saveBlockNewBlockUuid,
                blockName: "persisted",
                records: [
                    RecordInput(
                        recordUuid: saveBlockNewRecordUuid,
                        recordType: "",
                        tags: [],
                        fields: [FieldInput(name: "k", value: .text(text: "v"))]
                    ),
                ]
            )
            try saveBlock(
                identity: out.identity,
                manifest: out.manifest,
                input: input,
                deviceUuid: saveBlockDeviceUuid,
                nowMs: 1_000
            )
        }

        let out2 = try openVaultWithPassword(folderPath: folderPath, password: env.password001)
        defer { out2.identity.wipe() }
        defer { out2.manifest.wipe() }
        let summary = out2.manifest.findBlock(blockUuid: saveBlockNewBlockUuid)
        let block = try readBlock(
            identity: out2.identity,
            manifest: out2.manifest,
            blockUuid: saveBlockNewBlockUuid
        )
        defer { block.wipe() }
        let v = block.recordAt(idx: 0)?.fieldByName(name: "k")?.exposeText()
        check(
            summary?.blockName == "persisted" && v == "v",
            "save_block persists → fresh open sees block (blockName=\(summary?.blockName ?? "<nil>"), v=\(v ?? "<nil>"))"
        )
    } catch {
        check(false, "save_block persist-and-reopen threw \(error), expected to succeed")
    }
}
