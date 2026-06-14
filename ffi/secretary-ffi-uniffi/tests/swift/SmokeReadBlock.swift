// B.4b read_block assertions for the Swift smoke runner.
//
// Covers:
//   - Assert 19: read_block success → record_count == 1 + field_count == 2
//   - Assert 20: field_by_name("password").expose_text() == "hunter2"
//   - Assert 21: read_block(unknown_uuid) → VaultError.BlockNotFound
//   - Assert 22: wipe → record_count == 0

import Foundation

func runReadBlockAsserts(env: SmokeEnv) {
    // Assert 19: read_block success — record_count == 1 + field_count == 2.
    do {
        let folderPath = Data(env.vault001Url.path.utf8)
        let out = try openVaultWithPassword(folderPath: folderPath, password: env.password001)
        defer { out.identity.wipe() }
        defer { out.manifest.wipe() }
        let block = try readBlock(
            identity: out.identity,
            manifest: out.manifest,
            blockUuid: vault001BlockUuid,
            includeDeleted: false
        )
        defer { block.wipe() }
        let recordCount = block.recordCount()
        let record = block.recordAt(idx: 0)
        let fieldCount = record?.fieldCount() ?? 0
        check(
            recordCount == 1 && fieldCount == 2,
            "read_block success → record_count == 1 + field_count == 2 (got \(recordCount), \(fieldCount))"
        )
    } catch {
        check(false, "read_block success threw \(error), expected to succeed")
    }

    // Assert 20: field_by_name("password").expose_text() == "hunter2".
    do {
        let folderPath = Data(env.vault001Url.path.utf8)
        let out = try openVaultWithPassword(folderPath: folderPath, password: env.password001)
        defer { out.identity.wipe() }
        defer { out.manifest.wipe() }
        let block = try readBlock(
            identity: out.identity,
            manifest: out.manifest,
            blockUuid: vault001BlockUuid,
            includeDeleted: false
        )
        defer { block.wipe() }
        let record = block.recordAt(idx: 0)!
        let pwField = record.fieldByName(name: "password")!
        let secret = pwField.exposeText()
        check(
            secret == "hunter2",
            "field_by_name(\"password\").expose_text() == \"hunter2\" (got \"\(secret ?? "<nil>")\")"
        )
    } catch {
        check(false, "expose_text threw \(error), expected to succeed")
    }

    // Assert 21: read_block(unknown_uuid) → VaultError.BlockNotFound(uuid matches).
    do {
        let folderPath = Data(env.vault001Url.path.utf8)
        let out = try openVaultWithPassword(folderPath: folderPath, password: env.password001)
        defer { out.identity.wipe() }
        defer { out.manifest.wipe() }
        let unknownUuid = Data(repeating: 0, count: 16)
        _ = try readBlock(
            identity: out.identity,
            manifest: out.manifest,
            blockUuid: unknownUuid,
            includeDeleted: false
        )
        check(false, "read_block(unknown_uuid) should have thrown VaultError.BlockNotFound")
    } catch let e as VaultError {
        if case let .BlockNotFound(uuidHex) = e {
            check(
                uuidHex == "00000000000000000000000000000000",
                "read_block(unknown_uuid) → VaultError.BlockNotFound(uuid_hex=\"\(uuidHex)\")"
            )
        } else {
            check(false, "unknown UUID threw wrong VaultError variant: \(e)")
        }
    } catch {
        check(false, "unknown UUID threw \(error), expected VaultError.BlockNotFound")
    }

    // Assert 22: wipe → record_count == 0.
    do {
        let folderPath = Data(env.vault001Url.path.utf8)
        let out = try openVaultWithPassword(folderPath: folderPath, password: env.password001)
        defer { out.identity.wipe() }
        defer { out.manifest.wipe() }
        let block = try readBlock(
            identity: out.identity,
            manifest: out.manifest,
            blockUuid: vault001BlockUuid,
            includeDeleted: false
        )
        block.wipe()
        let countAfter = block.recordCount()
        check(
            countAfter == 0,
            "wipe → record_count == 0 (got \(countAfter))"
        )
    } catch {
        check(false, "wipe threw \(error), expected to succeed")
    }
}
