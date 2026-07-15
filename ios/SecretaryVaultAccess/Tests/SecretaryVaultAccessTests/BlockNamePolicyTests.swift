import XCTest
import SecretaryVaultAccess

/// Host tests for the pure block-name collision predicate. One-for-one mirror of
/// Android `BlockNamePolicyTest.kt` (PR #432). Runs in `swift test` Step 1 (no
/// xcframework), like `MovePolicyTests`.
final class BlockNamePolicyTests: XCTestCase {
    private func block(_ b: UInt8, _ name: String) -> BlockSummary {
        BlockSummary(uuid: Array(repeating: b, count: 16), name: name, createdAtMs: 0, lastModMs: 0)
    }
    private var work: BlockSummary { block(0x11, "Work") }
    private var personal: BlockSummary { block(0x22, "Personal") }
    private var existing: [BlockSummary] { [work, personal] }

    func testEmptyBlockListNeverCollides() {
        XCTAssertFalse(BlockNamePolicy.hasNameCollision(candidate: "Work", existing: []))
    }
    func testUniqueNameDoesNotCollide() {
        XCTAssertFalse(BlockNamePolicy.hasNameCollision(candidate: "Finance", existing: existing))
    }
    func testExactDuplicateCollides() {
        XCTAssertTrue(BlockNamePolicy.hasNameCollision(candidate: "Work", existing: existing))
    }
    func testSurroundingWhitespaceTrimmedBeforeComparison() {
        XCTAssertTrue(BlockNamePolicy.hasNameCollision(candidate: "  Work  ", existing: existing))
    }
    func testCaseOnlyDifferenceCollides() {
        XCTAssertTrue(BlockNamePolicy.hasNameCollision(candidate: "work", existing: existing))
    }
    func testBlankCandidateNeverCollides() {
        XCTAssertFalse(BlockNamePolicy.hasNameCollision(candidate: "   ", existing: existing))
    }
    func testRenameToOwnCurrentNameDoesNotCollide() {
        XCTAssertFalse(BlockNamePolicy.hasNameCollision(candidate: "Work", existing: existing, excludeUuid: work.uuid))
    }
    func testRenameToDifferentExistingNameCollides() {
        XCTAssertTrue(BlockNamePolicy.hasNameCollision(candidate: "Personal", existing: existing, excludeUuid: work.uuid))
    }
}
