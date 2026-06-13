import XCTest
@testable import SecretaryVaultAccess

final class MnemonicWordTests: XCTestCase {
    func testGroupsTwentyFourWordsNumbered() {
        let phrase = (1...24).map { "w\($0)" }.joined(separator: " ")
        let rows = groupMnemonic(phrase)
        XCTAssertEqual(rows.count, 24)
        XCTAssertEqual(rows.first, MnemonicWord(number: 1, word: "w1"))
        XCTAssertEqual(rows.last, MnemonicWord(number: 24, word: "w24"))
    }

    func testCollapsesExtraWhitespace() {
        let rows = groupMnemonic("  alpha   beta \n gamma ")
        XCTAssertEqual(rows, [
            MnemonicWord(number: 1, word: "alpha"),
            MnemonicWord(number: 2, word: "beta"),
            MnemonicWord(number: 3, word: "gamma"),
        ])
    }

    func testEmptyPhraseYieldsNoRows() {
        XCTAssertEqual(groupMnemonic("   "), [])
    }
}
