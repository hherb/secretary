import XCTest
import Foundation
@testable import SecretaryKit

/// #229: the FFI-boundary password copy must be scrubbed after use.
final class ZeroizingDataTests: XCTestCase {
    func testZeroizeOverwritesAllBytes() {
        var d = Data([1, 2, 3, 4, 5])
        zeroize(&d)
        XCTAssertEqual(d, Data(repeating: 0, count: 5))
    }

    func testZeroizeEmptyDataIsNoOp() {
        var d = Data()
        zeroize(&d)  // must not crash on a zero-length range
        XCTAssertEqual(d.count, 0)
    }

    func testWithZeroizingDataExposesBytesToBody() {
        let bytes: [UInt8] = [9, 8, 7]
        let seen = withZeroizingData(bytes) { d in [UInt8](d) }
        XCTAssertEqual(seen, [9, 8, 7])
    }

    func testWithZeroizingDataReturnsBodyResult() {
        let n = withZeroizingData([1, 2, 3]) { d in d.count }
        XCTAssertEqual(n, 3)
    }

    func testWithZeroizingDataPropagatesThrow() {
        struct Boom: Error {}
        // The defer-scrub still runs on the throwing path; we assert the error propagates
        // (the scrub itself is proven by testZeroizeOverwritesAllBytes — same code path).
        XCTAssertThrowsError(try withZeroizingData([1, 2, 3]) { _ in throw Boom() })
    }
}
