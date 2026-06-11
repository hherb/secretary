import XCTest
@testable import SecretaryDeviceUnlock

final class ZeroizingTests: XCTestCase {
    func testZeroizeOverwritesBuffer() {
        var bytes: [UInt8] = [1, 2, 3, 4, 255]
        zeroize(&bytes)
        XCTAssertEqual(bytes, [0, 0, 0, 0, 0])
    }

    func testZeroizeEmptyBufferIsNoop() {
        var empty: [UInt8] = []
        zeroize(&empty) // must not trap on a zero-length buffer
        XCTAssertEqual(empty, [])
    }
}
