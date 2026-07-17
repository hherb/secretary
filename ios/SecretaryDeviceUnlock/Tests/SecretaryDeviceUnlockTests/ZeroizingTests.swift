import XCTest
import SecretaryDeviceUnlock

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

    // Documents the copy-on-write boundary of `zeroize` (#453). `withUnsafeMutableBytes`
    // forces the array unique before mutating, so when the backing buffer is SHARED with
    // another live reference, `zeroize` clears only a fresh COW duplicate — the shared
    // original survives untouched. Consequence: a best-effort wipe at a call site is
    // effective ONLY while the array is uniquely owned. Wiping a still-shared secret
    // (e.g. an enroll task whose password buffer the concurrent sync task still holds) is
    // a harmless no-op on the real bytes, never a guarantee. Call sites that need the wipe
    // to bite must drop all other references FIRST (see the unlock-screen failure paths).
    func testZeroizeOnlyClearsAUniquelyOwnedBuffer() {
        let shared: [UInt8] = [1, 2, 3, 4, 255]
        var aliased = shared // COW-shares `shared`'s backing buffer
        zeroize(&aliased)
        XCTAssertEqual(shared, [1, 2, 3, 4, 255], "shared original survives — zeroize COW-copied")
        XCTAssertEqual(aliased, [0, 0, 0, 0, 0], "the now-unique local copy is cleared")
    }
}
