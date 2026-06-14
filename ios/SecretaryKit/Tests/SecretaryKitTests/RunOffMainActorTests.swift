import XCTest
@testable import SecretaryKit

/// Focused contract tests for the `runOffMainActor` offload helper, independent
/// of the FFI integration paths that also use it.
final class RunOffMainActorTests: XCTestCase {
    /// A non-`Sendable` reference type — proves the helper transfers such a return
    /// back across the suspension (the reason it uses `CheckedContinuation`
    /// instead of `Task.detached`, whose `Success` must be `Sendable`).
    private final class Box {
        let value: Int
        init(_ value: Int) { self.value = value }
    }

    func testReturnsNonSendableValue() async throws {
        let box = try await runOffMainActor { Box(42) }
        XCTAssertEqual(box.value, 42)
    }

    func testPropagatesThrownError() async {
        struct Boom: Error {}
        do {
            _ = try await runOffMainActor { () throws -> Int in throw Boom() }
            XCTFail("expected runOffMainActor to rethrow")
        } catch {
            XCTAssertTrue(error is Boom)
        }
    }
}
