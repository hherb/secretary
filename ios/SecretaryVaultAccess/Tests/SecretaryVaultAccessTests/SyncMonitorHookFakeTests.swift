import XCTest
import SecretaryVaultAccess
import SecretaryVaultAccessTesting

@MainActor
final class SyncMonitorHookFakeTests: XCTestCase {
    func testSpyCountsCalls() {
        let hook = FakeSyncMonitorHook()
        hook.muteSelfWrite()
        hook.muteSelfWrite()
        hook.acknowledge()
        XCTAssertEqual(hook.muteCalls, 2)
        XCTAssertEqual(hook.acknowledgeCalls, 1)
    }
    func testMuteWindowConstantIsAtLeastDebounce() {
        // The self-write mute must outlast the change-detection debounce so our own
        // write's pulse is suppressed rather than raising a spurious badge.
        XCTAssertGreaterThanOrEqual(
            ChangeDetectionTuning.defaultSelfWriteMuteWindow,
            ChangeDetectionTuning.defaultDebounceWindow)
    }
}
