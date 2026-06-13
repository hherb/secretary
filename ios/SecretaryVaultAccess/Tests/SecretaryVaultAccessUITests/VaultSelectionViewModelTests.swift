import XCTest
import SecretaryVaultAccess
import SecretaryVaultAccessTesting
@testable import SecretaryVaultAccessUI

@MainActor
final class VaultSelectionViewModelTests: XCTestCase {
    func testLoadPersistedEmptyWhenNoneStored() {
        let vm = VaultSelectionViewModel(store: FakeVaultLocationStore(),
                                        probe: FakeVaultShapeProbe(answer: .success(true)))
        vm.loadPersisted()
        XCTAssertEqual(vm.state, .empty)
    }

    func testLoadPersistedLocatedWhenStored() {
        let store = FakeVaultLocationStore(
            stored: VaultLocation(displayName: "MyVault", bookmark: Data([0x01])))
        let vm = VaultSelectionViewModel(store: store,
                                        probe: FakeVaultShapeProbe(answer: .success(true)))
        vm.loadPersisted()
        XCTAssertEqual(vm.state, .located(displayName: "MyVault"))
    }

    func testRecordSelectionPersistsAndLocates() {
        let store = FakeVaultLocationStore()
        let vm = VaultSelectionViewModel(store: store,
                                        probe: FakeVaultShapeProbe(answer: .success(true)))
        vm.recordSelection(bookmark: Data([0xAB]), displayName: "Picked")
        XCTAssertEqual(vm.state, .located(displayName: "Picked"))
        XCTAssertEqual(store.load(),
                       VaultLocation(displayName: "Picked", bookmark: Data([0xAB])))
    }

    func testChooseDifferentClearsToEmpty() {
        let store = FakeVaultLocationStore(
            stored: VaultLocation(displayName: "V", bookmark: Data([0x01])))
        let vm = VaultSelectionViewModel(store: store,
                                        probe: FakeVaultShapeProbe(answer: .success(true)))
        vm.loadPersisted()
        vm.chooseDifferent()
        XCTAssertEqual(vm.state, .empty)
        XCTAssertNil(store.load())
    }

    func testBeginAccessThrowsWhenEmpty() {
        let vm = VaultSelectionViewModel(store: FakeVaultLocationStore(),
                                        probe: FakeVaultShapeProbe(answer: .success(true)))
        vm.loadPersisted()
        XCTAssertThrowsError(try vm.beginAccess()) { err in
            XCTAssertEqual(err as? VaultSelectionError, .noVaultSelected)
        }
    }

    func testBeginAccessReturnsScopedPathWhenLocated() throws {
        let store = FakeVaultLocationStore(
            stored: VaultLocation(displayName: "V", bookmark: Data([0x01])),
            pathDataToReturn: Data("/vaults/v".utf8))
        let vm = VaultSelectionViewModel(store: store,
                                        probe: FakeVaultShapeProbe(answer: .success(true)))
        vm.loadPersisted()
        let scoped = try vm.beginAccess()
        XCTAssertEqual(scoped.pathData, Data("/vaults/v".utf8))
        scoped.end()
        XCTAssertEqual(store.liveScopes, 0)
    }

    func testBeginAccessUnavailableTransitionsStateAndRetainsLocation() {
        let store = FakeVaultLocationStore(
            stored: VaultLocation(displayName: "V", bookmark: Data([0x01])))
        store.beginAccessError = .locationUnavailable("vault moved")
        let vm = VaultSelectionViewModel(store: store,
                                        probe: FakeVaultShapeProbe(answer: .success(true)))
        vm.loadPersisted()
        XCTAssertThrowsError(try vm.beginAccess())
        XCTAssertEqual(vm.state, .unavailable(reason: "vault moved"))
        XCTAssertNotNil(store.load(), "an unavailable vault is NOT silently cleared")
    }

    func testLoadPersistedPreservesUnavailableReason() {
        let store = FakeVaultLocationStore(
            stored: VaultLocation(displayName: "V", bookmark: Data([0x01])))
        store.beginAccessError = .locationUnavailable("vault moved")
        let vm = VaultSelectionViewModel(store: store,
                                        probe: FakeVaultShapeProbe(answer: .success(true)))
        vm.loadPersisted()
        XCTAssertThrowsError(try vm.beginAccess())
        XCTAssertEqual(vm.state, .unavailable(reason: "vault moved"))
        // A re-appear (onAppear → loadPersisted) must NOT silently downgrade the
        // surfaced reason back to .located, which would hand the user an "Open"
        // button that just fails again with no explanation.
        vm.loadPersisted()
        XCTAssertEqual(vm.state, .unavailable(reason: "vault moved"))
    }

    func testChooseDifferentFromUnavailableRecoversToEmpty() {
        let store = FakeVaultLocationStore(
            stored: VaultLocation(displayName: "V", bookmark: Data([0x01])))
        store.beginAccessError = .locationUnavailable("vault moved")
        let vm = VaultSelectionViewModel(store: store,
                                        probe: FakeVaultShapeProbe(answer: .success(true)))
        vm.loadPersisted()
        XCTAssertThrowsError(try vm.beginAccess())
        XCTAssertEqual(vm.state, .unavailable(reason: "vault moved"))
        // The user can recover from the dead-end: choosing a different vault
        // clears the bad location and returns to the empty state.
        vm.chooseDifferent()
        XCTAssertEqual(vm.state, .empty)
        XCTAssertNil(store.load())
    }

    func testBeginAccessNonSelectionErrorStillTransitionsToUnavailable() {
        let store = ThrowingNonSelectionStore(
            location: VaultLocation(displayName: "V", bookmark: Data([0x01])))
        let vm = VaultSelectionViewModel(store: store,
                                        probe: FakeVaultShapeProbe(answer: .success(true)))
        vm.loadPersisted()
        XCTAssertThrowsError(try vm.beginAccess()) { err in
            XCTAssertEqual(err as? GenericError, GenericError(message: "boom"),
                           "the ORIGINAL error must be rethrown unchanged")
        }
        guard case .unavailable = vm.state else {
            return XCTFail("state must transition to .unavailable even for a non-VaultSelectionError")
        }
    }

    func testBalanceAcrossManyOpenLockCycles() throws {
        let store = FakeVaultLocationStore(
            stored: VaultLocation(displayName: "V", bookmark: Data([0x01])))
        let vm = VaultSelectionViewModel(store: store,
                                        probe: FakeVaultShapeProbe(answer: .success(true)))
        vm.loadPersisted()
        for _ in 0..<5 {
            let scoped = try vm.beginAccess()
            scoped.end()
        }
        XCTAssertEqual(store.started, 5)
        XCTAssertEqual(store.stopped, 5)
        XCTAssertEqual(store.liveScopes, 0, "no leaked scopes across cycles")
    }

    // --- Import-probe behaviour (Slice 2) ---

    func testConsiderImportOpensWhenFolderIsVault() {
        let store = FakeVaultLocationStore()
        let probe = FakeVaultShapeProbe(answer: .success(true))
        let vm = VaultSelectionViewModel(store: store, probe: probe)
        let outcome = vm.considerImport(url: URL(fileURLWithPath: "/v"),
                                        bookmark: Data("bm".utf8),
                                        displayName: "v")
        XCTAssertEqual(outcome, .opened)
        XCTAssertEqual(store.stored?.displayName, "v")     // persisted
        XCTAssertEqual(vm.state, .located(displayName: "v"))
    }

    func testConsiderImportRejectsNonVault() {
        let store = FakeVaultLocationStore()
        let probe = FakeVaultShapeProbe(answer: .success(false))
        let vm = VaultSelectionViewModel(store: store, probe: probe)
        let outcome = vm.considerImport(url: URL(fileURLWithPath: "/x"),
                                        bookmark: Data("bm".utf8),
                                        displayName: "x")
        XCTAssertEqual(outcome, .notAVault)
        XCTAssertNil(store.stored)                          // NOT persisted
    }

    func testConsiderImportProbeErrorIsUnavailable() {
        struct Boom: Error {}
        let store = FakeVaultLocationStore()
        let probe = FakeVaultShapeProbe(answer: .failure(Boom()))
        let vm = VaultSelectionViewModel(store: store, probe: probe)
        let outcome = vm.considerImport(url: URL(fileURLWithPath: "/x"),
                                        bookmark: Data("bm".utf8),
                                        displayName: "x")
        if case .unavailable = outcome {} else { XCTFail("expected .unavailable") }
        XCTAssertNil(store.stored)
    }
}

/// A store whose `beginAccess` throws a NON-`VaultSelectionError`, to prove the VM
/// still transitions to `.unavailable` (state never lies) and rethrows the original.
private struct GenericError: Error, Equatable { let message: String }

private final class ThrowingNonSelectionStore: VaultLocationStore {
    let location: VaultLocation
    init(location: VaultLocation) { self.location = location }
    func load() -> VaultLocation? { location }
    func persist(_ location: VaultLocation) {}
    func clear() {}
    func beginAccess(_ location: VaultLocation) throws -> ScopedVaultPath {
        throw GenericError(message: "boom")
    }
}
