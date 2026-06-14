import Foundation

/// A two-sided rendezvous used by responsiveness tests to hold a fake port
/// *mid-call*. The fake calls `enterAndWait()` from its (off-main-actor) port
/// method; the test calls `waitUntilEntered()` to learn the port is in flight,
/// makes its main-actor assertions, then `release()`s to let the fake return.
///
/// Being able to run main-actor assertions *while the port is suspended* is the
/// proof that the open/create call did not block the main actor — against the
/// old synchronous-on-main-actor code the test would deadlock instead.
///
/// Single-waiter contract: at most one caller may be suspended in
/// `enterAndWait()` and one in `waitUntilEntered()` at a time (the responsiveness
/// tests use exactly one of each). Violating this overwrites a stored
/// continuation; the `assertionFailure` guards below catch that in test builds.
public actor SuspensionGate {
    private var entered = false
    private var enteredWaiter: CheckedContinuation<Void, Never>?
    private var released = false
    private var releaseWaiter: CheckedContinuation<Void, Never>?

    public init() {}

    /// Fake side: mark entry (waking any `waitUntilEntered`), then suspend until
    /// `release()`. Returns immediately if already released.
    public func enterAndWait() async {
        entered = true
        enteredWaiter?.resume()
        enteredWaiter = nil
        if released { return }
        assert(releaseWaiter == nil, "SuspensionGate: only one enterAndWait() waiter allowed at a time")
        await withCheckedContinuation { releaseWaiter = $0 }
    }

    /// Test side: suspend until the fake has entered its port method.
    public func waitUntilEntered() async {
        if entered { return }
        assert(enteredWaiter == nil, "SuspensionGate: only one waitUntilEntered() waiter allowed at a time")
        await withCheckedContinuation { enteredWaiter = $0 }
    }

    /// Test side: let a suspended fake return.
    public func release() {
        released = true
        releaseWaiter?.resume()
        releaseWaiter = nil
    }
}
