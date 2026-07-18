import SwiftUI
import AppKit

/// Resolves the `NSWindow` hosting a SwiftUI view. Used so `MacBrowseView` can
/// scope its `willClose` session-wipe to its own window (see `browseWindowID`),
/// rather than reacting to every window's close. `viewDidMoveToWindow` is the
/// canonical hook: it fires with a non-nil `window` once the view is attached.
struct WindowAccessor: NSViewRepresentable {
    let onResolve: (NSWindow?) -> Void

    func makeNSView(context: Context) -> NSView { ResolvingView(onResolve: onResolve) }
    func updateNSView(_ nsView: NSView, context: Context) {}

    private final class ResolvingView: NSView {
        private let onResolve: (NSWindow?) -> Void
        init(onResolve: @escaping (NSWindow?) -> Void) {
            self.onResolve = onResolve
            super.init(frame: .zero)
        }
        @available(*, unavailable)
        required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            onResolve(window)
        }
    }
}
