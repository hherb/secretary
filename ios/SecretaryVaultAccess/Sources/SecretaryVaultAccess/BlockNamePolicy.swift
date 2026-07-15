import Foundation

/// Whether a candidate block name collides with an existing block's display name.
/// Pure + FFI-free so it is host-testable without a simulator. Mirror of Android
/// `blockNameCollides` (PR #432), named after `MovePolicy`.
///
/// UX layer ONLY: the write path always allows duplicate block names (they are
/// UUID-keyed and harmless); this drives a warn-but-allow affordance, never a
/// hard reject.
public enum BlockNamePolicy {
    /// True when `candidate` (after trimming) matches the display name of some block in
    /// `existing` OTHER than `excludeUuid`, compared **case-insensitively**. The comparison
    /// is locale-independent via `caseInsensitiveCompare(_:)` — deliberately NOT
    /// `localizedCaseInsensitiveCompare` (Turkish-i-class locale bugs); this is the Swift
    /// analogue of Android's `equals(ignoreCase = true)`. `candidate` is trimmed; `block.name`
    /// is compared untrimmed (stored names are already trimmed on write, so this can only
    /// ever *under*-warn, never falsely warn). `excludeUuid` is the block being renamed
    /// (`nil` on create), so renaming a block without changing its name is never a collision.
    /// Blank candidate → `false` (the blank-name guard in `confirmBlockName` owns that case).
    public static func hasNameCollision(candidate: String,
                                        existing: [BlockSummary],
                                        excludeUuid: [UInt8]? = nil) -> Bool {
        let trimmed = candidate.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { return false }
        return existing.contains { block in
            (excludeUuid == nil || block.uuid != excludeUuid!) &&
                trimmed.caseInsensitiveCompare(block.name) == .orderedSame
        }
    }
}
