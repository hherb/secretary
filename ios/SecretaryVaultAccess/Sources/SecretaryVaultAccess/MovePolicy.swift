import Foundation

/// Policy for whether the per-record Move affordance has anywhere to go. A move needs the record's
/// own block plus at least one distinct target block. The SwiftUI browse screen gates the Move
/// swipe action on the view model's `hasMoveTargets`, which delegates here. UX layer only: the move
/// picker's empty-state and the Rust `move_record_impl` guard remain authoritative (parity with
/// desktop #273 / mobile #429). The threshold is a named constant — never a magic number.
public enum MovePolicy {
    /// The record's own block + at least one distinct target block.
    static let minBlocksToMove = 2

    /// True when at least one block OTHER than the record's own exists, so a Move has a real
    /// destination. `blockCount` is the live-block count the browse VM already holds — the same
    /// collection the picker enumerates — so below the threshold Move can only dead-end.
    public static func hasMoveTargets(blockCount: Int) -> Bool { blockCount >= minBlocksToMove }
}
