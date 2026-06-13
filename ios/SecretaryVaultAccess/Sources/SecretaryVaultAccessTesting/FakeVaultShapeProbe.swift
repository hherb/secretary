import Foundation
import SecretaryVaultAccess

/// In-memory `VaultShapeProbe` returning a pre-seeded answer.
public final class FakeVaultShapeProbe: VaultShapeProbe {
    private let answer: Result<Bool, Error>
    public private(set) var lastFolder: URL?

    public init(answer: Result<Bool, Error>) {
        self.answer = answer
    }

    public func looksLikeVault(_ folder: URL) throws -> Bool {
        lastFolder = folder
        return try answer.get()
    }
}
