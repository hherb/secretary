/// One numbered word of a recovery phrase, for display in the mnemonic step.
/// 1-based `number` matches how users transcribe BIP-39 phrases.
public struct MnemonicWord: Equatable {
    public let number: Int
    public let word: String

    public init(number: Int, word: String) {
        self.number = number
        self.word = word
    }
}

/// Split a space-separated recovery phrase into numbered words for display.
/// Whitespace-tolerant (collapses runs, ignores leading/trailing). Pure: does no
/// I/O and holds no secret beyond the returned value, which the caller drops once
/// the mnemonic step is dismissed.
public func groupMnemonic(_ phrase: String) -> [MnemonicWord] {
    phrase
        .split(whereSeparator: { $0.isWhitespace })
        .enumerated()
        .map { MnemonicWord(number: $0.offset + 1, word: String($0.element)) }
}
