import Foundation

/// Pure lowercase/uppercase hex → bytes decoder for vault-UUID hex strings.
/// Returns `nil` for an odd length or any non-hex nibble. Empty in → empty out.
public enum HexUuid {
    public static func bytes(fromHex hex: String) -> [UInt8]? {
        let scalars = Array(hex.unicodeScalars)
        guard scalars.count % 2 == 0 else { return nil }
        var out = [UInt8]()
        out.reserveCapacity(scalars.count / 2)
        var index = 0
        while index < scalars.count {
            guard let hi = nibble(scalars[index]), let lo = nibble(scalars[index + 1]) else {
                return nil
            }
            out.append(UInt8(hi << 4 | lo))
            index += 2
        }
        return out
    }

    private static func nibble(_ scalar: Unicode.Scalar) -> Int? {
        switch scalar {
        case "0"..."9": return Int(scalar.value - 48)        // '0' == 48
        case "a"..."f": return Int(scalar.value - 87)        // 'a' == 97 → 10
        case "A"..."F": return Int(scalar.value - 55)        // 'A' == 65 → 10
        default: return nil
        }
    }
}
