import SwiftUI
import UIKit

/// Native counterpart to the desktop navy, ivory, and gold visual refresh.
enum SecretaryPalette {
    static let navy = Color(red: 23 / 255, green: 35 / 255, blue: 63 / 255)
    static let gold = Color(red: 201 / 255, green: 155 / 255, blue: 69 / 255)

    static let background = adaptive(
        light: UIColor(red: 242 / 255, green: 239 / 255, blue: 231 / 255, alpha: 1),
        dark: UIColor(red: 11 / 255, green: 18 / 255, blue: 32 / 255, alpha: 1))
    static let surface = adaptive(
        light: UIColor(red: 1, green: 253 / 255, blue: 248 / 255, alpha: 1),
        dark: UIColor(red: 20 / 255, green: 29 / 255, blue: 47 / 255, alpha: 1))
    static let primary = adaptive(
        light: UIColor(red: 23 / 255, green: 35 / 255, blue: 63 / 255, alpha: 1),
        dark: UIColor(red: 223 / 255, green: 184 / 255, blue: 102 / 255, alpha: 1))

    private static func adaptive(light: UIColor, dark: UIColor) -> Color {
        Color(uiColor: UIColor { traits in
            traits.userInterfaceStyle == .dark ? dark : light
        })
    }
}

/// Small mobile rendering of the desktop book-and-quill brand language.
struct SecretaryBrandMark: View {
    var size: CGFloat = 58

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: size * 0.24, style: .continuous)
                .fill(SecretaryPalette.navy)
            RoundedRectangle(cornerRadius: size * 0.24, style: .continuous)
                .stroke(SecretaryPalette.gold.opacity(0.5), lineWidth: 1)
            Image(systemName: "book.closed.fill")
                .font(.system(size: size * 0.39, weight: .semibold))
                .foregroundStyle(SecretaryPalette.gold)
            Image(systemName: "pencil.and.scribble")
                .font(.system(size: size * 0.2, weight: .bold))
                .foregroundStyle(Color.white)
                .offset(x: size * 0.19, y: -size * 0.2)
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}

/// Reusable hierarchy for the mobile entry, unlock, and creation forms.
struct SecretaryBrandHeader: View {
    let title: String
    let subtitle: String

    var body: some View {
        HStack(spacing: 16) {
            SecretaryBrandMark()
            VStack(alignment: .leading, spacing: 3) {
                Text("SECRETARY")
                    .font(.caption2.weight(.bold))
                    .tracking(1.2)
                    .foregroundStyle(SecretaryPalette.gold)
                Text(title)
                    .font(.title2.weight(.bold))
                    .foregroundStyle(.primary)
                Text(subtitle)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.vertical, 8)
    }
}

private struct SecretaryScreenChrome: ViewModifier {
    func body(content: Content) -> some View {
        content
            .scrollContentBackground(.hidden)
            .background(SecretaryPalette.background)
            .tint(SecretaryPalette.primary)
            .navigationBarTitleDisplayMode(.inline)
            .toolbarBackground(SecretaryPalette.navy, for: .navigationBar)
            .toolbarBackground(.visible, for: .navigationBar)
            .toolbarColorScheme(.dark, for: .navigationBar)
    }
}

extension View {
    /// Branded native chrome while retaining platform Form/List behavior.
    func secretaryScreenChrome() -> some View {
        modifier(SecretaryScreenChrome())
    }

    /// Treat the vault master password as an app-local secret rather than a
    /// website credential. iOS 26 can otherwise infer a sign-up form from two
    /// adjacent secure fields and place an Automatic Strong Password cover over
    /// both fields, preventing manual entry when the app has no web credential
    /// association. `.oneTimeCode` opts this local secret out of that heuristic.
    func secretaryVaultPasswordInput() -> some View {
        textContentType(.oneTimeCode)
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()
    }
}
