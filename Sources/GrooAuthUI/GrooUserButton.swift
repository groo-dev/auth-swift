import GrooAuth
import SwiftUI

/// The circle with a person's initials in it.
///
/// Its own view rather than something drawn inside `GrooUserButton`, because the
/// account screen shows the same mark at a different size and two drawings of one
/// identity drift.
public struct GrooAvatar: View {
    private let name: String?
    private let email: String?
    private let size: CGFloat

    @Environment(\.grooAuthTheme) private var theme

    public init(name: String?, email: String?, size: CGFloat = 32) {
        self.name = name
        self.email = email
        self.size = size
    }

    public var body: some View {
        Circle()
            .fill(theme.accent)
            .frame(width: size, height: size)
            .overlay {
                Text(initials)
                    .font(.system(size: size * 0.42, weight: .semibold))
                    .foregroundStyle(theme.onAccent)
            }
            .accessibilityHidden(true)
    }

    /// Up to two initials from the name, or one from the email, or a person
    /// glyph's worth of nothing. Never empty: an empty circle reads as a failed
    /// image load rather than as an avatar.
    private var initials: String {
        let words = (name ?? "").split(separator: " ").prefix(2)
        let fromName = words.compactMap { $0.first }.map(String.init).joined().uppercased()
        if !fromName.isEmpty { return fromName }
        if let first = email?.first { return String(first).uppercased() }
        return "?"
    }
}

/// Opens the account screen. The thing an app puts in a toolbar or a settings row.
///
/// Clerk's `UserButton` is a menu; this is a button that presents a screen. On a
/// phone a menu of account actions is a worse version of the screen it would open
/// — the same taps, less room, and no space to say what anything does.
public struct GrooUserButton: View {
    private let controller: GrooAuthController
    private let consoleURL: URL?
    private let showsLabel: Bool

    @Environment(\.grooAuthTheme) private var theme
    @State private var isPresentingAccount = false

    /// - Parameters:
    ///   - consoleURL: the hosted account page, passed through to
    ///     `GrooAccountView`. `nil` hides the link.
    ///   - showsLabel: `true` renders name and email beside the avatar, for a
    ///     settings row; `false` is the bare circle for a toolbar.
    public init(controller: GrooAuthController, consoleURL: URL? = nil, showsLabel: Bool = false) {
        self.controller = controller
        self.consoleURL = consoleURL
        self.showsLabel = showsLabel
    }

    public var body: some View {
        Button {
            isPresentingAccount = true
        } label: {
            if showsLabel {
                HStack(spacing: 12) {
                    GrooAvatar(name: controller.user?.name, email: controller.user?.email, size: 44)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(displayName).font(.headline).foregroundStyle(theme.ink)
                        if let email = controller.user?.email {
                            Text(email).font(.subheadline).foregroundStyle(theme.muted)
                        }
                    }
                    Spacer()
                    Image(systemName: "chevron.right")
                        .font(.footnote.weight(.semibold))
                        .foregroundStyle(theme.muted)
                }
            } else {
                GrooAvatar(name: controller.user?.name, email: controller.user?.email)
            }
        }
        .accessibilityLabel("Account")
        .accessibilityIdentifier("grooUserButton")
        .sheet(isPresented: $isPresentingAccount) {
            GrooAccountView(controller: controller, consoleURL: consoleURL)
                .environment(\.grooAuthTheme, theme)
        }
    }

    private var displayName: String {
        if let name = controller.user?.name, !name.isEmpty { return name }
        if let email = controller.user?.email, let local = email.split(separator: "@").first {
            return String(local)
        }
        return "Your Account"
    }
}
