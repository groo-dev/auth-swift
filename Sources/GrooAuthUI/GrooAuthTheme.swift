import SwiftUI

/// How a consuming app restyles the components in this library.
///
/// SwiftUI has no equivalent of the CSS custom properties `@groo.dev/auth-react`
/// themes with, so the contract is stated as a struct instead. The token NAMES
/// deliberately mirror that SDK's `--ga-*` variables, so one brand definition can
/// drive a web app and a native app without translation.
///
/// This is the middle of three options. Views that cannot be restyled are wrong
/// for a library anyone else adopts — the first adopter whose brand is not green
/// forks it. A headless library that ships only logic abandons the reason to
/// adopt a UI library at all. So: styled views that look deliberate by default,
/// themed through a fixed set of tokens, with `GrooAuthController.session` public
/// for an app that wants its own views over the same logic.
public struct GrooAuthTheme: Sendable {
    /// The colour of the primary action, and the ink that sits on it.
    public var accent: Color
    public var onAccent: Color

    /// Page behind content, and the cards on top of it.
    public var canvas: Color
    public var surface: Color

    /// Body text, secondary text, and hairlines.
    public var ink: Color
    public var muted: Color
    public var line: Color

    /// Destructive actions, and errors.
    public var danger: Color

    public var cornerRadius: CGFloat
    public var titleFont: Font
    public var bodyFont: Font

    public init(
        accent: Color = Color(red: 0.09, green: 0.42, blue: 0.29),
        onAccent: Color = .white,
        canvas: Color = Color(red: 0.95, green: 0.96, blue: 0.95),
        surface: Color = .white,
        ink: Color = Color(red: 0.09, green: 0.13, blue: 0.11),
        muted: Color = Color(red: 0.40, green: 0.44, blue: 0.42),
        line: Color = Color(red: 0.86, green: 0.89, blue: 0.87),
        danger: Color = Color(red: 0.64, green: 0.22, blue: 0.22),
        cornerRadius: CGFloat = 12,
        titleFont: Font = .largeTitle.bold(),
        bodyFont: Font = .body
    ) {
        self.accent = accent
        self.onAccent = onAccent
        self.canvas = canvas
        self.surface = surface
        self.ink = ink
        self.muted = muted
        self.line = line
        self.danger = danger
        self.cornerRadius = cornerRadius
        self.titleFont = titleFont
        self.bodyFont = bodyFont
    }

    /// The default. Matches `--ga-*` in `@groo.dev/auth-react` so an app using
    /// both SDKs looks like one product without configuring either.
    public static let groo = GrooAuthTheme()
}

public extension EnvironmentValues {
    /// ```swift
    /// GrooSignInView()
    ///     .environment(\.grooAuthTheme, GrooAuthTheme(accent: .indigo))
    /// ```
    @Entry var grooAuthTheme: GrooAuthTheme = .groo
}
