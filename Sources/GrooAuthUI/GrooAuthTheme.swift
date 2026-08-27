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

    /// The default palette, as named constants.
    ///
    /// Constants rather than expressions inlined into the initialiser below,
    /// because each `grooAdaptive` call builds a fresh platform colour and
    /// `Color` compares those by identity. Inlined, `GrooAuthTheme().surface`
    /// would not equal `GrooAuthTheme.groo.surface` despite drawing the same
    /// pixels.
    ///
    /// Public so a theme that changes one token can build on the rest rather
    /// than restating them.
    public enum Default {
        /// Every colour here is appearance-adaptive, so an app that never
        /// configures a theme looks right in dark mode as well as light.
        public static let accent = Color.grooAdaptive(light: .init(0.09, 0.42, 0.29), dark: .init(0.24, 0.70, 0.49))
        public static let onAccent = Color.grooAdaptive(light: .init(1, 1, 1), dark: .init(0.04, 0.09, 0.07))
        public static let canvas = Color.grooAdaptive(light: .init(0.95, 0.96, 0.95), dark: .init(0.07, 0.09, 0.08))
        public static let surface = Color.grooAdaptive(light: .init(1, 1, 1), dark: .init(0.11, 0.14, 0.12))
        public static let ink = Color.grooAdaptive(light: .init(0.09, 0.13, 0.11), dark: .init(0.93, 0.95, 0.94))
        public static let muted = Color.grooAdaptive(light: .init(0.40, 0.44, 0.42), dark: .init(0.62, 0.67, 0.64))
        public static let line = Color.grooAdaptive(light: .init(0.86, 0.89, 0.87), dark: .init(0.20, 0.24, 0.22))
        public static let danger = Color.grooAdaptive(light: .init(0.64, 0.22, 0.22), dark: .init(0.94, 0.45, 0.45))
        public static let cornerRadius: CGFloat = 12
    }

    /// A supplied token is taken exactly as given — an app that hands over one
    /// brand colour is not asked to supply two, and nothing derives a second
    /// appearance behind its back.
    public init(
        accent: Color = Default.accent,
        onAccent: Color = Default.onAccent,
        canvas: Color = Default.canvas,
        surface: Color = Default.surface,
        ink: Color = Default.ink,
        muted: Color = Default.muted,
        line: Color = Default.line,
        danger: Color = Default.danger,
        cornerRadius: CGFloat = Default.cornerRadius,
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
    /// both SDKs looks like one product without configuring either. Adaptive in
    /// both appearances — see the initialiser.
    public static let groo = GrooAuthTheme()
}

public extension EnvironmentValues {
    /// ```swift
    /// GrooSignInView()
    ///     .environment(\.grooAuthTheme, GrooAuthTheme(accent: .indigo))
    /// ```
    @Entry var grooAuthTheme: GrooAuthTheme = .groo
}
