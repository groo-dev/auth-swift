import SwiftUI

#if canImport(UIKit)
import UIKit
#elseif canImport(AppKit)
import AppKit
#endif

/// One appearance's worth of a colour, for `Color.grooAdaptive(light:dark:)`.
///
/// A plain sRGB triple rather than a `Color`, because the two halves have to be
/// resolvable at draw time and `Color` does not give its components back.
public struct GrooRGB: Sendable {
    let r: Double, g: Double, b: Double

    public init(_ r: Double, _ g: Double, _ b: Double) {
        self.r = r
        self.g = g
        self.b = b
    }

    var color: Color { Color(red: r, green: g, blue: b) }

    #if canImport(UIKit)
    var uiColor: UIColor { UIColor(red: r, green: g, blue: b, alpha: 1) }
    #elseif canImport(AppKit)
    var nsColor: NSColor { NSColor(srgbRed: r, green: g, blue: b, alpha: 1) }
    #endif
}

public extension Color {
    /// A colour that resolves one way in light appearance and another in dark.
    ///
    /// `GrooAuthTheme`'s defaults are built from this, because a library's
    /// default cannot be a fixed palette: Space's app is dark end to end, so a
    /// fixed light default turns its sign-in screen into a white flash before a
    /// black app, and every adopter whose app is dark hits the same thing.
    ///
    /// Public because an app themeing these components has the same problem with
    /// its own brand colours, and should not have to reach for `UIColor` to solve
    /// it. A theme token given a plain `Color` is still taken exactly as given —
    /// adaptivity is opt-in, never derived.
    static func grooAdaptive(light: GrooRGB, dark: GrooRGB) -> Color {
        #if canImport(UIKit)
        return Color(UIColor { traits in
            traits.userInterfaceStyle == .dark ? dark.uiColor : light.uiColor
        })
        #elseif canImport(AppKit)
        return Color(NSColor(name: nil) { appearance in
            appearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua ? dark.nsColor : light.nsColor
        })
        #else
        // No appearance to ask. Light is the safer guess: a too-bright screen is
        // legible, a dark-on-dark one is not.
        return light.color
        #endif
    }
}
