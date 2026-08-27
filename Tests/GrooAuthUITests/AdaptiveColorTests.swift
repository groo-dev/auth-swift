import SwiftUI
import XCTest
@testable import GrooAuthUI

#if canImport(UIKit)
import UIKit
#elseif canImport(AppKit)
import AppKit
#endif

/// A fixed default palette would make the sign-in screen a white flash in every
/// dark app, so what matters is that the default tokens actually resolve
/// DIFFERENTLY per appearance — not what the two values are.
///
/// These run on macOS as well as iOS deliberately: `swift test` runs on macOS,
/// and a guard that only compiles on the platform nobody runs locally is no
/// guard at all.
final class AdaptiveColorTests: XCTestCase {
    private enum Appearance { case light, dark }

    /// sRGB components of `color` as that appearance would draw it.
    private func components(_ color: Color, _ appearance: Appearance) -> [CGFloat] {
        var r: CGFloat = 0, g: CGFloat = 0, b: CGFloat = 0, a: CGFloat = 0
        #if canImport(UIKit)
        let traits = UITraitCollection(userInterfaceStyle: appearance == .dark ? .dark : .light)
        UIColor(color).resolvedColor(with: traits).getRed(&r, green: &g, blue: &b, alpha: &a)
        #elseif canImport(AppKit)
        let named: NSAppearance.Name = appearance == .dark ? .darkAqua : .aqua
        NSAppearance(named: named)!.performAsCurrentDrawingAppearance {
            NSColor(color).usingColorSpace(.sRGB)!.getRed(&r, green: &g, blue: &b, alpha: &a)
        }
        #endif
        return [r, g, b, a]
    }

    private var colourTokens: [(String, Color)] {
        let theme = GrooAuthTheme.groo
        return [
            ("accent", theme.accent), ("onAccent", theme.onAccent),
            ("canvas", theme.canvas), ("surface", theme.surface),
            ("ink", theme.ink), ("muted", theme.muted),
            ("line", theme.line), ("danger", theme.danger),
        ]
    }

    func testEveryDefaultColourResolvesDifferentlyInEachAppearance() {
        // Every token, because one that forgot to adapt is exactly the bug this
        // guards: unreadable in the appearance nobody checked.
        for (name, color) in colourTokens {
            XCTAssertNotEqual(
                components(color, .light), components(color, .dark),
                "\(name) is the same in light and dark"
            )
        }
    }

    func testInkStaysReadableOnCanvasInBothAppearances() {
        // The failure this catches is dark ink on a dark canvas — legible in the
        // appearance it was designed in and invisible in the other.
        for appearance in [Appearance.light, .dark] {
            let canvas = components(GrooAuthTheme.groo.canvas, appearance)
            let ink = components(GrooAuthTheme.groo.ink, appearance)
            let separation = abs((canvas[0] + canvas[1] + canvas[2]) - (ink[0] + ink[1] + ink[2]))
            XCTAssertGreaterThan(separation, 1.0, "ink and canvas are too close in \(appearance)")
        }
    }

    func testASuppliedColourIsNotMadeAdaptive() {
        // An app handing over one brand colour means that colour, in both
        // appearances. Deriving a second silently would be a surprise.
        let theme = GrooAuthTheme(accent: Color(red: 1, green: 0, blue: 0))
        XCTAssertEqual(components(theme.accent, .light), components(theme.accent, .dark))
    }
}
