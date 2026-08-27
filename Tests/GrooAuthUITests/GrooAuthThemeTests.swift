import XCTest
import SwiftUI
@testable import GrooAuthUI

/// The default values are not what these pin — they will be tuned. What matters
/// is that a consuming app CAN override them, because a library whose views
/// cannot be restyled gets forked by its first adopter.
final class GrooAuthThemeTests: XCTestCase {
    func testEnvironmentDefaultsToGroo() {
        var env = EnvironmentValues()
        XCTAssertEqual(env.grooAuthTheme.cornerRadius, GrooAuthTheme.groo.cornerRadius)
        XCTAssertEqual(env.grooAuthTheme.accent, GrooAuthTheme.groo.accent)
        // Silences the "never mutated" warning while documenting that `env` is the
        // thing under test in the sibling case.
        env.grooAuthTheme = .groo
    }

    func testASuppliedThemeReplacesTheDefault() {
        var env = EnvironmentValues()
        env.grooAuthTheme = GrooAuthTheme(accent: .indigo, cornerRadius: 2)
        XCTAssertEqual(env.grooAuthTheme.accent, .indigo)
        XCTAssertEqual(env.grooAuthTheme.cornerRadius, 2)
    }

    func testOverridingOneTokenKeepsTheRest() {
        // The common case: an app sets its brand colour and inherits everything
        // else. If the initialiser stopped defaulting, this is what would break.
        let themed = GrooAuthTheme(accent: .indigo)
        XCTAssertEqual(themed.accent, .indigo)
        XCTAssertEqual(themed.surface, GrooAuthTheme.groo.surface)
        XCTAssertEqual(themed.cornerRadius, GrooAuthTheme.groo.cornerRadius)
    }
}
