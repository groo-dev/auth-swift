import XCTest
@testable import GrooAuth

final class GrooAccountSectionsTests: XCTestCase {
    func testEachSectionNamesTheScopeItNeeds() {
        XCTAssertEqual(GrooAccountSections.passkeys.requiredScopes, ["accounts:passkeys"])
        XCTAssertEqual(GrooAccountSections.devices.requiredScopes, ["accounts:devices"])
        XCTAssertEqual(GrooAccountSections.connectedApps.requiredScopes, ["accounts:apps"])
        XCTAssertEqual(GrooAccountSections.tokens.requiredScopes, ["accounts:tokens"])
    }

    func testAnEmptySetAsksForNothing() {
        // An app showing no security sections must not request their scopes — this
        // is what lets `requiredScopes` be spliced into a config unconditionally.
        XCTAssertTrue(GrooAccountSections([]).requiredScopes.isEmpty)
    }

    func testAllIsEveryScope() {
        XCTAssertEqual(
            Set(GrooAccountSections.all.requiredScopes),
            ["accounts:passkeys", "accounts:devices", "accounts:apps", "accounts:tokens"]
        )
    }
}
