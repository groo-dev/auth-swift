import XCTest
@testable import GrooAuth

/// Covers the `init(config:tokenStore:)` convenience initializer, which wires up
/// the production `URLSessionTransport`/`ASWebAuthenticator` so app call sites
/// don't have to construct them by hand. Only exercises construction + basic
/// state — the full sign-in/refresh flows are already covered against the
/// full init elsewhere (`SignInTests`, `RefreshTests`).
final class GrooAuthSessionConvenienceInitTests: XCTestCase {
    private let testConfig = GrooAuthConfig(
        issuer: URL(string: "https://accounts.groo.dev")!,
        clientId: "test-client",
        redirectURI: "groo://callback",
        scopes: ["openid", "profile", "email"],
        keychainService: "dev.groo.test"
    )

    func testConvenienceInitConstructsAndStartsSignedOut() async throws {
        let session = GrooAuthSession(config: testConfig, tokenStore: InMemoryTokenStore())
        let state = await session.currentState()
        XCTAssertEqual(state, .signedOut)
    }
}
