import XCTest
@testable import GrooAuth

final class ReauthTests: XCTestCase {
    private let config = GrooAuthConfig(
        issuer: URL(string: "https://accounts.groo.dev")!, clientId: "test-client",
        redirectURI: "groo://callback", scopes: ["openid"], keychainService: "dev.groo.test"
    )
    private let discoveryURL = "https://accounts.groo.dev/.well-known/openid-configuration"
    private let tokenURL = "https://accounts.groo.dev/v1/oauth/token"
    private let discoveryBody = #"""
    {"issuer":"https://accounts.groo.dev","authorization_endpoint":"https://accounts.groo.dev/v1/oauth/authorize","token_endpoint":"https://accounts.groo.dev/v1/oauth/token","jwks_uri":"https://accounts.groo.dev/.well-known/jwks.json","revocation_endpoint":"https://accounts.groo.dev/v1/oauth/revoke"}
    """#
    private let alice = GrooUser(sub: "alice", email: "a@x.test", name: "Alice")

    private func expired(user: GrooUser?) -> StoredTokens {
        StoredTokens(accessToken: "old", refreshToken: "r1", tokenType: "Bearer",
                     expiresAt: Date().addingTimeInterval(-10), idToken: nil, scope: nil, user: user)
    }

    private func session(_ store: TokenStoring, tokenStatus: Int, tokenBody: String) -> (GrooAuthSession, MockTransport) {
        let transport = MockTransport(routes: [
            discoveryURL: (200, discoveryBody),
            tokenURL: (tokenStatus, tokenBody),
            "https://accounts.groo.dev/v1/oauth/revoke": (200, "{}"),
        ])
        return (GrooAuthSession(config: config, tokenStore: store, transport: transport,
                                webAuthenticator: StubWebAuthenticator(), now: { Date() }), transport)
    }

    func testInvalidGrantKeepsTheIdentityAndRequiresReauth() async throws {
        let store = InMemoryTokenStore()
        try store.save(expired(user: alice))
        let (s, _) = session(store, tokenStatus: 400, tokenBody: #"{"error":"invalid_grant"}"#)

        var states = await s.stateStream.makeAsyncIterator()
        _ = await states.next() // current state (.signedIn)

        do { _ = try await s.accessToken(); XCTFail("expected reauthRequired") } catch GrooAuthError.reauthRequired {}

        XCTAssertNil(try store.load(), "tokens are cleared")
        XCTAssertEqual(try store.loadIdentity(), alice, "identity is kept")
        let published = await states.next()
        XCTAssertEqual(published, .reauthRequired(alice))
        let state = await s.currentState()
        XCTAssertEqual(state, .reauthRequired(alice))
    }

    func testAnyRefusalOfTheRefreshRequiresReauth() async throws {
        let store = InMemoryTokenStore()
        try store.save(expired(user: alice))
        let (s, _) = session(store, tokenStatus: 401, tokenBody: #"{"error":"invalid_client"}"#)
        do { _ = try await s.accessToken(); XCTFail("expected reauthRequired") } catch GrooAuthError.reauthRequired {}
        let state = await s.currentState()
        XCTAssertEqual(state, .reauthRequired(alice))
    }

    func testTokensWithNoUserStillSignOutAsBefore() async throws {
        // A Keychain item from before user was stored: there is no identity to keep.
        let store = InMemoryTokenStore()
        try store.save(expired(user: nil))
        let (s, _) = session(store, tokenStatus: 400, tokenBody: #"{"error":"invalid_grant"}"#)
        do { _ = try await s.accessToken(); XCTFail("expected an error") } catch GrooAuthError.signedOut {}
        XCTAssertNil(try store.loadIdentity())
        let state = await s.currentState()
        XCTAssertEqual(state, .signedOut)
    }

    func testInReauthAccessTokenThrowsReauthRequiredWithoutTouchingTheNetwork() async throws {
        let store = InMemoryTokenStore()
        try store.clearTokens(keeping: alice)
        let (s, transport) = session(store, tokenStatus: 200, tokenBody: "{}")
        do { _ = try await s.accessToken(); XCTFail("expected reauthRequired") } catch GrooAuthError.reauthRequired {}
        do { _ = try await s.forceRefreshAccessToken(); XCTFail("expected reauthRequired") } catch GrooAuthError.reauthRequired {}
        XCTAssertEqual(transport.totalCallCount, 0)
    }

    func testSigningOutFromReauthForgetsTheIdentity() async throws {
        let store = InMemoryTokenStore()
        try store.clearTokens(keeping: alice)
        let (s, _) = session(store, tokenStatus: 200, tokenBody: "{}")
        _ = await s.signOut()
        XCTAssertNil(try store.loadIdentity())
        let state = await s.currentState()
        XCTAssertEqual(state, .signedOut)
    }

    func testTheReauthStateSurvivesANewSessionOverTheSameStore() async throws {
        let store = InMemoryTokenStore()
        try store.clearTokens(keeping: alice)
        let (fresh, _) = session(store, tokenStatus: 200, tokenBody: "{}")
        let state = await fresh.currentState()
        XCTAssertEqual(state, .reauthRequired(alice), "an app relaunch still knows who to ask")
    }
}
