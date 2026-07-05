import XCTest
@testable import GrooAuth

final class RefreshTests: XCTestCase {
    private let testConfig = GrooAuthConfig(
        issuer: URL(string: "https://accounts.groo.dev")!,
        clientId: "test-client",
        redirectURI: "groo://callback",
        scopes: ["openid", "profile", "email"],
        keychainService: "dev.groo.test"
    )

    private let discoveryURL = "https://accounts.groo.dev/.well-known/openid-configuration"
    private let tokenURL = "https://accounts.groo.dev/v1/oauth/token"
    private let discoveryBody = #"""
    {"issuer":"https://accounts.groo.dev","authorization_endpoint":"https://accounts.groo.dev/v1/oauth/authorize","token_endpoint":"https://accounts.groo.dev/v1/oauth/token","jwks_uri":"https://accounts.groo.dev/.well-known/jwks.json"}
    """#

    private func expiredTokens(user: GrooUser = GrooUser(sub: "u", email: nil, name: nil)) -> StoredTokens {
        StoredTokens(
            accessToken: "old", refreshToken: "r1", tokenType: "Bearer",
            expiresAt: Date().addingTimeInterval(-10), idToken: nil, scope: nil, user: user
        )
    }

    // MARK: - Single-flight refresh

    func testConcurrentAccessTokenRefreshesOnce() async throws {
        let store = InMemoryTokenStore()
        try store.save(expiredTokens())

        let transport = MockTransport(routes: [
            discoveryURL: (200, discoveryBody),
            tokenURL: (200, #"{"access_token":"new","refresh_token":"r2","token_type":"Bearer","expires_in":900}"#),
        ])
        let session = GrooAuthSession(
            config: testConfig, tokenStore: store, transport: transport,
            webAuthenticator: StubWebAuthenticator(), now: { Date() }
        )

        let results = try await withThrowingTaskGroup(of: String.self) { group -> [String] in
            for _ in 0..<10 {
                group.addTask { try await session.accessToken() }
            }
            var collected: [String] = []
            for try await value in group { collected.append(value) }
            return collected
        }

        XCTAssertEqual(results.count, 10)
        XCTAssertEqual(Set(results), ["new"])
        XCTAssertEqual(transport.callCount(for: tokenURL), 1, "single-flight must yield exactly one token-endpoint request")
        XCTAssertEqual(transport.callCount(for: discoveryURL), 1, "discovery must be cached, fetched at most once")

        // A follow-up call sees the now-fresh token and makes no further token call.
        let t = try await session.accessToken()
        XCTAssertEqual(t, "new")
        XCTAssertEqual(transport.callCount(for: tokenURL), 1)
    }

    func testRefreshRejectionSignsOut() async throws {
        let store = InMemoryTokenStore()
        try store.save(expiredTokens())

        let transport = MockTransport(routes: [
            discoveryURL: (200, discoveryBody),
            tokenURL: (400, #"{"error":"invalid_grant"}"#),
        ])
        let session = GrooAuthSession(
            config: testConfig, tokenStore: store, transport: transport,
            webAuthenticator: StubWebAuthenticator(), now: { Date() }
        )

        do {
            _ = try await session.accessToken()
            XCTFail("expected refresh rejection to throw")
        } catch GrooAuthError.protocolError(let err) {
            XCTAssertEqual(err.error, "invalid_grant")
        }

        let state = await session.currentState()
        XCTAssertEqual(state, .signedOut)
        XCTAssertNil(try store.load(), "rejected refresh must clear the token store")
    }

    // MARK: - Cached / no-op paths

    func testAccessTokenReturnsCachedTokenWhenNotExpired() async throws {
        let store = InMemoryTokenStore()
        let user = GrooUser(sub: "u", email: nil, name: nil)
        try store.save(StoredTokens(
            accessToken: "cached", refreshToken: "r1", tokenType: "Bearer",
            expiresAt: Date().addingTimeInterval(3600), idToken: nil, scope: nil, user: user
        ))

        // Routes exist but must never be hit.
        let transport = MockTransport(routes: [
            discoveryURL: (200, discoveryBody),
            tokenURL: (200, #"{"access_token":"new","refresh_token":"r2","token_type":"Bearer","expires_in":900}"#),
        ])
        let session = GrooAuthSession(
            config: testConfig, tokenStore: store, transport: transport,
            webAuthenticator: StubWebAuthenticator(), now: { Date() }
        )

        let token = try await session.accessToken()
        XCTAssertEqual(token, "cached")
        XCTAssertEqual(transport.totalCallCount, 0, "a non-expired token must not trigger discovery or refresh")

        let state = await session.currentState()
        XCTAssertEqual(state, .signedIn(user))
    }

    func testAccessTokenThrowsSignedOutWhenNoTokens() async throws {
        let store = InMemoryTokenStore()
        let transport = MockTransport(routes: [:])
        let session = GrooAuthSession(
            config: testConfig, tokenStore: store, transport: transport,
            webAuthenticator: StubWebAuthenticator(), now: { Date() }
        )

        do {
            _ = try await session.accessToken()
            XCTFail("expected .signedOut")
        } catch GrooAuthError.signedOut {
            // expected
        }

        let state = await session.currentState()
        XCTAssertEqual(state, .signedOut)
    }
}
