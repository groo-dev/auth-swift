import XCTest
@testable import GrooAuth

/// `TokenStoring` test double whose `load()` always throws — simulates a
/// genuine Keychain read failure (as opposed to a legitimate "no tokens
/// stored" `nil`), so `signOut()` can be tested for the case where it cannot
/// know whether there was a refresh token to revoke.
private final class ThrowingLoadTokenStore: TokenStoring, @unchecked Sendable {
    struct LoadFailure: Error, CustomStringConvertible {
        var description: String { "simulated keychain read failure" }
    }

    private(set) var clearCallCount = 0

    func load() throws -> StoredTokens? {
        throw LoadFailure()
    }

    func save(_ tokens: StoredTokens) throws {
        XCTFail("save() should never be called by signOut()")
    }

    func clear() throws {
        clearCallCount += 1
    }
}

final class SignOutTests: XCTestCase {
    private let testConfig = GrooAuthConfig(
        issuer: URL(string: "https://accounts.groo.dev")!,
        clientId: "test-client",
        redirectURI: "groo://callback",
        scopes: ["openid", "profile", "email"],
        keychainService: "dev.groo.test"
    )

    private let discoveryURL = "https://accounts.groo.dev/.well-known/openid-configuration"
    private let revokeURL = "https://accounts.groo.dev/v1/oauth/revoke"
    private let discoveryBodyWithRevocation = #"""
    {"issuer":"https://accounts.groo.dev","authorization_endpoint":"https://accounts.groo.dev/v1/oauth/authorize","token_endpoint":"https://accounts.groo.dev/v1/oauth/token","jwks_uri":"https://accounts.groo.dev/.well-known/jwks.json","revocation_endpoint":"https://accounts.groo.dev/v1/oauth/revoke"}
    """#

    private func tokens(user: GrooUser = GrooUser(sub: "u", email: nil, name: nil)) -> StoredTokens {
        StoredTokens(
            accessToken: "access-1", refreshToken: "refresh-123", tokenType: "Bearer",
            expiresAt: Date().addingTimeInterval(3600), idToken: nil, scope: nil, user: user
        )
    }

    func testSignOutRevokesAndClearsOnSuccess() async throws {
        let store = InMemoryTokenStore()
        try store.save(tokens())

        let transport = MockTransport(routes: [
            discoveryURL: (200, discoveryBodyWithRevocation),
            revokeURL: (200, ""),
        ])
        let session = GrooAuthSession(
            config: testConfig, tokenStore: store, transport: transport,
            webAuthenticator: StubWebAuthenticator(), now: { Date() }
        )

        let result = await session.signOut()

        XCTAssertEqual(result, .revokedAndCleared)
        XCTAssertNil(try store.load(), "signOut must clear local tokens")

        let state = await session.currentState()
        XCTAssertEqual(state, .signedOut)

        XCTAssertEqual(transport.callCount(for: revokeURL), 1, "revocation endpoint must be called exactly once")
        let body = transport.lastRequestBody(for: revokeURL)
        let bodyString = String(data: body ?? Data(), encoding: .utf8) ?? ""
        XCTAssertTrue(bodyString.contains("token=refresh-123"), "revoke body must carry the refresh token: \(bodyString)")
        XCTAssertTrue(bodyString.contains("client_id=test-client"), "revoke body must carry the client_id: \(bodyString)")
    }

    func testSignOutClearsButReportsFailureOnRevoke500() async throws {
        let store = InMemoryTokenStore()
        try store.save(tokens())

        let transport = MockTransport(routes: [
            discoveryURL: (200, discoveryBodyWithRevocation),
            revokeURL: (500, #"{"error":"server_error"}"#),
        ])
        let session = GrooAuthSession(
            config: testConfig, tokenStore: store, transport: transport,
            webAuthenticator: StubWebAuthenticator(), now: { Date() }
        )

        let result = await session.signOut()

        guard case .clearedButRevokeFailed(let reason) = result else {
            XCTFail("expected .clearedButRevokeFailed, got \(result)")
            return
        }
        XCTAssertTrue(reason.contains("500"), "reason should mention the HTTP failure: \(reason)")

        XCTAssertNil(try store.load(), "signOut must clear local tokens even when revoke fails")

        let state = await session.currentState()
        XCTAssertEqual(state, .signedOut)
    }

    func testSignOutSurfacesLoadFailureInsteadOfClaimingRevocation() async throws {
        let store = ThrowingLoadTokenStore()
        // No routes configured: a load failure must short-circuit before any
        // revoke attempt, since there's no refresh token to send.
        let transport = MockTransport(routes: [:])
        let session = GrooAuthSession(
            config: testConfig, tokenStore: store, transport: transport,
            webAuthenticator: StubWebAuthenticator(), now: { Date() }
        )

        let result = await session.signOut()

        guard case .clearedButRevokeFailed(let reason) = result else {
            XCTFail("a load() throw must never be reported as .revokedAndCleared — got \(result)")
            return
        }
        XCTAssertTrue(
            reason.contains("simulated keychain read failure"),
            "reason should mention the real load failure: \(reason)"
        )
        XCTAssertEqual(transport.totalCallCount, 0, "no refresh token was readable, so nothing should be revoked")
        XCTAssertEqual(store.clearCallCount, 1, "local state must still be cleared despite the load failure")

        let state = await session.currentState()
        XCTAssertEqual(state, .signedOut)
    }

    func testSignOutWithNoTokensIsNoOp() async throws {
        let store = InMemoryTokenStore()
        let transport = MockTransport(routes: [:])
        let session = GrooAuthSession(
            config: testConfig, tokenStore: store, transport: transport,
            webAuthenticator: StubWebAuthenticator(), now: { Date() }
        )

        let result = await session.signOut()

        XCTAssertEqual(result, .revokedAndCleared)
        XCTAssertEqual(transport.totalCallCount, 0, "no tokens means nothing to revoke; no network calls at all")

        let state = await session.currentState()
        XCTAssertEqual(state, .signedOut)
    }
}
