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

    // MARK: - A refresh that outlives its session

    func testASessionClearedDuringAFailingRefreshIsNotResurrectedAsReauth() async throws {
        let store = InMemoryTokenStore()
        try store.save(expired(user: alice))
        let (s, transport) = session(store, tokenStatus: 400, tokenBody: #"{"error":"invalid_grant"}"#)
        let gate = transport.gate(tokenURL)
        var states = await s.stateStream.makeAsyncIterator()
        _ = await states.next() // .signedIn

        let refresh = Task { try await s.accessToken() }
        await gate.waitUntilHeld()
        // signOut() now waits for the in-flight refresh, so the session is changed
        // under it directly (what a concurrent signIn or another writer does).
        try store.clear()
        gate.release()
        do { _ = try await refresh.value; XCTFail("expected an error") } catch GrooAuthError.signedOut {}

        XCTAssertNil(try store.loadIdentity(), "a signed-out person's identity must not be resurrected")
        XCTAssertNil(try store.load())
        let state = await s.currentState()
        XCTAssertEqual(state, .signedOut)

        _ = await s.signOut() // sentinel: anything the refresh published sits before this
        let next = await states.next()
        XCTAssertEqual(next, .signedOut, "the discarded refresh published nothing")
    }

    func testASessionClearedDuringASucceedingRefreshIsNotResurrectedAsSignedIn() async throws {
        let store = InMemoryTokenStore()
        try store.save(expired(user: alice))
        let (s, transport) = session(store, tokenStatus: 200, tokenBody: #"{"access_token":"new","refresh_token":"r2","token_type":"Bearer","expires_in":900}"#)
        let gate = transport.gate(tokenURL)

        let refresh = Task { try await s.accessToken() }
        await gate.waitUntilHeld()
        try store.clear()
        gate.release()
        do { _ = try await refresh.value; XCTFail("expected an error") } catch GrooAuthError.signedOut {}

        XCTAssertNil(try store.load(), "late refreshed tokens must not be saved over a sign-out")
        let state = await s.currentState()
        XCTAssertEqual(state, .signedOut)
    }

    func testSignOutDuringARefreshRevokesTheRotatedToken() async throws {
        let store = InMemoryTokenStore()
        try store.save(expired(user: alice))
        let (s, transport) = session(store, tokenStatus: 200, tokenBody: #"{"access_token":"new","refresh_token":"r2","token_type":"Bearer","expires_in":900}"#)
        let gate = transport.gate(tokenURL)

        let refresh = Task { try await s.accessToken() }
        await gate.waitUntilHeld()
        let signOut = Task { await s.signOut() }
        // Give signOut a chance to run up to its wait on the in-flight refresh.
        try await Task.sleep(nanoseconds: 50_000_000)
        gate.release()
        _ = try? await refresh.value
        _ = await signOut.value

        let revokeURL = "https://accounts.groo.dev/v1/oauth/revoke"
        let body = String(decoding: try XCTUnwrap(transport.lastRequestBody(for: revokeURL)), as: UTF8.self)
        XCTAssertTrue(body.contains("token=r2"), "the live (rotated) token is revoked, got: \(body)")
        XCTAssertNil(try store.load())
        let state = await s.currentState()
        XCTAssertEqual(state, .signedOut)
    }

    func testConcurrentCallersDuringARejectedRefreshShareOneReauth() async throws {
        let store = InMemoryTokenStore()
        try store.save(expired(user: alice))
        let (s, transport) = session(store, tokenStatus: 400, tokenBody: #"{"error":"invalid_grant"}"#)
        var states = await s.stateStream.makeAsyncIterator()
        _ = await states.next()

        let results = await withTaskGroup(of: Bool.self) { group in
            for _ in 0..<10 {
                group.addTask {
                    do { _ = try await s.accessToken(); return false } catch GrooAuthError.reauthRequired { return true } catch { return false }
                }
            }
            var all: [Bool] = []
            for await r in group { all.append(r) }
            return all
        }
        XCTAssertEqual(results, Array(repeating: true, count: 10))
        XCTAssertEqual(transport.callCount(for: tokenURL), 1)

        _ = await s.signOut() // sentinel
        var reauths = 0
        while let next = await states.next(), next != .signedOut {
            if next == .reauthRequired(alice) { reauths += 1 }
        }
        XCTAssertEqual(reauths, 1)
    }

    // MARK: - Stores that cannot keep an identity

    /// Implements only the original three requirements: a real clear, no identity.
    private final class NoIdentityStore: TokenStoring, @unchecked Sendable {
        var tokens: StoredTokens?
        func load() throws -> StoredTokens? { tokens }
        func save(_ tokens: StoredTokens) throws { self.tokens = tokens }
        func clear() throws { tokens = nil }
    }

    func testStoreWithoutIdentitySupportPublishesWhatItWillReport() async throws {
        let store = NoIdentityStore()
        try store.save(expired(user: alice))
        let (s, _) = session(store, tokenStatus: 400, tokenBody: #"{"error":"invalid_grant"}"#)
        var states = await s.stateStream.makeAsyncIterator()
        _ = await states.next()

        do { _ = try await s.accessToken(); XCTFail("expected signedOut") } catch GrooAuthError.signedOut {}

        let published = await states.next()
        let state = await s.currentState()
        XCTAssertEqual(published, .signedOut)
        XCTAssertEqual(state, .signedOut, "published and reported state agree")
    }

    /// A store whose clear() does nothing (an extension's non-destructive store).
    private final class NoOpClearStore: TokenStoring, @unchecked Sendable {
        var tokens: StoredTokens?
        func load() throws -> StoredTokens? { tokens }
        func save(_ tokens: StoredTokens) throws { self.tokens = tokens }
        func clear() throws {}
    }

    func testStoreThatCannotClearSurfacesTheOriginalRefusalAndStaysSignedIn() async throws {
        let store = NoOpClearStore()
        try store.save(expired(user: alice))
        let (s, _) = session(store, tokenStatus: 400, tokenBody: #"{"error":"invalid_grant"}"#)
        do { _ = try await s.accessToken(); XCTFail("expected protocolError") } catch GrooAuthError.protocolError(let e) {
            XCTAssertEqual(e.error, "invalid_grant")
        }
        let state = await s.currentState()
        XCTAssertEqual(state, .signedIn(alice))
    }

    func testARefusedRefreshForAReplacedSessionHandsOutTheNewToken() async throws {
        let store = InMemoryTokenStore()
        try store.save(expired(user: alice))
        let (s, transport) = session(store, tokenStatus: 400, tokenBody: #"{"error":"invalid_grant"}"#)
        let gate = transport.gate(tokenURL)
        var states = await s.stateStream.makeAsyncIterator()
        _ = await states.next()

        let call = Task { try await s.accessToken() }
        await gate.waitUntilHeld()
        let bob = GrooUser(sub: "bob", email: nil, name: nil)
        try store.save(StoredTokens(accessToken: "bobs", refreshToken: "rb", tokenType: "Bearer",
                                    expiresAt: Date().addingTimeInterval(900), idToken: nil, scope: nil, user: bob))
        gate.release()

        let token = try await call.value
        XCTAssertEqual(token, "bobs")
        let state = await s.currentState()
        XCTAssertEqual(state, .signedIn(bob))
        _ = await s.signOut() // sentinel
        let next = await states.next()
        XCTAssertEqual(next, .signedOut, "no .reauthRequired was published")
    }

    func testSignOutDoesNotWaitForeverOnAHungRefresh() async throws {
        let store = InMemoryTokenStore()
        try store.save(expired(user: alice))
        let (s, transport) = session(store, tokenStatus: 200, tokenBody: #"{"access_token":"new","refresh_token":"r2","token_type":"Bearer","expires_in":900}"#)
        await s.setSignOutRefreshWaitForTesting(.milliseconds(100))
        let gate = transport.gate(tokenURL)

        let refresh = Task { try await s.accessToken() }
        await gate.waitUntilHeld()
        _ = await s.signOut() // returns after the bound although the refresh is held
        let state = await s.currentState()
        XCTAssertEqual(state, .signedOut)

        gate.release()
        do { _ = try await refresh.value; XCTFail("expected an error") } catch GrooAuthError.signedOut {}
        XCTAssertNil(try store.load(), "the late refresh result is discarded")
        let after = await s.currentState()
        XCTAssertEqual(after, .signedOut)
    }
}
