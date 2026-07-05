import XCTest
@testable import GrooAuth

/// Covers `stateStream` subscriber lifecycle: a fresh subscriber still sees the
/// current state immediately (existing behavior, exercised elsewhere too), and a
/// dropped subscriber's continuation is pruned rather than leaking for the
/// actor's lifetime.
final class StateStreamTests: XCTestCase {
    private let testConfig = GrooAuthConfig(
        issuer: URL(string: "https://accounts.groo.dev")!,
        clientId: "test-client",
        redirectURI: "groo://callback",
        scopes: ["openid", "profile", "email"],
        keychainService: "dev.groo.test"
    )

    func testDroppedStateStreamSubscriberIsPruned() async throws {
        let store = InMemoryTokenStore()
        let transport = MockTransport(routes: [:])
        let session = GrooAuthSession(
            config: testConfig, tokenStore: store, transport: transport,
            webAuthenticator: StubWebAuthenticator(), now: { Date() }
        )

        let initialCount = await session.stateContinuationCountForTesting()
        XCTAssertEqual(initialCount, 0)

        do {
            let stream = await session.stateStream
            var iterator = stream.makeAsyncIterator()
            _ = await iterator.next() // consume the immediate "current state" emission
            let subscribedCount = await session.stateContinuationCountForTesting()
            XCTAssertEqual(subscribedCount, 1)
            // `stream`/`iterator` fall out of scope at the end of this block with
            // no other references kept — the subscription is effectively dropped.
        }

        // `onTermination` hops back onto the actor via a new Task, so it may not
        // have run the instant the scope above exits. Poll briefly rather than
        // asserting instantly.
        var remainingAttempts = 20
        var countAfterDrop = await session.stateContinuationCountForTesting()
        while countAfterDrop != 0, remainingAttempts > 0 {
            try await Task.sleep(nanoseconds: 10_000_000)
            remainingAttempts -= 1
            countAfterDrop = await session.stateContinuationCountForTesting()
        }
        XCTAssertEqual(
            countAfterDrop, 0,
            "a dropped stateStream subscriber must be pruned, not leaked"
        )

        // A subsequent publish (signOut always publishes .signedOut) must not
        // crash now that the dropped subscriber's continuation is gone.
        _ = await session.signOut()
    }

    func testNewSubscriberImmediatelySeesCurrentState() async throws {
        let store = InMemoryTokenStore()
        let user = GrooUser(sub: "u1", email: nil, name: nil)
        try store.save(StoredTokens(
            accessToken: "a", refreshToken: "r", tokenType: "Bearer",
            expiresAt: Date().addingTimeInterval(3600), idToken: nil, scope: nil, user: user
        ))
        let transport = MockTransport(routes: [:])
        let session = GrooAuthSession(
            config: testConfig, tokenStore: store, transport: transport,
            webAuthenticator: StubWebAuthenticator(), now: { Date() }
        )

        let stream = await session.stateStream
        var iterator = stream.makeAsyncIterator()
        let first = await iterator.next()
        XCTAssertEqual(first, .signedIn(user), "a new subscriber must immediately see the current state")
    }
}
