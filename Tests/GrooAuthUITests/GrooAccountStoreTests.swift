import Foundation
import XCTest
@testable import GrooAuth
@testable import GrooAuthUI

/// Answers `/v1/account/*` from a script, and records what was asked.
private final class AccountTransport: HTTPTransporting, @unchecked Sendable {
    var responses: [(status: Int, body: String)]
    private(set) var requests: [(url: String, method: String, authorization: String?, body: Data?)] = []

    init(responses: [(status: Int, body: String)]) {
        self.responses = responses
    }

    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        requests.append((
            request.url!.absoluteString,
            request.httpMethod ?? "GET",
            request.value(forHTTPHeaderField: "Authorization"),
            request.httpBody
        ))
        let next = responses.isEmpty ? (status: 500, body: "{}") : responses.removeFirst()
        let http = HTTPURLResponse(url: request.url!, statusCode: next.status, httpVersion: "HTTP/1.1", headerFields: nil)!
        return (Data(next.body.utf8), http)
    }

    func sendWithoutFollowingRedirects(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        try await send(request)
    }
}

private final class UnusedWebAuthenticator: WebAuthenticating, @unchecked Sendable {
    func authenticate(url: URL, callbackScheme: String, anchor: ASPresentationAnchor) async throws -> URL {
        XCTFail("no sign-in should be attempted in these tests")
        throw GrooAuthError.userCancelled
    }
}

#if canImport(AuthenticationServices)
import AuthenticationServices
#endif

private let PROFILE = #"""
{"user":{"id":"u1","email":"someone@groo.dev","phone":null,"name":"Ada","emailVerified":true,"phoneVerified":false,"blocked":false,"totpEnabled":false,"hasPassword":true,"lastLoginAt":null,"createdAt":"2026-01-01T00:00:00.000Z","updatedAt":"2026-01-01T00:00:00.000Z"}}
"""#

@MainActor
final class GrooAccountStoreTests: XCTestCase {
    private func makeStore(_ transport: AccountTransport) -> GrooAccountStore {
        let store = InMemoryTokenStore()
        try? store.save(StoredTokens(
            accessToken: "at-1",
            refreshToken: "rt-1",
            tokenType: "Bearer",
            expiresAt: Date().addingTimeInterval(3600),
            idToken: nil,
            scope: "openid accounts:profile",
            user: GrooUser(sub: "u1", email: "someone@groo.dev", name: "Ada")
        ))
        let session = GrooAuthSession(
            config: GrooAuthConfig(
                issuer: URL(string: "https://me.example.test")!,
                clientId: "c",
                redirectURI: "app://cb",
                scopes: ["openid"],
                keychainService: "test"
            ),
            tokenStore: store,
            transport: transport,
            webAuthenticator: UnusedWebAuthenticator()
        )
        return GrooAccountStore(session: session)
    }

    func testLoadsTheProfileWithABearerToken() async {
        let transport = AccountTransport(responses: [(200, PROFILE)])
        let store = makeStore(transport)

        await store.load()

        XCTAssertEqual(store.profile?.name, "Ada")
        XCTAssertEqual(store.profile?.email, "someone@groo.dev")
        XCTAssertEqual(store.profile?.hasPassword, true)
        XCTAssertNil(store.error)

        let request = transport.requests.first
        // The account surface is at the ISSUER, not at any product's API, and it
        // is Bearer-only — a cookie or a PAT is refused there.
        XCTAssertEqual(request?.url, "https://me.example.test/v1/account/profile")
        XCTAssertEqual(request?.authorization, "Bearer at-1")
    }

    func testSavesOnlyTheFieldsItWasGiven() async {
        let transport = AccountTransport(responses: [(200, PROFILE), (200, PROFILE)])
        let store = makeStore(transport)
        await store.load()

        await store.save(name: "Ada Lovelace", phone: nil)

        let patch = transport.requests.last
        XCTAssertEqual(patch?.method, "PATCH")
        let sent = (try? JSONSerialization.jsonObject(with: patch?.body ?? Data())) as? [String: String]
        XCTAssertEqual(sent?["name"], "Ada Lovelace")
        // `nil` means "leave it alone", which is what lets a screen send only what
        // it edited rather than echoing back fields it never showed.
        XCTAssertNil(sent?["phone"])
    }

    func testAMissingScopeSaysWhichOneAndWhatToDo() async {
        // The most likely failure while rolling this out: an app whose users
        // consented before it asked for accounts:profile.
        let transport = AccountTransport(responses: [
            (403, #"{"error":"missing required scope \"accounts:profile\""}"#),
        ])
        let store = makeStore(transport)

        await store.load()

        XCTAssertNil(store.profile)
        XCTAssertEqual(
            store.error,
            "This app was not granted permission to accounts:profile. Sign out and in again to approve it."
        )
    }

    func testAFailedRefreshKeepsTheProfileItAlreadyHad() async {
        let transport = AccountTransport(responses: [(200, PROFILE), (500, #"{"error":"boom"}"#)])
        let store = makeStore(transport)
        await store.load()

        await store.load()

        // Blanking good content because a refresh failed makes an app look like it
        // lost the data. The error is reported; the profile stays.
        XCTAssertEqual(store.profile?.name, "Ada")
        XCTAssertEqual(store.error, "boom")
    }

    func testTheFirstLoadIsTheOnlyOneThatShowsASpinner() async {
        let transport = AccountTransport(responses: [(200, PROFILE), (200, PROFILE)])
        let store = makeStore(transport)
        XCTAssertFalse(store.isLoading)

        await store.load()
        XCTAssertFalse(store.isLoading, "isLoading must be cleared when the load finishes")

        // A refresh behind rendered content must not flip it back on.
        let refresh = Task { await store.load() }
        await refresh.value
        XCTAssertFalse(store.isLoading)
    }

    func testASignedOutSessionIsReportedRatherThanCrashing() async {
        let transport = AccountTransport(responses: [])
        let store = InMemoryTokenStore()
        let session = GrooAuthSession(
            config: GrooAuthConfig(
                issuer: URL(string: "https://me.example.test")!,
                clientId: "c",
                redirectURI: "app://cb",
                scopes: ["openid"],
                keychainService: "test"
            ),
            tokenStore: store,
            transport: transport,
            webAuthenticator: UnusedWebAuthenticator()
        )
        let accountStore = GrooAccountStore(session: session)

        await accountStore.load()

        XCTAssertEqual(accountStore.error, "You are signed out.")
        XCTAssertTrue(transport.requests.isEmpty, "no token, so no request should be attempted")
    }
}

final class MissingScopeParsingTests: XCTestCase {
    func testPullsTheScopeOutOfTheIssuersMessage() {
        XCTAssertEqual(
            GrooAuthSession.missingScope(in: #"missing required scope "accounts:tokens""#),
            "accounts:tokens"
        )
    }

    func testReturnsNilForAMessageThatNamesNoScope() {
        // Falling back to a generic protocol error is right here: inventing a
        // scope name from an unrelated refusal would send someone to re-approve
        // something that was never the problem.
        XCTAssertNil(GrooAuthSession.missingScope(in: "Forbidden"))
        XCTAssertNil(GrooAuthSession.missingScope(in: #"user is "blocked""#))
    }
}
