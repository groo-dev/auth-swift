import Foundation
import XCTest
#if canImport(AuthenticationServices)
import AuthenticationServices
#endif
@testable import GrooAuth
@testable import GrooAuthUI

/// Answers by PATH, so a test can script four endpoints at once and assert which
/// of them were even asked.
private final class ListsTransport: HTTPTransporting, @unchecked Sendable {
    var routes: [String: (status: Int, body: String)]
    private(set) var paths: [String] = []
    private(set) var methods: [String: String] = [:]

    init(routes: [String: (status: Int, body: String)]) {
        self.routes = routes
    }

    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let path = request.url!.path
        paths.append(path)
        methods[path] = request.httpMethod ?? "GET"
        let next = routes[path] ?? (status: 404, body: #"{"error":"no route"}"#)
        let http = HTTPURLResponse(url: request.url!, statusCode: next.status, httpVersion: "HTTP/1.1", headerFields: nil)!
        return (Data(next.body.utf8), http)
    }

    func sendWithoutFollowingRedirects(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        try await send(request)
    }
}

private final class UnusedWeb: WebAuthenticating, @unchecked Sendable {
    func authenticate(url: URL, callbackScheme: String, anchor: ASPresentationAnchor) async throws -> URL {
        XCTFail("no sign-in in these tests")
        throw GrooAuthError.userCancelled
    }
}

@MainActor
final class GrooAccountListsTests: XCTestCase {
    private func makeStore(
        _ transport: ListsTransport,
        sections: GrooAccountSections = .all
    ) -> GrooAccountListsStore {
        let store = InMemoryTokenStore()
        try? store.save(StoredTokens(
            accessToken: "at-1", refreshToken: "rt-1", tokenType: "Bearer",
            expiresAt: Date().addingTimeInterval(3600), idToken: nil,
            scope: "openid", user: GrooUser(sub: "u1", email: "a@b.test", name: "Ada")
        ))
        let session = GrooAuthSession(
            config: GrooAuthConfig(
                issuer: URL(string: "https://me.example.test")!,
                clientId: "c", redirectURI: "app://cb", scopes: ["openid"], keychainService: "t"
            ),
            tokenStore: store, transport: transport, webAuthenticator: UnusedWeb()
        )
        return GrooAccountListsStore(session: session, sections: sections)
    }

    private var allRoutes: [String: (status: Int, body: String)] {
        [
            "/v1/account/passkeys": (200, #"{"passkeys":[{"id":"pk1","name":"iPhone","deviceType":"multiDevice","backedUp":true,"lastUsedAt":"2026-08-01T10:00:00.000Z","createdAt":"2026-07-01T10:00:00.000Z"}]}"#),
            "/v1/account/sessions": (200, #"{"sessions":[{"id":"s1","deviceInfo":"Safari","ipAddress":"1.2.3.4","lastActive":"2026-08-02T10:00:00.000Z","createdAt":"2026-08-01T10:00:00.000Z"}]}"#),
            "/v1/account/connected-apps": (200, #"{"apps":[{"id":"c1","applicationId":"app1","appName":"Pad","scopes":["pad:read"],"consentedAt":"2026-07-01T10:00:00.000Z","lastAccessedAt":"2026-08-03T10:00:00.000Z"}]}"#),
            "/v1/account/tokens": (200, #"{"tokens":[{"id":"t1","name":"CI","description":null,"tokenPrefix":"groo_pat_ab","lastUsed":null,"expiresAt":null,"revoked":false,"createdAt":"2026-07-01T10:00:00.000Z"}]}"#),
        ]
    }

    func testLoadsEverySectionItWasAskedFor() async {
        let transport = ListsTransport(routes: allRoutes)
        let store = makeStore(transport)

        await store.load()

        XCTAssertEqual(store.passkeys.first?.name, "iPhone")
        XCTAssertEqual(store.devices.first?.deviceInfo, "Safari")
        XCTAssertEqual(store.connectedApps.first?.appName, "Pad")
        XCTAssertEqual(store.tokens.first?.tokenPrefix, "groo_pat_ab")
        XCTAssertTrue(store.errors.values.compactMap { $0 }.isEmpty)
    }

    func testNeverFetchesASectionTheAppDidNotAskFor() async {
        // The point of the option set: a section costs a scope, and asking for a
        // scope the app does not use is what teaches people to approve without
        // reading. Fetching it anyway would make that promise a lie.
        let transport = ListsTransport(routes: allRoutes)
        let store = makeStore(transport, sections: [.passkeys])

        await store.load()

        XCTAssertEqual(transport.paths, ["/v1/account/passkeys"])
        XCTAssertTrue(store.devices.isEmpty)
        XCTAssertTrue(store.tokens.isEmpty)
    }

    func testOneSectionFailingLeavesTheOthersIntact() async {
        // The likely failure is a MISSING SCOPE, and scopes are per-section: an
        // app granted accounts:passkeys but not accounts:devices must still show
        // its passkeys rather than a blank screen.
        var routes = allRoutes
        routes["/v1/account/sessions"] = (403, #"{"error":"missing required scope \"accounts:devices\""}"#)
        let transport = ListsTransport(routes: routes)
        let store = makeStore(transport)

        await store.load()

        XCTAssertEqual(store.passkeys.count, 1)
        XCTAssertEqual(store.tokens.count, 1)
        XCTAssertTrue(store.devices.isEmpty)
        XCTAssertEqual(
            store.errors["devices"],
            "This app was not granted permission to accounts:devices. Sign out and in again to approve it."
        )
        XCTAssertNil(store.errors["passkeys"] ?? nil)
    }

    func testRevokingRereadsTheListRatherThanEditingItLocally() async {
        var routes = allRoutes
        let transport = ListsTransport(routes: routes)
        let store = makeStore(transport, sections: [.passkeys])
        await store.load()
        XCTAssertEqual(store.passkeys.count, 1)

        // The issuer decides what remains. A local splice would disagree with it
        // the moment two devices are doing this at once.
        routes["/v1/account/passkeys/pk1"] = (200, #"{"deleted":true}"#)
        routes["/v1/account/passkeys"] = (200, #"{"passkeys":[]}"#)
        transport.routes = routes

        await store.deletePasskey("pk1")

        XCTAssertEqual(transport.methods["/v1/account/passkeys/pk1"], "DELETE")
        XCTAssertTrue(store.passkeys.isEmpty)
        XCTAssertNil(store.pendingRevoke)
    }

    func testAFailedRevokeReportsAndLeavesTheRow() async {
        var routes = allRoutes
        routes["/v1/account/sessions/s1"] = (404, #"{"error":"Session not found"}"#)
        let transport = ListsTransport(routes: routes)
        let store = makeStore(transport, sections: [.devices])
        await store.load()

        await store.revokeDevice("s1")

        XCTAssertEqual(store.errors["devices"], "Session not found")
        // Still there: nothing was removed, and pretending otherwise would have
        // someone believe a device was signed out when it was not.
        XCTAssertEqual(store.devices.count, 1)
        XCTAssertNil(store.pendingRevoke)
    }

    func testDisconnectingAnAppUsesTheApplicationIdNotTheConsentId() async {
        // The route revokes every CLIENT the application owns, and it keys off the
        // application id. Sending the consent row's id matches nothing and reports
        // success — a silent no-op on a security action.
        var routes = allRoutes
        routes["/v1/account/connected-apps/app1"] = (200, #"{"revoked":true}"#)
        let transport = ListsTransport(routes: routes)
        let store = makeStore(transport, sections: [.connectedApps])
        await store.load()

        await store.disconnectApp(store.connectedApps[0].applicationId)

        XCTAssertEqual(transport.methods["/v1/account/connected-apps/app1"], "DELETE")
    }
}

final class GrooTimestampTests: XCTestCase {
    func testParsesTheMillisecondFormTheIssuerActuallySends() {
        // A default ISO8601DateFormatter returns nil for this, which would have
        // silently dropped the "last used" line off every row.
        XCTAssertNotNil(GrooTimestamp.parse("2026-08-01T10:00:00.000Z"))
    }

    func testAlsoParsesTheFormWithoutMilliseconds() {
        // Still valid ISO 8601. Refusing it would be the same bug mirrored.
        XCTAssertNotNil(GrooTimestamp.parse("2026-08-01T10:00:00Z"))
    }

    func testReturnsNilForSomethingThatIsNotADate() {
        XCTAssertNil(GrooTimestamp.parse("last Tuesday"))
    }
}
