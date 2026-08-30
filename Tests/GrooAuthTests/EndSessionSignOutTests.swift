import XCTest
import AuthenticationServices
#if canImport(AppKit)
import AppKit
#endif
#if canImport(UIKit)
import UIKit
#endif
@testable import GrooAuth

@MainActor
private func makeAnchor() -> ASPresentationAnchor {
    #if canImport(AppKit)
    return NSWindow()
    #elseif canImport(UIKit)
    return UIWindow()
    #endif
}

/// RP-INITIATED LOGOUT: `signOut` MUST END THE ISSUER'S BROWSER SESSION.
///
/// ═══ THE DEFECT THESE TESTS EXIST FOR ═══
///
/// Reported 2026-08-31: sign out of the iOS app, tap "Sign in with Groo", and you
/// are returned to the SAME account with no login screen, no consent screen and no
/// account picker. There was no way to sign in as anybody else.
///
/// Nothing was broken. `signOut` revoked the refresh token and cleared the
/// keychain, which signs the APP out; `ASWebAuthenticationSession` runs
/// non-ephemeral, so the issuer's cookie lives in the shared system-browser jar,
/// untouched. The next `/authorize` saw a valid session and existing consent and
/// returned a code immediately. Measured against the live issuer:
///
///     with the session cookie   -> 302 dev.groo.ios://oauth-callback?code=...
///     after /v1/auth/logout     -> 302 https://me.groo.dev/login?continue=...
///
/// On a shared device this means "Sign Out" leaves the next person one tap from
/// the previous person's account, with no credential.
///
/// ═══ WHY THESE ASSERTIONS ARE SHAPED THIS WAY ═══
///
/// A test that only checked `signOut` returns `.revokedAndCleared` would have
/// passed throughout the entire bug — that was the return value the whole time.
/// So each test below asserts on the thing that was actually missing: that a
/// request reached the web authenticator, that it went to the ADVERTISED
/// end-session URL, and that it carried a `post_logout_redirect_uri` (without
/// which the endpoint answers 200 with a body and the sheet never closes).
final class EndSessionSignOutTests: XCTestCase {
    private let testConfig = GrooAuthConfig(
        issuer: URL(string: "https://accounts.groo.dev")!,
        clientId: "test-client",
        redirectURI: "groo://callback",
        scopes: ["openid"],
        keychainService: "dev.groo.test"
    )

    private let discoveryURL = "https://accounts.groo.dev/.well-known/openid-configuration"
    private let revokeURL = "https://accounts.groo.dev/v1/oauth/revoke"

    private let withEndSession = #"""
    {"issuer":"https://accounts.groo.dev","authorization_endpoint":"https://accounts.groo.dev/v1/oauth/authorize","token_endpoint":"https://accounts.groo.dev/v1/oauth/token","jwks_uri":"https://accounts.groo.dev/.well-known/jwks.json","revocation_endpoint":"https://accounts.groo.dev/v1/oauth/revoke","end_session_endpoint":"https://accounts.groo.dev/v1/auth/logout"}
    """#

    private let withoutEndSession = #"""
    {"issuer":"https://accounts.groo.dev","authorization_endpoint":"https://accounts.groo.dev/v1/oauth/authorize","token_endpoint":"https://accounts.groo.dev/v1/oauth/token","jwks_uri":"https://accounts.groo.dev/.well-known/jwks.json","revocation_endpoint":"https://accounts.groo.dev/v1/oauth/revoke"}
    """#

    private func storeWithTokens() throws -> InMemoryTokenStore {
        let store = InMemoryTokenStore()
        try store.save(
            StoredTokens(
                accessToken: "access-1", refreshToken: "refresh-123", tokenType: "Bearer",
                expiresAt: Date().addingTimeInterval(3600), idToken: nil, scope: nil,
                user: GrooUser(sub: "u", email: nil, name: nil)
            )
        )
        return store
    }

    private func session(
        discovery: String,
        web: StubWebAuthenticator,
        store: InMemoryTokenStore
    ) -> GrooAuthSession {
        GrooAuthSession(
            config: testConfig,
            tokenStore: store,
            transport: MockTransport(routes: [discoveryURL: (200, discovery), revokeURL: (200, "")]),
            webAuthenticator: web,
            now: { Date() }
        )
    }

    /// THE CENTRAL ASSERTION. The browser is driven at all, and at the right URL.
    func testSignOutDrivesTheAdvertisedEndSessionEndpoint() async throws {
        let store = try storeWithTokens()
        let web = StubWebAuthenticator(result: .success(URL(string: "groo://callback")!))
        let s = session(discovery: withEndSession, web: web, store: store)

        let result = await s.signOut(presentationAnchor: await makeAnchor())

        XCTAssertEqual(result, .revokedAndCleared)
        let url = try XCTUnwrap(web.lastURL, "signOut must drive the web authenticator — this is the whole fix")
        XCTAssertEqual(url.host, "accounts.groo.dev")
        XCTAssertEqual(url.path, "/v1/auth/logout", "must use the ADVERTISED endpoint, not a guessed path")
    }

    /// Without this parameter the endpoint returns JSON instead of redirecting, and
    /// `ASWebAuthenticationSession` has no callback to fire — a sheet that hangs
    /// until the person cancels, which then reads as a failed sign-out.
    func testEndSessionRequestCarriesPostLogoutRedirectURI() async throws {
        let store = try storeWithTokens()
        let web = StubWebAuthenticator(result: .success(URL(string: "groo://callback")!))
        let s = session(discovery: withEndSession, web: web, store: store)

        _ = await s.signOut(presentationAnchor: await makeAnchor())

        let url = try XCTUnwrap(web.lastURL)
        let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems ?? []
        XCTAssertEqual(
            items.first(where: { $0.name == "post_logout_redirect_uri" })?.value,
            "groo://callback"
        )
        XCTAssertEqual(web.lastCallbackScheme, "groo", "the sheet closes on the redirectURI's own scheme")
    }

    /// A DISMISSED SHEET IS NOT A CLEAN SIGN-OUT. The cookie survives it, so the
    /// caller is told — this is the case a naive implementation swallows as
    /// `userCancelled` and reports success for.
    func testCancelledSheetIsReportedRatherThanRoundedUp() async throws {
        let store = try storeWithTokens()
        let web = StubWebAuthenticator(result: .failure(GrooAuthError.userCancelled))
        let s = session(discovery: withEndSession, web: web, store: store)

        let result = await s.signOut(presentationAnchor: await makeAnchor())

        guard case .clearedButBrowserSessionLive(let reason) = result else {
            XCTFail("a dismissed sheet leaves the cookie alive and must say so — got \(result)")
            return
        }
        XCTAssertTrue(reason.contains("dismissed"), "reason should name what happened: \(reason)")
        // Local sign-out is never held hostage to the browser step.
        XCTAssertNil(try store.load(), "local tokens must be cleared even when the sheet is dismissed")
        let state = await s.currentState()
        XCTAssertEqual(state, .signedOut)
    }

    /// An issuer with no `end_session_endpoint` cannot be logged out of. Guessing a
    /// path would open a sheet on a 404; reporting it is the honest option.
    func testIssuerWithNoEndSessionEndpointIsReportedNotGuessed() async throws {
        let store = try storeWithTokens()
        let web = StubWebAuthenticator(result: .success(URL(string: "groo://callback")!))
        let s = session(discovery: withoutEndSession, web: web, store: store)

        let result = await s.signOut(presentationAnchor: await makeAnchor())

        guard case .clearedButBrowserSessionLive(let reason) = result else {
            XCTFail("expected the live browser session to be reported, got \(result)")
            return
        }
        XCTAssertTrue(reason.contains("end_session_endpoint"), "reason should name what is missing: \(reason)")
        XCTAssertNil(web.lastURL, "no endpoint means no browser sheet at all — never a guessed URL")
    }

    /// A failed REVOKE outranks a live browser session, but must not erase it: both
    /// reasons travel together. Losing one because the other is being reported is
    /// how a partial sign-out comes to read as clean.
    func testRevokeFailureAndLiveBrowserSessionAreBothReported() async throws {
        let store = try storeWithTokens()
        let web = StubWebAuthenticator(result: .failure(GrooAuthError.userCancelled))
        let s = GrooAuthSession(
            config: testConfig,
            tokenStore: store,
            transport: MockTransport(routes: [
                discoveryURL: (200, withEndSession),
                revokeURL: (500, #"{"error":"server_error"}"#),
            ]),
            webAuthenticator: web,
            now: { Date() }
        )

        let result = await s.signOut(presentationAnchor: await makeAnchor())

        guard case .clearedButRevokeFailed(let reason) = result else {
            XCTFail("a failed revoke is the more serious case and should be reported — got \(result)")
            return
        }
        XCTAssertTrue(reason.contains("500"), "the revoke failure must survive: \(reason)")
        XCTAssertTrue(reason.contains("dismissed"), "the browser failure must survive too: \(reason)")
    }
}
