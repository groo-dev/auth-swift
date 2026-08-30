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

/// `prompt` ON THE AUTHORIZE URL — HOW ACCOUNT SWITCHING ACTUALLY WORKS.
///
/// Reported 2026-08-31: sign out of the iOS app, tap "Sign in with Groo", and you
/// are returned to the SAME account with no screen of any kind. Signing out
/// clears this app's tokens; the issuer's cookie lives in the shared
/// system-browser jar (`ASWebAuthenticationSession` is deliberately
/// non-ephemeral), and the issuer answered that cookie with a code.
///
/// The fix belongs HERE rather than at sign-out. Clearing the browser cookie from
/// the app costs a system consent sheet on every sign-out, and no major provider
/// works that way — `accounts.google.com` advertises no `end_session_endpoint`
/// whatsoever (checked 2026-08-31), so an app signing in with Google never logs
/// you out of the browser; it sends `prompt` at authorize time.
///
/// These tests read the URL the web authenticator was handed, because that URL is
/// the entire contract with the issuer. `signIn` returning a user proves nothing
/// about it: it returned one throughout the bug.
final class SignInPromptTests: XCTestCase {
    private let config = GrooAuthConfig(
        issuer: URL(string: "https://accounts.groo.dev")!,
        clientId: "test-client",
        redirectURI: "groo://callback",
        scopes: ["openid", "email"],
        keychainService: "dev.groo.test"
    )

    private let discoveryURL = "https://accounts.groo.dev/.well-known/openid-configuration"
    private let discovery = #"""
    {"issuer":"https://accounts.groo.dev","authorization_endpoint":"https://accounts.groo.dev/v1/oauth/authorize","token_endpoint":"https://accounts.groo.dev/v1/oauth/token","jwks_uri":"https://accounts.groo.dev/.well-known/jwks.json"}
    """#

    /// Drives `signIn` far enough to capture the authorize URL. The flow fails
    /// afterwards (the stub returns a callback with no code), which is fine — the
    /// URL has already been built and recorded by then, and that is the subject.
    private func authorizeURL(prompt: GrooAuthPrompt?) async -> URL? {
        let web = StubWebAuthenticator(result: .success(URL(string: "groo://callback?error=access_denied")!))
        let session = GrooAuthSession(
            config: config,
            tokenStore: InMemoryTokenStore(),
            transport: MockTransport(routes: [discoveryURL: (200, discovery)]),
            webAuthenticator: web,
            now: { Date() }
        )
        _ = try? await session.signIn(presentationAnchor: await makeAnchor(), prompt: prompt)
        return web.lastURL
    }

    private func query(_ url: URL?, _ name: String) -> String? {
        guard let url else { return nil }
        return URLComponents(url: url, resolvingAgainstBaseURL: false)?
            .queryItems?.first(where: { $0.name == name })?.value
    }

    /// THE DEFAULT MUST STAY SILENT. Every other Groo app relies on single
    /// sign-on: with a live browser session and existing consent the issuer
    /// returns a code with no screen. Sending `prompt` unconditionally would put
    /// a login form in front of all of them.
    func testNoPromptIsSentByDefault() async {
        let url = await authorizeURL(prompt: nil)
        XCTAssertNotNil(url, "signIn must still build an authorize URL")
        XCTAssertNil(query(url, "prompt"), "no prompt unless the caller asks — this is what preserves SSO")
    }

    func testPromptLoginIsSentWhenRequested() async {
        let url = await authorizeURL(prompt: .login)
        XCTAssertEqual(query(url, "prompt"), "login")
    }

    /// Adding `prompt` must not disturb the rest of the request. PKCE especially:
    /// a challenge dropped or replaced here fails at the token endpoint, long
    /// after the screen the person was looking at.
    func testPromptDoesNotDisturbTheRestOfTheRequest() async {
        let withPrompt = await authorizeURL(prompt: .login)
        let without = await authorizeURL(prompt: nil)

        for name in ["response_type", "client_id", "redirect_uri", "scope", "code_challenge_method"] {
            XCTAssertEqual(
                query(withPrompt, name), query(without, name),
                "\(name) must be identical with and without prompt"
            )
        }
        XCTAssertEqual(query(withPrompt, "code_challenge_method"), "S256")
        XCTAssertNotNil(query(withPrompt, "code_challenge"))
        XCTAssertNotNil(query(withPrompt, "state"))
        XCTAssertNotNil(query(withPrompt, "nonce"))
    }

    /// The value has to be exactly what OIDC defines; the Groo issuer refuses
    /// anything it does not implement rather than ignoring it, so a typo here
    /// would be a sign-in that always fails.
    func testRawValueMatchesTheSpecSpelling() {
        XCTAssertEqual(GrooAuthPrompt.login.rawValue, "login")
    }
}
