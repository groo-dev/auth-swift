import XCTest
import CryptoKit
#if canImport(AuthenticationServices)
import AuthenticationServices
#endif
#if canImport(AppKit)
import AppKit
#elseif canImport(UIKit)
import UIKit
#endif
@testable import GrooAuth

@MainActor
private func makeTestAnchor() -> ASPresentationAnchor {
    #if canImport(AppKit)
    return NSWindow()
    #elseif canImport(UIKit)
    return UIWindow()
    #endif
}

/// This issuer's `id_token` carries `sub`, `auth_time`, `nonce` and `amr` and
/// nothing else — OIDC Core 5.4 puts the `profile` and `email` claims at
/// UserInfo for a code flow. Without the follow-up call, `GrooUser.email` and
/// `.name` are nil for every client, which is what made a live Settings screen
/// render "?" where a person's name belongs.
final class UserInfoTests: XCTestCase {
    private let testConfig = GrooAuthConfig(
        issuer: URL(string: "https://accounts.groo.dev")!,
        clientId: "test-client",
        redirectURI: "dev.groo.test://oauth-callback",
        scopes: ["openid", "profile", "email"],
        keychainService: "dev.groo.test"
    )

    private let discoveryURL = "https://accounts.groo.dev/.well-known/openid-configuration"
    private let tokenURL = "https://accounts.groo.dev/v1/oauth/token"
    private let jwksURL = "https://accounts.groo.dev/.well-known/jwks.json"
    private let userinfoURL = "https://accounts.groo.dev/v1/oauth/userinfo"
    private let discoveryBody = #"""
    {"issuer":"https://accounts.groo.dev","authorization_endpoint":"https://accounts.groo.dev/v1/oauth/authorize","token_endpoint":"https://accounts.groo.dev/v1/oauth/token","jwks_uri":"https://accounts.groo.dev/.well-known/jwks.json","userinfo_endpoint":"https://accounts.groo.dev/v1/oauth/userinfo"}
    """#

    private let expectedState = "expected-state-123"
    private let expectedNonce = "expected-nonce-456"
    private let expectedVerifier = "expected-verifier-789"

    private func makeJWTAndJWKS(claims: [String: Any], kid: String = "k1") throws -> (jwt: String, jwksBody: String) {
        let key = P256.Signing.PrivateKey()
        func b64(_ d: Data) -> String { PKCE.base64URL(d) }
        let header = try JSONSerialization.data(withJSONObject: ["alg": "ES256", "kid": kid, "typ": "JWT"])
        let payload = try JSONSerialization.data(withJSONObject: claims)
        let signingInput = b64(header) + "." + b64(payload)
        let sig = try key.signature(for: Data(signingInput.utf8))
        let jwt = signingInput + "." + b64(sig.rawRepresentation)
        let pub = key.publicKey.x963Representation
        let x = pub.subdata(in: 1..<33), y = pub.subdata(in: 33..<65)
        let jwksBody = #"{"keys":[{"kty":"EC","crv":"P-256","x":"\#(b64(x))","y":"\#(b64(y))","kid":"\#(kid)","alg":"ES256"}]}"#
        return (jwt, jwksBody)
    }

    /// An id_token exactly as this issuer mints it: no name, no email.
    private func claimlessIDToken() -> [String: Any] {
        [
            "iss": "https://accounts.groo.dev",
            "aud": "test-client",
            "sub": "user-1",
            "exp": Int(Date().addingTimeInterval(3600).timeIntervalSince1970),
            "iat": Int(Date().timeIntervalSince1970),
            "nonce": expectedNonce,
            "auth_time": Int(Date().timeIntervalSince1970),
        ]
    }

    /// The same document with no `userinfo_endpoint`, for an issuer that offers none.
    private var discoveryWithoutUserInfo: String {
        #"""
        {"issuer":"https://accounts.groo.dev","authorization_endpoint":"https://accounts.groo.dev/v1/oauth/authorize","token_endpoint":"https://accounts.groo.dev/v1/oauth/token","jwks_uri":"https://accounts.groo.dev/.well-known/jwks.json"}
        """#
    }

    private func signIn(
        userinfo: (status: Int, body: String)?,
        discovery: String? = nil,
        store: TokenStoring
    ) async throws -> GrooUser {
        let (jwt, jwksBody) = try makeJWTAndJWKS(claims: claimlessIDToken())
        var routes: [String: (status: Int, body: String)] = [
            discoveryURL: (200, discovery ?? discoveryBody),
            jwksURL: (200, jwksBody),
            tokenURL: (200, #"{"access_token":"at","refresh_token":"rt","token_type":"Bearer","expires_in":3600,"id_token":"\#(jwt)","scope":"openid profile email"}"#),
        ]
        if let userinfo { routes[userinfoURL] = userinfo }
        let transport = MockTransport(routes: routes)
        let callback = URL(string: "dev.groo.test://oauth-callback?code=abc&state=\(expectedState)")!
        let session = GrooAuthSession(
            config: testConfig, tokenStore: store, transport: transport,
            webAuthenticator: StubWebAuthenticator(result: .success(callback)), now: { Date() },
            pkceOverride: PKCEOverride(state: expectedState, nonce: expectedNonce, verifier: expectedVerifier)
        )
        return try await session.signIn(presentationAnchor: await makeTestAnchor())
    }

    func testFillsNameAndEmailFromUserInfo() async throws {
        let store = InMemoryTokenStore()
        let user = try await signIn(
            userinfo: (200, #"{"sub":"user-1","name":"Ada","email":"ada@groo.dev","email_verified":true}"#),
            store: store
        )

        XCTAssertEqual(user.name, "Ada")
        XCTAssertEqual(user.email, "ada@groo.dev")
        // Persisted, so a relaunch shows a name without another round trip.
        XCTAssertEqual(try store.load()?.user?.name, "Ada")
    }

    func testASignInStillSucceedsWhenUserInfoFails() async throws {
        // The tokens are already in hand and valid at this point. Trading a working
        // session for a display name would be the wrong way round.
        let store = InMemoryTokenStore()
        let user = try await signIn(userinfo: (500, #"{"error":"boom"}"#), store: store)

        XCTAssertEqual(user.sub, "user-1")
        XCTAssertNil(user.name)
        XCTAssertNotNil(try store.load()?.accessToken)
    }

    func testAMismatchedSubjectIsDiscarded() async throws {
        // OIDC Core 5.3.2. A response for a different subject is not a partial
        // answer, it is a mixed-up one, and taking the name off it would label
        // this session with someone else's identity.
        let store = InMemoryTokenStore()
        let user = try await signIn(
            userinfo: (200, #"{"sub":"someone-else","name":"Mallory","email":"mallory@evil.test"}"#),
            store: store
        )

        XCTAssertEqual(user.sub, "user-1")
        XCTAssertNil(user.name)
        XCTAssertNil(user.email)
    }

    func testAnIssuerWithNoUserInfoEndpointIsNotAnError() async throws {
        // Discovery without the endpoint at all — not merely a route that fails.
        // An issuer is allowed to offer no UserInfo, and a client that treated
        // that as a broken sign-in would be wrong about the spec.
        let store = InMemoryTokenStore()
        let user = try await signIn(userinfo: nil, discovery: discoveryWithoutUserInfo, store: store)
        XCTAssertEqual(user.sub, "user-1")
        XCTAssertNil(user.name)
    }
}
