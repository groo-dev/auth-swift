import XCTest
import CryptoKit
@testable import GrooAuth

final class SignInTests: XCTestCase {
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
    private let discoveryBody = #"""
    {"issuer":"https://accounts.groo.dev","authorization_endpoint":"https://accounts.groo.dev/v1/oauth/authorize","token_endpoint":"https://accounts.groo.dev/v1/oauth/token","jwks_uri":"https://accounts.groo.dev/.well-known/jwks.json"}
    """#

    private let expectedState = "expected-state-123"
    private let expectedNonce = "expected-nonce-456"
    private let expectedVerifier = "expected-verifier-789"

    /// Signs `claims` with a fresh ES256 key and returns the JWT plus the matching
    /// JWKS body (reusing Task 4's approach: `x963Representation` split into X/Y).
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

    private func makeSession(
        transport: MockTransport,
        webAuthenticator: StubWebAuthenticator,
        store: TokenStoring = InMemoryTokenStore()
    ) -> GrooAuthSession {
        GrooAuthSession(
            config: testConfig, tokenStore: store, transport: transport,
            webAuthenticator: webAuthenticator, now: { Date() },
            pkceOverride: PKCEOverride(state: expectedState, nonce: expectedNonce, verifier: expectedVerifier)
        )
    }

    // MARK: - (a) Authorization URL shape

    func testAuthorizationURLContainsRequiredParams() async throws {
        let store = InMemoryTokenStore()
        let transport = MockTransport(routes: [discoveryURL: (200, discoveryBody)])
        let stub = StubWebAuthenticator(result: .failure(GrooAuthError.userCancelled))
        let session = makeSession(transport: transport, webAuthenticator: stub, store: store)

        do {
            _ = try await session.signIn(presentationAnchor: nil)
            XCTFail("expected the stub's userCancelled failure to propagate")
        } catch GrooAuthError.userCancelled {
            // expected
        }

        guard let authorizeURL = stub.lastURL else {
            return XCTFail("webAuthenticator.authenticate was never called")
        }
        XCTAssertEqual(stub.lastCallbackScheme, "dev.groo.test")

        let components = URLComponents(url: authorizeURL, resolvingAgainstBaseURL: false)!
        XCTAssertEqual(components.scheme, "https")
        XCTAssertEqual(components.host, "accounts.groo.dev")
        XCTAssertEqual(components.path, "/v1/oauth/authorize")

        let items = Dictionary(uniqueKeysWithValues: (components.queryItems ?? []).map { ($0.name, $0.value ?? "") })
        XCTAssertEqual(items["client_id"], "test-client")
        XCTAssertEqual(items["response_type"], "code")
        XCTAssertEqual(items["redirect_uri"], "dev.groo.test://oauth-callback")
        XCTAssertEqual(items["scope"], "openid profile email")
        XCTAssertEqual(items["state"], expectedState)
        XCTAssertEqual(items["nonce"], expectedNonce)
        XCTAssertEqual(items["code_challenge"], PKCE.challenge(for: expectedVerifier))
        XCTAssertEqual(items["code_challenge_method"], "S256")

        XCTAssertNil(try store.load(), "a cancelled/failed sign-in must not store anything")
    }

    // MARK: - (b) Mismatched state

    func testMismatchedStateThrowsAndStoresNothing() async throws {
        let store = InMemoryTokenStore()
        let transport = MockTransport(routes: [discoveryURL: (200, discoveryBody)])
        let callback = URL(string: "dev.groo.test://oauth-callback?code=abc&state=not-the-expected-state")!
        let stub = StubWebAuthenticator(result: .success(callback))
        let session = makeSession(transport: transport, webAuthenticator: stub, store: store)

        do {
            _ = try await session.signIn(presentationAnchor: nil)
            XCTFail("expected .stateMismatch")
        } catch GrooAuthError.stateMismatch {
            // expected
        }

        XCTAssertNil(try store.load(), "state mismatch must not store any tokens")
        let state = await session.currentState()
        XCTAssertEqual(state, .signedOut)
    }

    // MARK: - (c) Happy path

    func testHappyPathStoresTokensAndReturnsUser() async throws {
        let store = InMemoryTokenStore()
        let exp = Date().addingTimeInterval(600).timeIntervalSince1970
        let (jwt, jwksBody) = try makeJWTAndJWKS(claims: [
            "sub": "user-1",
            "aud": "test-client",
            "iss": "https://accounts.groo.dev",
            "exp": exp,
            "nonce": expectedNonce,
            "email": "a@b.c",
            "name": "Ada",
        ])
        let transport = MockTransport(routes: [
            discoveryURL: (200, discoveryBody),
            tokenURL: (200, #"""
            {"access_token":"at1","refresh_token":"rt1","token_type":"Bearer","expires_in":900,"id_token":"\#(jwt)","scope":"openid profile email"}
            """#),
            jwksURL: (200, jwksBody),
        ])
        let callback = URL(string: "dev.groo.test://oauth-callback?code=abc&state=\(expectedState)")!
        let stub = StubWebAuthenticator(result: .success(callback))
        let session = makeSession(transport: transport, webAuthenticator: stub, store: store)

        let user = try await session.signIn(presentationAnchor: nil)

        XCTAssertEqual(user.sub, "user-1")
        XCTAssertEqual(user.email, "a@b.c")
        XCTAssertEqual(user.name, "Ada")

        let stored = try store.load()
        XCTAssertEqual(stored?.accessToken, "at1")
        XCTAssertEqual(stored?.refreshToken, "rt1")
        XCTAssertEqual(stored?.idToken, jwt)
        XCTAssertEqual(stored?.user, user)

        let state = await session.currentState()
        XCTAssertEqual(state, .signedIn(user))
    }

    // MARK: - (d) Callback carries an error

    func testCallbackErrorThrowsProtocolError() async throws {
        let store = InMemoryTokenStore()
        let transport = MockTransport(routes: [discoveryURL: (200, discoveryBody)])
        let callback = URL(string: "dev.groo.test://oauth-callback?error=access_denied&state=\(expectedState)")!
        let stub = StubWebAuthenticator(result: .success(callback))
        let session = makeSession(transport: transport, webAuthenticator: stub, store: store)

        do {
            _ = try await session.signIn(presentationAnchor: nil)
            XCTFail("expected .protocolError")
        } catch GrooAuthError.protocolError(let err) {
            XCTAssertEqual(err.error, "access_denied")
        }

        XCTAssertNil(try store.load())
    }

    // MARK: - stateStream

    func testStateStreamEmitsCurrentThenSignedInOnSuccess() async throws {
        let store = InMemoryTokenStore()
        let exp = Date().addingTimeInterval(600).timeIntervalSince1970
        let (jwt, jwksBody) = try makeJWTAndJWKS(claims: [
            "sub": "user-1",
            "aud": "test-client",
            "iss": "https://accounts.groo.dev",
            "exp": exp,
            "nonce": expectedNonce,
        ])
        let transport = MockTransport(routes: [
            discoveryURL: (200, discoveryBody),
            tokenURL: (200, #"""
            {"access_token":"at1","refresh_token":"rt1","token_type":"Bearer","expires_in":900,"id_token":"\#(jwt)"}
            """#),
            jwksURL: (200, jwksBody),
        ])
        let callback = URL(string: "dev.groo.test://oauth-callback?code=abc&state=\(expectedState)")!
        let stub = StubWebAuthenticator(result: .success(callback))
        let session = makeSession(transport: transport, webAuthenticator: stub, store: store)

        let stream = await session.stateStream
        var iterator = stream.makeAsyncIterator()

        let initial = await iterator.next()
        XCTAssertEqual(initial, .signedOut, "a fresh subscriber sees the current (signed-out) state immediately")

        let user = try await session.signIn(presentationAnchor: nil)

        let afterSignIn = await iterator.next()
        XCTAssertEqual(afterSignIn, .signedIn(user), "signIn success must publish .signedIn on the state stream")
    }
}
