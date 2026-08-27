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

/// Stands in for the platform sheet. The ceremony itself needs a real
/// authenticator and a window server, so what these tests exercise is the
/// protocol either side of it — which is where the bugs live anyway.
private final class StubPasskeyAuthenticator: PasskeyAuthenticating, @unchecked Sendable {
    let result: Result<PasskeyAssertion, Error>
    private(set) var lastRelyingParty: String?
    private(set) var lastChallenge: Data?
    private(set) var lastAllowedCredentialIDs: [Data]?

    init(result: Result<PasskeyAssertion, Error>) {
        self.result = result
    }

    func assert(
        relyingPartyIdentifier: String,
        challenge: Data,
        allowedCredentialIDs: [Data],
        anchor: ASPresentationAnchor
    ) async throws -> PasskeyAssertion {
        lastRelyingParty = relyingPartyIdentifier
        lastChallenge = challenge
        lastAllowedCredentialIDs = allowedCredentialIDs
        return try result.get()
    }

    func register(
        relyingPartyIdentifier: String,
        challenge: Data,
        userID: Data,
        userName: String,
        anchor: ASPresentationAnchor
    ) async throws -> PasskeyRegistration {
        XCTFail("sign-in must never create a passkey")
        throw GrooAuthError.userCancelled
    }
}

final class PasskeySignInTests: XCTestCase {
    private let testConfig = GrooAuthConfig(
        issuer: URL(string: "https://accounts.groo.dev")!,
        clientId: "test-client",
        redirectURI: "dev.groo.test://oauth-callback",
        scopes: ["openid", "profile", "email"],
        keychainService: "dev.groo.test"
    )

    private let discoveryURL = "https://accounts.groo.dev/.well-known/openid-configuration"
    private let optionsURL = "https://accounts.groo.dev/v1/auth/passkey/authenticate/options"
    private let verifyURL = "https://accounts.groo.dev/v1/auth/passkey/authenticate/verify"
    private let authorizePrefix = "https://accounts.groo.dev/v1/oauth/authorize"
    private let tokenURL = "https://accounts.groo.dev/v1/oauth/token"
    private let jwksURL = "https://accounts.groo.dev/.well-known/jwks.json"
    private let discoveryBody = #"""
    {"issuer":"https://accounts.groo.dev","authorization_endpoint":"https://accounts.groo.dev/v1/oauth/authorize","token_endpoint":"https://accounts.groo.dev/v1/oauth/token","jwks_uri":"https://accounts.groo.dev/.well-known/jwks.json"}
    """#

    private let expectedState = "expected-state-123"
    private let expectedNonce = "expected-nonce-456"
    private let expectedVerifier = "expected-verifier-789"

    /// base64url of "challenge-bytes", which is what the server would send.
    private let challengeB64 = PKCE.base64URL(Data("challenge-bytes".utf8))

    private var assertion: PasskeyAssertion {
        PasskeyAssertion(
            credentialID: "Y3JlZC1pZA",
            clientDataJSON: "Y2xpZW50LWRhdGE",
            authenticatorData: "YXV0aC1kYXRh",
            signature: "c2ln",
            userHandle: "dXNlcg"
        )
    }

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
        passkey: StubPasskeyAuthenticator,
        store: TokenStoring = InMemoryTokenStore()
    ) -> GrooAuthSession {
        GrooAuthSession(
            config: testConfig, tokenStore: store, transport: transport,
            webAuthenticator: StubWebAuthenticator(result: .failure(GrooAuthError.userCancelled)),
            passkeyAuthenticator: passkey, now: { Date() },
            pkceOverride: PKCEOverride(state: expectedState, nonce: expectedNonce, verifier: expectedVerifier)
        )
    }

    private func transportForHappyPath(idToken: String, jwksBody: String) -> MockTransport {
        let transport = MockTransport(routes: [
            discoveryURL: (200, discoveryBody),
            optionsURL: (200, #"{"options":{"challenge":"\#(challengeB64)"}}"#),
            verifyURL: (200, #"{"authTicket":"ticket-abc","expiresIn":60}"#),
            jwksURL: (200, jwksBody),
            tokenURL: (200, #"{"access_token":"at","refresh_token":"rt","token_type":"Bearer","expires_in":3600,"id_token":"\#(idToken)","scope":"openid profile email"}"#),
        ])
        transport.setPrefixRoute(
            authorizePrefix,
            status: 302,
            headers: ["Location": "dev.groo.test://oauth-callback?code=code-xyz&state=\(expectedState)&iss=https://accounts.groo.dev"]
        )
        return transport
    }

    private func idTokenClaims() -> [String: Any] {
        [
            "iss": "https://accounts.groo.dev",
            "aud": "test-client",
            "sub": "user-1",
            "exp": Int(Date().addingTimeInterval(3600).timeIntervalSince1970),
            "iat": Int(Date().timeIntervalSince1970),
            "nonce": expectedNonce,
            "email": "someone@groo.dev",
        ]
    }

    // MARK: - The whole flow

    func testSignsInAndStoresTokens() async throws {
        let (jwt, jwksBody) = try makeJWTAndJWKS(claims: idTokenClaims())
        let store = InMemoryTokenStore()
        let transport = transportForHappyPath(idToken: jwt, jwksBody: jwksBody)
        let passkey = StubPasskeyAuthenticator(result: .success(assertion))
        let session = makeSession(transport: transport, passkey: passkey, store: store)

        let user = try await session.signInWithPasskey(presentationAnchor: await makeTestAnchor())

        XCTAssertEqual(user.sub, "user-1")
        XCTAssertEqual(try store.load()?.accessToken, "at")
        XCTAssertEqual(try store.load()?.refreshToken, "rt")
    }

    func testRelyingPartyComesFromTheIssuerHost() async throws {
        let (jwt, jwksBody) = try makeJWTAndJWKS(claims: idTokenClaims())
        let transport = transportForHappyPath(idToken: jwt, jwksBody: jwksBody)
        let passkey = StubPasskeyAuthenticator(result: .success(assertion))
        let session = makeSession(transport: transport, passkey: passkey)

        _ = try await session.signInWithPasskey(presentationAnchor: await makeTestAnchor())

        // Never a literal: a passkey is bound to the relying party that created
        // it, and a hardcoded host would work for exactly one workspace.
        XCTAssertEqual(passkey.lastRelyingParty, "accounts.groo.dev")
    }

    func testChallengeIsDecodedFromBase64URLBeforeReachingThePlatform() async throws {
        let (jwt, jwksBody) = try makeJWTAndJWKS(claims: idTokenClaims())
        let transport = transportForHappyPath(idToken: jwt, jwksBody: jwksBody)
        let passkey = StubPasskeyAuthenticator(result: .success(assertion))
        let session = makeSession(transport: transport, passkey: passkey)

        _ = try await session.signInWithPasskey(presentationAnchor: await makeTestAnchor())

        // The wire is base64url and the platform wants bytes. Handing it the
        // string, or standard-base64 bytes, produces a signature the server
        // rejects with nothing useful to say about why.
        XCTAssertEqual(passkey.lastChallenge, Data("challenge-bytes".utf8))
    }

    func testSignInNamesNoCredentials() async throws {
        let (jwt, jwksBody) = try makeJWTAndJWKS(claims: idTokenClaims())
        let transport = transportForHappyPath(idToken: jwt, jwksBody: jwksBody)
        let passkey = StubPasskeyAuthenticator(result: .success(assertion))
        let session = makeSession(transport: transport, passkey: passkey)

        _ = try await session.signInWithPasskey(presentationAnchor: await makeTestAnchor())

        // The person has not said who they are yet, so any passkey for the
        // relying party may answer.
        XCTAssertEqual(passkey.lastAllowedCredentialIDs, [])
    }

    func testCarriesTheTicketAndPKCEToAuthorize() async throws {
        let (jwt, jwksBody) = try makeJWTAndJWKS(claims: idTokenClaims())
        let transport = transportForHappyPath(idToken: jwt, jwksBody: jwksBody)
        let passkey = StubPasskeyAuthenticator(result: .success(assertion))
        let session = makeSession(transport: transport, passkey: passkey)

        _ = try await session.signInWithPasskey(presentationAnchor: await makeTestAnchor())

        let authorizeCall = try XCTUnwrap(transport.calls.first(where: { $0.hasPrefix(authorizePrefix) }))
        let items = Dictionary(
            uniqueKeysWithValues: (URLComponents(string: authorizeCall)?.queryItems ?? []).map { ($0.name, $0.value ?? "") }
        )
        XCTAssertEqual(items["auth_ticket"], "ticket-abc")
        XCTAssertEqual(items["client_id"], "test-client")
        XCTAssertEqual(items["redirect_uri"], "dev.groo.test://oauth-callback")
        XCTAssertEqual(items["state"], expectedState)
        XCTAssertEqual(items["nonce"], expectedNonce)
        // PKCE is not optional on this path either — the code still has to be
        // exchanged for a verifier only this app holds.
        XCTAssertEqual(items["code_challenge"], PKCE.challenge(for: expectedVerifier))
        XCTAssertEqual(items["code_challenge_method"], "S256")
    }

    func testAsksTheIssuerForANativeTicket() async throws {
        let (jwt, jwksBody) = try makeJWTAndJWKS(claims: idTokenClaims())
        let transport = transportForHappyPath(idToken: jwt, jwksBody: jwksBody)
        let passkey = StubPasskeyAuthenticator(result: .success(assertion))
        let session = makeSession(transport: transport, passkey: passkey)

        _ = try await session.signInWithPasskey(presentationAnchor: await makeTestAnchor())

        let body = try XCTUnwrap(transport.lastBodies[verifyURL])
        let json = try XCTUnwrap(try JSONSerialization.jsonObject(with: body) as? [String: Any])
        // Without the flag the issuer answers with a session cookie, which is the
        // one thing an app cannot use.
        XCTAssertEqual(json["native_auth_ticket"] as? Bool, true)
        XCTAssertEqual(json["challenge"] as? String, challengeB64)
        XCTAssertEqual(json["client_id"] as? String, "test-client")

        let response = try XCTUnwrap(json["response"] as? [String: Any])
        XCTAssertEqual(response["id"] as? String, "Y3JlZC1pZA")
        XCTAssertEqual(response["type"] as? String, "public-key")
        let inner = try XCTUnwrap(response["response"] as? [String: Any])
        XCTAssertEqual(inner["clientDataJSON"] as? String, "Y2xpZW50LWRhdGE")
        XCTAssertEqual(inner["authenticatorData"] as? String, "YXV0aC1kYXRh")
        XCTAssertEqual(inner["signature"] as? String, "c2ln")
        XCTAssertEqual(inner["userHandle"] as? String, "dXNlcg")
    }

    // MARK: - The refusals, which are most of the work

    func testStoresNothingWhenTheIssuerNeedsAScreen() async throws {
        let store = InMemoryTokenStore()
        let transport = MockTransport(routes: [
            discoveryURL: (200, discoveryBody),
            optionsURL: (200, #"{"options":{"challenge":"\#(challengeB64)"}}"#),
            verifyURL: (200, #"{"authTicket":"ticket-abc","expiresIn":60}"#),
        ])
        transport.setPrefixRoute(
            authorizePrefix,
            status: 302,
            headers: ["Location": "dev.groo.test://oauth-callback?error=interaction_required&error_description=needs+consent&state=\(expectedState)"]
        )
        let session = makeSession(
            transport: transport,
            passkey: StubPasskeyAuthenticator(result: .success(assertion)),
            store: store
        )

        do {
            _ = try await session.signInWithPasskey(presentationAnchor: await makeTestAnchor())
            XCTFail("expected interactionRequired")
        } catch GrooAuthError.interactionRequired(let oauth) {
            XCTAssertEqual(oauth.error, "interaction_required")
        }
        XCTAssertNil(try store.load())
    }

    func testAccessDeniedIsAlsoSomethingTheHostedFlowCanAnswer() async throws {
        let transport = MockTransport(routes: [
            discoveryURL: (200, discoveryBody),
            optionsURL: (200, #"{"options":{"challenge":"\#(challengeB64)"}}"#),
            verifyURL: (200, #"{"authTicket":"ticket-abc","expiresIn":60}"#),
        ])
        // A spent or unknown ticket. The person is not at fault and the hosted
        // flow will work, so this must not surface as a protocol failure.
        transport.setPrefixRoute(
            authorizePrefix,
            status: 302,
            headers: ["Location": "dev.groo.test://oauth-callback?error=access_denied&state=\(expectedState)"]
        )
        let session = makeSession(transport: transport, passkey: StubPasskeyAuthenticator(result: .success(assertion)))

        do {
            _ = try await session.signInWithPasskey(presentationAnchor: await makeTestAnchor())
            XCTFail("expected interactionRequired")
        } catch GrooAuthError.interactionRequired {
            // expected
        }
    }

    func testStepUpAnswerIsTreatedAsNeedingAScreen() async throws {
        let transport = MockTransport(routes: [
            discoveryURL: (200, discoveryBody),
            optionsURL: (200, #"{"options":{"challenge":"\#(challengeB64)"}}"#),
            // A 200 that carries a step-up token instead of a ticket.
            verifyURL: (200, #"{"stepUpRequired":true,"stepUpToken":"t","targetAal":"aal2"}"#),
        ])
        let session = makeSession(transport: transport, passkey: StubPasskeyAuthenticator(result: .success(assertion)))

        do {
            _ = try await session.signInWithPasskey(presentationAnchor: await makeTestAnchor())
            XCTFail("expected interactionRequired")
        } catch GrooAuthError.interactionRequired {
            // expected
        }
    }

    func testABlockedAccountKeepsTheIssuersOwnWords() async throws {
        let transport = MockTransport(routes: [
            discoveryURL: (200, discoveryBody),
            optionsURL: (200, #"{"options":{"challenge":"\#(challengeB64)"}}"#),
            verifyURL: (403, #"{"error":"approval_pending","error_description":"Your account is pending approval"}"#),
        ])
        let session = makeSession(transport: transport, passkey: StubPasskeyAuthenticator(result: .success(assertion)))

        do {
            _ = try await session.signInWithPasskey(presentationAnchor: await makeTestAnchor())
            XCTFail("expected protocolError")
        } catch GrooAuthError.protocolError(let oauth) {
            // Nothing this SDK could say would be more useful than the issuer's
            // own sentence.
            XCTAssertEqual(oauth.errorDescription, "Your account is pending approval")
        }
    }

    func testAStateMismatchIsRefusedOnThisPathToo() async throws {
        let store = InMemoryTokenStore()
        let transport = MockTransport(routes: [
            discoveryURL: (200, discoveryBody),
            optionsURL: (200, #"{"options":{"challenge":"\#(challengeB64)"}}"#),
            verifyURL: (200, #"{"authTicket":"ticket-abc","expiresIn":60}"#),
        ])
        transport.setPrefixRoute(
            authorizePrefix,
            status: 302,
            headers: ["Location": "dev.groo.test://oauth-callback?code=c&state=someone-elses-state"]
        )
        let session = makeSession(
            transport: transport,
            passkey: StubPasskeyAuthenticator(result: .success(assertion)),
            store: store
        )

        do {
            _ = try await session.signInWithPasskey(presentationAnchor: await makeTestAnchor())
            XCTFail("expected stateMismatch")
        } catch GrooAuthError.stateMismatch {
            // expected
        }
        XCTAssertNil(try store.load())
    }

    func testAnUnavailablePasskeyPropagatesUnchanged() async throws {
        let transport = MockTransport(routes: [
            discoveryURL: (200, discoveryBody),
            optionsURL: (200, #"{"options":{"challenge":"\#(challengeB64)"}}"#),
        ])
        let session = makeSession(
            transport: transport,
            passkey: StubPasskeyAuthenticator(result: .failure(GrooAuthError.passkeyUnavailable))
        )

        do {
            _ = try await session.signInWithPasskey(presentationAnchor: await makeTestAnchor())
            XCTFail("expected passkeyUnavailable")
        } catch GrooAuthError.passkeyUnavailable {
            // The caller distinguishes this from a cancellation to decide whether
            // to keep offering the button.
        }
        XCTAssertNil(transport.lastBodies[verifyURL], "no assertion, nothing to verify")
    }

    func testCancellationStoresNothingAndVerifiesNothing() async throws {
        let store = InMemoryTokenStore()
        let transport = MockTransport(routes: [
            discoveryURL: (200, discoveryBody),
            optionsURL: (200, #"{"options":{"challenge":"\#(challengeB64)"}}"#),
        ])
        let session = makeSession(
            transport: transport,
            passkey: StubPasskeyAuthenticator(result: .failure(GrooAuthError.userCancelled)),
            store: store
        )

        do {
            _ = try await session.signInWithPasskey(presentationAnchor: await makeTestAnchor())
            XCTFail("expected userCancelled")
        } catch GrooAuthError.userCancelled {
            // expected
        }
        XCTAssertNil(try store.load())
    }
}
