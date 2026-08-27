import Foundation
import XCTest
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
private func anchor() -> ASPresentationAnchor {
    #if canImport(AppKit)
    return NSWindow()
    #elseif canImport(UIKit)
    return UIWindow()
    #endif
}

private final class RecordingPasskeyAuthenticator: PasskeyAuthenticating, @unchecked Sendable {
    let registration: Result<PasskeyRegistration, Error>
    private(set) var lastRelyingParty: String?
    private(set) var lastChallenge: Data?
    private(set) var lastUserID: Data?
    private(set) var lastUserName: String?

    init(registration: Result<PasskeyRegistration, Error>) { self.registration = registration }

    func assert(
        relyingPartyIdentifier: String, challenge: Data, allowedCredentialIDs: [Data], anchor: ASPresentationAnchor
    ) async throws -> PasskeyAssertion {
        XCTFail("registration must never run an assertion")
        throw GrooAuthError.userCancelled
    }

    func register(
        relyingPartyIdentifier: String, challenge: Data, userID: Data, userName: String, anchor: ASPresentationAnchor
    ) async throws -> PasskeyRegistration {
        lastRelyingParty = relyingPartyIdentifier
        lastChallenge = challenge
        lastUserID = userID
        lastUserName = userName
        return try registration.get()
    }
}

/// Registering a passkey is the one account action a web console cannot perform
/// for someone: the credential is bound to the authenticator that made it.
@MainActor
final class PasskeyRegistrationTests: XCTestCase {
    private let optionsPath = "/v1/account/passkeys/register/options"
    private let verifyPath = "/v1/account/passkeys/register/verify"

    private func makeSession(
        transport: HTTPTransporting,
        passkey: PasskeyAuthenticating
    ) -> GrooAuthSession {
        let store = InMemoryTokenStore()
        try? store.save(StoredTokens(
            accessToken: "at-1", refreshToken: "rt-1", tokenType: "Bearer",
            expiresAt: Date().addingTimeInterval(3600), idToken: nil,
            scope: "openid accounts:passkeys", user: GrooUser(sub: "u1", email: "ada@groo.dev", name: "Ada")
        ))
        return GrooAuthSession(
            config: GrooAuthConfig(
                issuer: URL(string: "https://me.example.test")!,
                clientId: "c", redirectURI: "app://cb", scopes: ["openid"], keychainService: "t"
            ),
            tokenStore: store, transport: transport,
            webAuthenticator: StubWebAuthenticator(result: .failure(GrooAuthError.userCancelled)),
            passkeyAuthenticator: passkey
        )
    }

    private final class Transport: HTTPTransporting, @unchecked Sendable {
        var routes: [String: (status: Int, body: String)]
        private(set) var bodies: [String: Data] = [:]
        init(routes: [String: (status: Int, body: String)]) { self.routes = routes }

        func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
            let path = request.url!.path
            if let body = request.httpBody { bodies[path] = body }
            let next = routes[path] ?? (status: 404, body: #"{"error":"no route"}"#)
            let http = HTTPURLResponse(url: request.url!, statusCode: next.status, httpVersion: "HTTP/1.1", headerFields: nil)!
            return (Data(next.body.utf8), http)
        }

        func sendWithoutFollowingRedirects(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
            try await send(request)
        }
    }

    /// base64url of "challenge!" and of "user-handle-bytes".
    private let challengeB64 = PKCE.base64URL(Data("challenge!".utf8))
    private let userHandleB64 = PKCE.base64URL(Data("user-handle-bytes".utf8))

    private var created: PasskeyRegistration {
        PasskeyRegistration(credentialID: "Y3JlZA", clientDataJSON: "Y2Rq", attestationObject: "YXR0")
    }

    private func optionsBody() -> String {
        #"{"options":{"challenge":"\#(challengeB64)","user":{"id":"\#(userHandleB64)","name":"ada@groo.dev"}}}"#
    }

    func testSendsTheCreatedCredentialToTheIssuer() async throws {
        let transport = Transport(routes: [
            optionsPath: (200, optionsBody()),
            verifyPath: (201, #"{"passkey":{"id":"pk1"}}"#),
        ])
        let passkey = RecordingPasskeyAuthenticator(registration: .success(created))
        let session = makeSession(transport: transport, passkey: passkey)

        try await session.registerPasskey(name: "My iPhone", presentationAnchor: anchor())

        let body = try XCTUnwrap(transport.bodies[verifyPath])
        let json = try XCTUnwrap(try JSONSerialization.jsonObject(with: body) as? [String: Any])
        XCTAssertEqual(json["challenge"] as? String, challengeB64)
        XCTAssertEqual(json["name"] as? String, "My iPhone")
        let response = try XCTUnwrap(json["response"] as? [String: Any])
        XCTAssertEqual(response["type"] as? String, "public-key")
        let inner = try XCTUnwrap(response["response"] as? [String: Any])
        XCTAssertEqual(inner["clientDataJSON"] as? String, "Y2Rq")
        XCTAssertEqual(inner["attestationObject"] as? String, "YXR0")
    }

    func testUsesTheServersUserHandleVerbatim() async throws {
        let transport = Transport(routes: [
            optionsPath: (200, optionsBody()),
            verifyPath: (201, #"{"passkey":{"id":"pk1"}}"#),
        ])
        let passkey = RecordingPasskeyAuthenticator(registration: .success(created))
        let session = makeSession(transport: transport, passkey: passkey)

        try await session.registerPasskey(presentationAnchor: anchor())

        // WebAuthn stores these bytes verbatim and matches a later assertion
        // against them. Re-deriving the handle from `sub` produces a credential
        // the server cannot recognise — and it fails at the NEXT sign-in, not here.
        XCTAssertEqual(passkey.lastUserID, Data("user-handle-bytes".utf8))
        XCTAssertEqual(passkey.lastChallenge, Data("challenge!".utf8))
        XCTAssertEqual(passkey.lastRelyingParty, "me.example.test")
        XCTAssertEqual(passkey.lastUserName, "ada@groo.dev")
    }

    func testAMissingScopeIsNamedRatherThanGuessedAt() async throws {
        let transport = Transport(routes: [
            optionsPath: (403, #"{"error":"missing required scope \"accounts:passkeys\""}"#),
        ])
        let session = makeSession(
            transport: transport,
            passkey: RecordingPasskeyAuthenticator(registration: .success(created))
        )

        do {
            try await session.registerPasskey(presentationAnchor: anchor())
            XCTFail("expected insufficientScope")
        } catch GrooAuthError.insufficientScope(let scope) {
            XCTAssertEqual(scope, "accounts:passkeys")
        }
    }

    func testAStaleSignInKeepsTheIssuersOwnRefusal() async throws {
        // Both routes are step-up gated: adding a credential that can authenticate
        // the account outright is as sensitive as changing a password. Nothing the
        // SDK could substitute would be clearer than what the issuer says.
        let transport = Transport(routes: [
            optionsPath: (403, #"{"error":"Recent authentication required"}"#),
        ])
        let session = makeSession(
            transport: transport,
            passkey: RecordingPasskeyAuthenticator(registration: .success(created))
        )

        do {
            try await session.registerPasskey(presentationAnchor: anchor())
            XCTFail("expected protocolError")
        } catch GrooAuthError.protocolError(let oauth) {
            XCTAssertEqual(oauth.error, "Recent authentication required")
        }
    }

    func testACancelledSheetVerifiesNothing() async throws {
        let transport = Transport(routes: [optionsPath: (200, optionsBody())])
        let session = makeSession(
            transport: transport,
            passkey: RecordingPasskeyAuthenticator(registration: .failure(GrooAuthError.userCancelled))
        )

        do {
            try await session.registerPasskey(presentationAnchor: anchor())
            XCTFail("expected userCancelled")
        } catch GrooAuthError.userCancelled {
            // expected
        }
        XCTAssertNil(transport.bodies[verifyPath])
    }

    func testASignedOutSessionNeverPresentsASheet() async throws {
        let transport = Transport(routes: [:])
        let passkey = RecordingPasskeyAuthenticator(registration: .success(created))
        let session = GrooAuthSession(
            config: GrooAuthConfig(
                issuer: URL(string: "https://me.example.test")!,
                clientId: "c", redirectURI: "app://cb", scopes: ["openid"], keychainService: "t"
            ),
            tokenStore: InMemoryTokenStore(), transport: transport,
            webAuthenticator: StubWebAuthenticator(result: .failure(GrooAuthError.userCancelled)),
            passkeyAuthenticator: passkey
        )

        do {
            try await session.registerPasskey(presentationAnchor: anchor())
            XCTFail("expected signedOut")
        } catch GrooAuthError.signedOut {
            // expected
        }
        XCTAssertNil(passkey.lastRelyingParty)
    }
}
