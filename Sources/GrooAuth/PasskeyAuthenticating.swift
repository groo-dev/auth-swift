import Foundation
#if canImport(AuthenticationServices)
import AuthenticationServices
#endif

/// One passkey assertion, in the shape the server's WebAuthn verifier expects.
///
/// Every field is base64url, because that is what `AuthenticationResponseJSON`
/// is: `@simplewebauthn/server` parses these strings, and handing it standard
/// base64 produces a signature failure with nothing to say about why.
public struct PasskeyAssertion: Sendable, Equatable {
    public let credentialID: String
    public let clientDataJSON: String
    public let authenticatorData: String
    public let signature: String
    /// Present when the authenticator returned one. A discoverable credential
    /// carries the user handle; the server does not need it to find the passkey,
    /// which is why this is allowed to be absent rather than treated as a failure.
    public let userHandle: String?

    public init(
        credentialID: String,
        clientDataJSON: String,
        authenticatorData: String,
        signature: String,
        userHandle: String?
    ) {
        self.credentialID = credentialID
        self.clientDataJSON = clientDataJSON
        self.authenticatorData = authenticatorData
        self.signature = signature
        self.userHandle = userHandle
    }
}

/// One newly created passkey, in the shape the server's WebAuthn verifier expects.
public struct PasskeyRegistration: Sendable, Equatable {
    public let credentialID: String
    public let clientDataJSON: String
    public let attestationObject: String

    public init(credentialID: String, clientDataJSON: String, attestationObject: String) {
        self.credentialID = credentialID
        self.clientDataJSON = clientDataJSON
        self.attestationObject = attestationObject
    }
}

/// Abstraction over `ASAuthorizationController`, for the same reason
/// `WebAuthenticating` abstracts `ASWebAuthenticationSession`: the ceremony needs
/// a real authenticator and a window server, so the flow around it is what tests
/// can actually exercise.
public protocol PasskeyAuthenticating: Sendable {
    /// - Parameters:
    ///   - relyingPartyIdentifier: the issuer's host. Never a literal — a passkey
    ///     is bound to the RP that created it, and a mismatch here is not an error
    ///     the person can act on, it is simply "no passkeys found".
    ///   - challenge: raw bytes, already decoded from the server's base64url.
    ///   - allowedCredentialIDs: empty means "any passkey for this RP", which is
    ///     what a sign-in wants — the person has not said who they are yet.
    func assert(
        relyingPartyIdentifier: String,
        challenge: Data,
        allowedCredentialIDs: [Data],
        anchor: ASPresentationAnchor
    ) async throws -> PasskeyAssertion

    /// Creates a passkey on THIS device.
    ///
    /// The one account action a web console genuinely cannot perform on someone's
    /// behalf: a passkey is bound to the authenticator that made it, so a browser
    /// on a laptop cannot enrol a phone.
    ///
    /// - Parameters:
    ///   - userID: the account's `sub`, as raw bytes.
    ///   - userName: what the platform shows in its sheet and later in the
    ///     password manager — an email, normally.
    func register(
        relyingPartyIdentifier: String,
        challenge: Data,
        userID: Data,
        userName: String,
        anchor: ASPresentationAnchor
    ) async throws -> PasskeyRegistration
}

#if canImport(AuthenticationServices) && !os(watchOS) && !os(tvOS)

/// Production `PasskeyAuthenticating` backed by `ASAuthorizationController`.
///
/// Kept thin for the same reason `ASWebAuthenticator` is: there is no
/// authenticator in CI to drive it. `GrooAuthSession.signInWithPasskey` owns the
/// protocol work and is what the suite exercises.
public final class ASPasskeyAuthenticator: PasskeyAuthenticating, @unchecked Sendable {
    public init() {}

    public func assert(
        relyingPartyIdentifier: String,
        challenge: Data,
        allowedCredentialIDs: [Data],
        anchor: ASPresentationAnchor
    ) async throws -> PasskeyAssertion {
        try await withCheckedThrowingContinuation { continuation in
            Task { @MainActor in
                let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
                    relyingPartyIdentifier: relyingPartyIdentifier
                )
                let request = provider.createCredentialAssertionRequest(challenge: challenge)
                if !allowedCredentialIDs.isEmpty {
                    request.allowedCredentials = allowedCredentialIDs.map {
                        ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: $0)
                    }
                }
                Self.present(request, anchor: anchor, continuation: PasskeyDelegate.Outcome.assertion(continuation))
            }
        }
    }

    public func register(
        relyingPartyIdentifier: String,
        challenge: Data,
        userID: Data,
        userName: String,
        anchor: ASPresentationAnchor
    ) async throws -> PasskeyRegistration {
        try await withCheckedThrowingContinuation { continuation in
            Task { @MainActor in
                let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
                    relyingPartyIdentifier: relyingPartyIdentifier
                )
                let request = provider.createCredentialRegistrationRequest(
                    challenge: challenge,
                    name: userName,
                    userID: userID
                )
                Self.present(request, anchor: anchor, continuation: PasskeyDelegate.Outcome.registration(continuation))
            }
        }
    }

    @MainActor
    private static func present(
        _ request: ASAuthorizationRequest,
        anchor: ASPresentationAnchor,
        continuation: PasskeyDelegate.Outcome
    ) {
        let controller = ASAuthorizationController(authorizationRequests: [request])
        let delegate = PasskeyDelegate(anchor: anchor, outcome: continuation)
        controller.delegate = delegate
        controller.presentationContextProvider = delegate
        // The controller does not retain its delegate, and the delegate is the
        // only thing holding the continuation. Without this the whole pair is
        // deallocated at the end of this closure and the caller waits forever.
        delegate.controller = controller
        controller.performRequests()
    }
}

/// Holds the continuation and keeps itself alive until exactly one of the two
/// delegate callbacks fires.
@MainActor
private final class PasskeyDelegate: NSObject, ASAuthorizationControllerDelegate,
    ASAuthorizationControllerPresentationContextProviding
{
    /// Which ceremony is in flight. The two differ only in what the platform
    /// hands back, and the failure handling below is identical — so it is written
    /// once and this says who to resume.
    enum Outcome {
        case assertion(CheckedContinuation<PasskeyAssertion, Error>)
        case registration(CheckedContinuation<PasskeyRegistration, Error>)
    }

    private let anchor: ASPresentationAnchor
    private var outcome: Outcome?
    var controller: ASAuthorizationController?
    /// Retains self until a callback fires — see `ASPasskeyAuthenticator.present`.
    private var selfRetain: PasskeyDelegate?

    init(anchor: ASPresentationAnchor, outcome: Outcome) {
        self.anchor = anchor
        self.outcome = outcome
        super.init()
        self.selfRetain = self
    }

    /// A `CheckedContinuation` traps if resumed twice, so finishing is funnelled
    /// through here rather than trusting the framework to call back exactly once.
    private func finish(_ error: Error) {
        guard let outcome else { return }
        release()
        switch outcome {
        case .assertion(let c): c.resume(throwing: error)
        case .registration(let c): c.resume(throwing: error)
        }
    }

    private func finish(_ assertion: PasskeyAssertion) {
        guard case .assertion(let c) = outcome else {
            finish(GrooAuthError.invalidResponse("the platform answered a registration with an assertion"))
            return
        }
        release()
        c.resume(returning: assertion)
    }

    private func finish(_ registration: PasskeyRegistration) {
        guard case .registration(let c) = outcome else {
            finish(GrooAuthError.invalidResponse("the platform answered an assertion with a registration"))
            return
        }
        release()
        c.resume(returning: registration)
    }

    private func release() {
        outcome = nil
        controller = nil
        selfRetain = nil
    }

    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor { anchor }

    func authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithAuthorization authorization: ASAuthorization
    ) {
        if let assertion = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion {
            guard let signature = assertion.signature else {
                finish(GrooAuthError.invalidResponse("passkey assertion carried no signature"))
                return
            }
            guard let authenticatorData = assertion.rawAuthenticatorData else {
                finish(GrooAuthError.invalidResponse("passkey assertion carried no authenticator data"))
                return
            }
            finish(PasskeyAssertion(
                credentialID: PKCE.base64URL(assertion.credentialID),
                clientDataJSON: PKCE.base64URL(assertion.rawClientDataJSON),
                authenticatorData: PKCE.base64URL(authenticatorData),
                signature: PKCE.base64URL(signature),
                userHandle: assertion.userID.map { PKCE.base64URL($0) }
            ))
            return
        }
        if let created = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration {
            guard let attestation = created.rawAttestationObject else {
                finish(GrooAuthError.invalidResponse("new passkey carried no attestation object"))
                return
            }
            finish(PasskeyRegistration(
                credentialID: PKCE.base64URL(created.credentialID),
                clientDataJSON: PKCE.base64URL(created.rawClientDataJSON),
                attestationObject: PKCE.base64URL(attestation)
            ))
            return
        }
        finish(GrooAuthError.invalidResponse(
            "the platform returned \(type(of: authorization.credential)), which is neither ceremony's credential"
        ))
    }

    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        let code = (error as? ASAuthorizationError)?.code
        // `.canceled` is the sheet being dismissed. `.notHandled`/`.failed` are what
        // this device answers when it holds no passkey for the relying party — which
        // is not a failure either: it is the ordinary state of a device that has
        // never enrolled one, and the caller offers the password flow instead.
        switch code {
        case .canceled:
            finish(GrooAuthError.userCancelled)
        case .notHandled, .failed:
            finish(GrooAuthError.passkeyUnavailable)
        default:
            GrooAuthLog.web.error("passkey ceremony failed: \(error.localizedDescription, privacy: .public)")
            finish(GrooAuthError.transport(error.localizedDescription))
        }
    }
}

#endif
