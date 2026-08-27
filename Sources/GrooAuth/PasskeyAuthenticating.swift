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

                let controller = ASAuthorizationController(authorizationRequests: [request])
                let delegate = PasskeyDelegate(anchor: anchor, continuation: continuation)
                controller.delegate = delegate
                controller.presentationContextProvider = delegate
                // The controller does not retain its delegate, and the delegate is
                // the only thing holding the continuation. Without this the whole
                // pair is deallocated at the end of this closure and the caller
                // waits forever.
                delegate.controller = controller
                controller.performRequests()
            }
        }
    }
}

/// Holds the continuation and keeps itself alive until exactly one of the two
/// delegate callbacks fires.
@MainActor
private final class PasskeyDelegate: NSObject, ASAuthorizationControllerDelegate,
    ASAuthorizationControllerPresentationContextProviding
{
    private let anchor: ASPresentationAnchor
    private var continuation: CheckedContinuation<PasskeyAssertion, Error>?
    var controller: ASAuthorizationController?
    /// Retains self until a callback fires — see `ASPasskeyAuthenticator.assert`.
    private var selfRetain: PasskeyDelegate?

    init(anchor: ASPresentationAnchor, continuation: CheckedContinuation<PasskeyAssertion, Error>) {
        self.anchor = anchor
        self.continuation = continuation
        super.init()
        self.selfRetain = self
    }

    /// A `CheckedContinuation` traps if resumed twice, so finishing is funnelled
    /// through here rather than trusting the framework to call back exactly once.
    private func finish(_ result: Result<PasskeyAssertion, Error>) {
        guard let continuation else { return }
        self.continuation = nil
        controller = nil
        selfRetain = nil
        continuation.resume(with: result)
    }

    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor { anchor }

    func authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithAuthorization authorization: ASAuthorization
    ) {
        guard
            let assertion = authorization.credential
                as? ASAuthorizationPlatformPublicKeyCredentialAssertion
        else {
            finish(.failure(GrooAuthError.invalidResponse(
                "passkey sign-in returned \(type(of: authorization.credential)), not a platform assertion"
            )))
            return
        }
        guard let signature = assertion.signature else {
            finish(.failure(GrooAuthError.invalidResponse("passkey assertion carried no signature")))
            return
        }
        guard let authenticatorData = assertion.rawAuthenticatorData else {
            finish(.failure(GrooAuthError.invalidResponse("passkey assertion carried no authenticator data")))
            return
        }
        finish(.success(PasskeyAssertion(
            credentialID: PKCE.base64URL(assertion.credentialID),
            clientDataJSON: PKCE.base64URL(assertion.rawClientDataJSON),
            authenticatorData: PKCE.base64URL(authenticatorData),
            signature: PKCE.base64URL(signature),
            userHandle: assertion.userID.map { PKCE.base64URL($0) }
        )))
    }

    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        let code = (error as? ASAuthorizationError)?.code
        // `.canceled` is the sheet being dismissed. `.notHandled`/`.failed` are what
        // this device answers when it holds no passkey for the relying party — which
        // is not a failure either: it is the ordinary state of a device that has
        // never enrolled one, and the caller offers the password flow instead.
        switch code {
        case .canceled:
            finish(.failure(GrooAuthError.userCancelled))
        case .notHandled, .failed:
            finish(.failure(GrooAuthError.passkeyUnavailable))
        default:
            GrooAuthLog.web.error("passkey assertion failed: \(error.localizedDescription, privacy: .public)")
            finish(.failure(GrooAuthError.transport(error.localizedDescription)))
        }
    }
}

#endif
