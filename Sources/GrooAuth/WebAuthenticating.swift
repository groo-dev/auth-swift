import Foundation
#if canImport(AuthenticationServices)
import AuthenticationServices
#endif

/// Abstraction over `ASWebAuthenticationSession` so the session actor's sign-in flow
/// (`GrooAuthSession.signIn`) can be driven by a test double. `StubWebAuthenticator`
/// (test target) is the fake; `ASWebAuthenticator` below is the real thing.
public protocol WebAuthenticating: Sendable {
    func authenticate(url: URL, callbackScheme: String, anchor: ASPresentationAnchor) async throws -> URL
}

#if canImport(AuthenticationServices)

/// Delegate object satisfying `ASWebAuthenticationPresentationContextProviding`.
/// `ASWebAuthenticationSession` calls `presentationAnchor(for:)` on the main thread
/// while presenting; this just returns the anchor the caller supplied.
@MainActor
private final class PresentationContextProvider: NSObject, ASWebAuthenticationPresentationContextProviding {
    let anchor: ASPresentationAnchor
    /// Retains the session for the lifetime of this provider so it isn't
    /// deallocated (which cancels the in-flight auth) before completion fires.
    var session: ASWebAuthenticationSession?

    init(anchor: ASPresentationAnchor) {
        self.anchor = anchor
        super.init()
    }

    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        anchor
    }
}

/// Production `WebAuthenticating` backed by `ASWebAuthenticationSession`.
///
/// Not unit-tested — there's no browser/window server in CI to drive it — so it's
/// kept intentionally thin: build the session, present it, map cancellation to
/// `.userCancelled`, and resume with the callback URL. `GrooAuthSession.signIn` owns
/// all the OAuth/PKCE/state/nonce logic and is what the test suite exercises.
public final class ASWebAuthenticator: WebAuthenticating, @unchecked Sendable {
    public init() {}

    public func authenticate(url: URL, callbackScheme: String, anchor: ASPresentationAnchor) async throws -> URL {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<URL, Error>) in
            Task { @MainActor in
                let provider = PresentationContextProvider(anchor: anchor)
                let session = ASWebAuthenticationSession(url: url, callbackURLScheme: callbackScheme) { callbackURL, error in
                    // Keep the provider (and, transitively, the session) alive until this fires.
                    withExtendedLifetime(provider) {
                        if let error {
                            if let authError = error as? ASWebAuthenticationSessionError, authError.code == .canceledLogin {
                                continuation.resume(throwing: GrooAuthError.userCancelled)
                            } else {
                                continuation.resume(throwing: GrooAuthError.transport(error.localizedDescription))
                            }
                            return
                        }
                        guard let callbackURL else {
                            continuation.resume(throwing: GrooAuthError.invalidResponse("ASWebAuthenticationSession returned no callback URL"))
                            return
                        }
                        continuation.resume(returning: callbackURL)
                    }
                }
                session.prefersEphemeralWebBrowserSession = false
                session.presentationContextProvider = provider
                provider.session = session
                session.start()
            }
        }
    }
}

#endif
