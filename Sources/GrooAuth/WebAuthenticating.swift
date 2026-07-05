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
        GrooAuthLog.web.notice("ASWebAuthenticator.authenticate invoked")
        return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<URL, Error>) in
            Task { @MainActor in
                GrooAuthLog.web.notice("main-actor task started, building session")
                let provider = PresentationContextProvider(anchor: anchor)
                let session = ASWebAuthenticationSession(url: url, callbackURLScheme: callbackScheme) { callbackURL, error in
                    // Keep the provider (and, transitively, the session) alive until this fires.
                    withExtendedLifetime(provider) {
                        if let error {
                            let nsError = error as NSError
                            let isCanceledLogin = (error as? ASWebAuthenticationSessionError)?.code == .canceledLogin
                            GrooAuthLog.web.error("ASWebAuth completion ERROR domain=\(nsError.domain, privacy: .public) code=\(nsError.code, privacy: .public) desc=\(error.localizedDescription, privacy: .public) canceledLogin=\(isCanceledLogin, privacy: .public)")
                            if isCanceledLogin {
                                continuation.resume(throwing: GrooAuthError.userCancelled)
                            } else {
                                continuation.resume(throwing: GrooAuthError.transport(error.localizedDescription))
                            }
                            return
                        }
                        guard let callbackURL else {
                            GrooAuthLog.web.error("ASWebAuth completion returned neither a callback URL nor an error")
                            continuation.resume(throwing: GrooAuthError.invalidResponse("ASWebAuthenticationSession returned no callback URL"))
                            return
                        }
                        // Non-secret diagnostics only: presence of code/error and the
                        // (non-secret) state value. The `code` value itself is never logged.
                        let items = URLComponents(url: callbackURL, resolvingAgainstBaseURL: false)?.queryItems ?? []
                        let hasCode = items.contains { $0.name == "code" && $0.value != nil }
                        let hasError = items.contains { $0.name == "error" && $0.value != nil }
                        let stateValue = items.first(where: { $0.name == "state" })?.value ?? "nil"
                        GrooAuthLog.web.notice("ASWebAuth completion URL scheme=\(callbackURL.scheme ?? "nil", privacy: .public) host=\(callbackURL.host ?? "nil", privacy: .public) hasCode=\(hasCode, privacy: .public) hasError=\(hasError, privacy: .public) state=\(stateValue, privacy: .public)")
                        continuation.resume(returning: callbackURL)
                    }
                }
                session.prefersEphemeralWebBrowserSession = false
                session.presentationContextProvider = provider
                provider.session = session
                GrooAuthLog.web.notice("presenting ASWebAuthenticationSession callbackScheme=\(callbackScheme, privacy: .public) authHost=\(url.host ?? "nil", privacy: .public) ephemeral=false")
                session.start()
            }
        }
    }
}

#endif
