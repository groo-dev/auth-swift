import Foundation
#if canImport(AuthenticationServices)
import AuthenticationServices
#endif
#if canImport(AppKit)
import AppKit
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
        return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<URL, Error>) in
            Task { @MainActor in
                let provider = PresentationContextProvider(anchor: anchor)
                // `@Sendable` is load-bearing. Defined inside this `Task { @MainActor in }`,
                // an un-annotated closure would inherit @MainActor isolation. On macOS,
                // `ASWebAuthenticationSession.start()` runs an internal `_startDryRun` that
                // invokes the completion handler SYNCHRONOUSLY on a background XPC queue
                // (com.apple.NSXPCConnection…SafariLaunchAgent), not on the main actor.
                // A @MainActor-isolated closure entered off-main trips Swift's executor
                // precondition (`swift_task_isCurrentExecutor` → `dispatch_assert_queue`),
                // which traps with EXC_BREAKPOINT and kills the app (macOS-only; iOS calls
                // back on the main actor). Marking the closure @Sendable makes it
                // nonisolated — resuming a continuation is thread-safe from any executor.
                let completion: @Sendable (URL?, (any Error)?) -> Void = { callbackURL, error in
                    // Keep the provider (and, transitively, the session) alive until this fires.
                    withExtendedLifetime(provider) {
                        if let error {
                            let isCanceledLogin = (error as? ASWebAuthenticationSessionError)?.code == .canceledLogin
                            if isCanceledLogin {
                                continuation.resume(throwing: GrooAuthError.userCancelled)
                            } else {
                                GrooAuthLog.web.error("ASWebAuthenticationSession failed: \(error.localizedDescription, privacy: .public)")
                                continuation.resume(throwing: GrooAuthError.transport(error.localizedDescription))
                            }
                            return
                        }
                        guard let callbackURL else {
                            GrooAuthLog.web.error("ASWebAuthenticationSession returned neither a callback URL nor an error")
                            continuation.resume(throwing: GrooAuthError.invalidResponse("ASWebAuthenticationSession returned no callback URL"))
                            return
                        }
                        continuation.resume(returning: callbackURL)
                    }
                }
                let session = ASWebAuthenticationSession(url: url, callbackURLScheme: callbackScheme, completionHandler: completion)
                session.prefersEphemeralWebBrowserSession = false
                session.presentationContextProvider = provider
                provider.session = session
                // If start() returns false the completion handler never fires, so
                // resume here rather than leaving the caller awaiting forever.
                if !session.start() {
                    GrooAuthLog.web.error("ASWebAuthenticationSession.start() returned false — could not present the sign-in browser")
                    continuation.resume(throwing: GrooAuthError.transport("Could not present the sign-in browser"))
                }
            }
        }
    }
}

#endif
