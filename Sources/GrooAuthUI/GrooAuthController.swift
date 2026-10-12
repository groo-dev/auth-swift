import Foundation
import Observation
import AuthenticationServices
import GrooAuth

/// The auth state, as SwiftUI can observe it.
///
/// `user` is set whenever the SDK knows who the person is: while signed in AND
/// while `requiresReauth` (tokens gone, identity kept). It does NOT mean "signed
/// in". Gate on `isSignedIn`, never on `user != nil`.
///
/// `GrooAuthSession` is an actor: correct for a token store that several tasks
/// touch, and unusable directly from a view body. This republishes its state on
/// the main actor.
///
/// It exists because both of our apps had already written it. `bt/space` has an
/// `AuthService`, `gr/ios` has an `AuthService`, and they differ only in
/// accidents. Every further adopter would have written a third.
@MainActor
@Observable
public final class GrooAuthController {
    /// The person the SDK knows: signed in, or kept for a re-sign-in
    /// (`requiresReauth`). Not "the signed-in person" any more: gate access on
    /// `isSignedIn`, never on `user != nil`.
    public private(set) var user: GrooUser?
    public private(set) var isSignedIn = false

    /// True until the token store has been read once.
    ///
    /// The distinction this exists for is "signed out" versus "not known yet".
    /// An app that cannot tell them apart shows its sign-in screen for a frame on
    /// every launch, to someone who is already signed in — the single most
    /// noticeable bug in a native auth flow, and the reason this is not simply
    /// `isSignedIn == false`.
    public private(set) var isLoading = true

    /// True when the issuer refused this person's session but the SDK still knows
    /// who they are (`GrooAuthState.reauthRequired`). `user` stays set; `isSignedIn`
    /// is false. An app that only looks at `isSignedIn` shows its sign-in screen,
    /// as before; an offline-first app keeps the person's data and asks them to
    /// sign in again.
    public private(set) var requiresReauth = false

    /// The underlying session, deliberately public.
    ///
    /// The views in this library are opinionated. That is only acceptable if an
    /// app that wants its own can build them over the same logic rather than
    /// reimplementing the protocol.
    public let session: GrooAuthSession

    /// Holds the observation task so it is cancelled when this controller goes.
    ///
    /// A `@MainActor` class's `deinit` is nonisolated and cannot touch
    /// main-actor state, so the task cannot simply be a property cancelled from
    /// there — the compiler refuses it. Parking it in a small object whose OWN
    /// deinit does the cancelling needs no isolation at all, and releases with
    /// the controller. Without this, every controller leaks its task, which an
    /// app would never notice and a library should not do.
    private final class Cancellation: @unchecked Sendable {
        var task: Task<Void, Never>?
        deinit { task?.cancel() }
    }
    private nonisolated let cancellation = Cancellation()

    public init(session: GrooAuthSession) {
        self.session = session
        // Started here rather than in a view's .task: a controller that only
        // learns its state once something renders is a controller whose state
        // depends on the view tree.
        cancellation.task = Task { [weak self] in
            for await state in await session.stateStream {
                guard let self else { return }
                self.apply(state)
            }
        }
    }

    private func apply(_ state: GrooAuthState) {
        isLoading = false
        switch state {
        case .signedOut:
            isSignedIn = false
            requiresReauth = false
            user = nil
        case .signedIn(let signedIn):
            isSignedIn = true
            requiresReauth = false
            user = signedIn
        case .reauthRequired(let kept):
            isSignedIn = false
            requiresReauth = true
            user = kept
        }
    }

    /// Presents the hosted sign-in.
    ///
    /// Throws rather than swallowing: a sign-in that fails silently leaves someone
    /// tapping a button that appears to do nothing. Callers should treat
    /// `GrooAuthError.userCancelled` as ordinary — that is a closed sheet, not a
    /// failure to report.
    @discardableResult
    /// `prompt: .login` forces the issuer to re-authenticate instead of answering
    /// the browser cookie it still holds. A sign-in SCREEN should pass it: that
    /// screen only appears when this device is signed out, and reusing whoever the
    /// browser last saw is what made "Sign Out" then "Sign In" return the same
    /// account with no prompt at all.
    public func signIn(
        presentationAnchor: ASPresentationAnchor,
        prompt: GrooAuthPrompt? = nil
    ) async throws -> GrooUser {
        try await session.signIn(presentationAnchor: presentationAnchor, prompt: prompt)
    }

    /// Presents the platform passkey sheet — no browser at any point.
    ///
    /// Throws `.passkeyUnavailable` when this device holds no passkey for the
    /// issuer, and `.interactionRequired` when the issuer needs to show a screen
    /// this app has none of. Both mean "fall back to `signIn`", and neither is a
    /// failure to report to the person.
    @discardableResult
    public func signInWithPasskey(presentationAnchor: ASPresentationAnchor) async throws -> GrooUser {
        try await session.signInWithPasskey(presentationAnchor: presentationAnchor)
    }

    /// Local tokens are cleared either way; the result says whether the issuer was
    /// also reached. A network failure must still leave this device signed out.
    ///
    /// This leaves the issuer's BROWSER session alone — no sheet, nothing to
    /// dismiss. Account switching is handled by `signIn(prompt: .login)` instead;
    /// see `GrooAuthSession.signOut` for why that is the right place for it.
    @discardableResult
    public func signOut() async -> SignOutResult {
        await session.signOut()
    }

    /// `signOut`, plus ending the session in the system browser — at the cost of a
    /// system consent sheet. Not the ordinary path; see `GrooAuthSession`.
    @discardableResult
    public func signOutEverywhere(presentationAnchor: ASPresentationAnchor) async -> SignOutResult {
        await session.signOutEverywhere(presentationAnchor: presentationAnchor)
    }

    /// Awaits the first published state. For tests, which must not race the
    /// observation task; an app observes `isLoading` instead.
    func waitForFirstState() async {
        while isLoading {
            await Task.yield()
        }
    }
}
