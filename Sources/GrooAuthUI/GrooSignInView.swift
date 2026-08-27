import SwiftUI
import AuthenticationServices
import GrooAuth

#if canImport(UIKit)
import UIKit
#endif

/// The whole signed-out state: branding, one button, and an error when there is
/// one.
///
/// There is no email or password field, and there will not be. Credentials are
/// entered at the issuer, in a web session this app cannot read — that is what
/// the authorization-code flow is for, and a native form that posted a password
/// would throw it away.
///
/// Branding is the only per-app part, so it is the only thing this takes.
public struct GrooSignInView: View {
    private let appName: String
    private let tagline: String?
    private let icon: Image?
    private let controller: GrooAuthController

    @Environment(\.grooAuthTheme) private var theme
    @State private var isSigningIn = false
    @State private var errorMessage: String?

    /// Hides the passkey button once this device has told us it has none.
    ///
    /// There is no way to ASK — the platform only answers by running the ceremony
    /// — so the button is offered until an attempt says otherwise, and then it
    /// stops being offered. Leaving it up would invite the same dead end twice.
    @State private var passkeyOffered = true

    public init(
        appName: String,
        tagline: String? = nil,
        icon: Image? = nil,
        controller: GrooAuthController
    ) {
        self.appName = appName
        self.tagline = tagline
        self.icon = icon
        self.controller = controller
    }

    public var body: some View {
        VStack(spacing: 24) {
            Spacer()

            if let icon {
                icon
                    .font(.system(size: 56))
                    .foregroundStyle(theme.accent)
                    .accessibilityHidden(true)
            }

            VStack(spacing: 8) {
                Text(appName)
                    .font(theme.titleFont)
                    .foregroundStyle(theme.ink)
                if let tagline {
                    Text(tagline)
                        .font(theme.bodyFont)
                        .foregroundStyle(theme.muted)
                        .multilineTextAlignment(.center)
                }
            }

            Spacer()

            if let errorMessage {
                Text(errorMessage)
                    .font(.footnote)
                    .foregroundStyle(theme.danger)
                    .multilineTextAlignment(.center)
                    .accessibilityIdentifier("grooSignIn.error")
            }

            VStack(spacing: 12) {
                if passkeyOffered {
                    // First, as it is on the hosted page: for someone who has a
                    // passkey it is both the fastest and the strongest option, and
                    // putting it second teaches people to ignore it.
                    Button(action: signInWithPasskey) {
                        HStack(spacing: 8) {
                            Image(systemName: "person.badge.key.fill")
                            Text("Sign in with a passkey").fontWeight(.semibold)
                        }
                        .frame(maxWidth: .infinity, minHeight: 50)
                        .background(theme.accent, in: RoundedRectangle(cornerRadius: theme.cornerRadius))
                        .foregroundStyle(theme.onAccent)
                    }
                    .disabled(isSigningIn)
                    .accessibilityIdentifier("grooSignIn.passkeyButton")
                }

                Button(action: signIn) {
                    HStack {
                        if isSigningIn { ProgressView().controlSize(.small) }
                        Text(isSigningIn ? "Signing in…" : "Sign in with Groo")
                            .fontWeight(.semibold)
                    }
                    .frame(maxWidth: .infinity, minHeight: 50)
                    .background(
                        passkeyOffered ? AnyShapeStyle(theme.surface) : AnyShapeStyle(theme.accent),
                        in: RoundedRectangle(cornerRadius: theme.cornerRadius)
                    )
                    .foregroundStyle(passkeyOffered ? theme.ink : theme.onAccent)
                }
                .disabled(isSigningIn)
                .accessibilityIdentifier("grooSignIn.button")
            }
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(theme.canvas)
    }

    /// The native ceremony, with the hosted flow as the answer to everything it
    /// cannot finish itself.
    private func signInWithPasskey() {
        isSigningIn = true
        errorMessage = nil
        Task {
            do {
                try await controller.signInWithPasskey(presentationAnchor: Self.presentationAnchor())
                isSigningIn = false
            } catch GrooAuthError.userCancelled {
                isSigningIn = false
            } catch GrooAuthError.passkeyUnavailable {
                // Not an error to report. This device simply has no passkey for
                // the issuer, which is the ordinary state of a device that has
                // never enrolled one. Stop offering it and leave the person on
                // the button that will work.
                passkeyOffered = false
                isSigningIn = false
            } catch GrooAuthError.interactionRequired {
                // The person proved their passkey and the issuer still needs a
                // screen — consent, most often, and only ever once. Carrying
                // straight on into the hosted flow is the only way forward, so
                // it happens without making them tap again.
                signIn()
            } catch {
                errorMessage = Self.message(for: error)
                isSigningIn = false
            }
        }
    }

    private func signIn() {
        isSigningIn = true
        errorMessage = nil
        Task {
            do {
                try await controller.signIn(presentationAnchor: Self.presentationAnchor())
            } catch GrooAuthError.userCancelled {
                // A closed sheet is not a failure. Reporting it teaches people to
                // ignore this label, which is where a real error then goes unread.
            } catch {
                // Surfaced, never swallowed: a sign-in that fails silently leaves
                // someone tapping a button that appears to do nothing.
                errorMessage = Self.message(for: error)
            }
            isSigningIn = false
        }
    }

    /// `GrooAuthError` already names the specific failure, so it is shown rather
    /// than replaced with a friendlier sentence that would hide which step broke.
    static func message(for error: Error) -> String {
        guard let authError = error as? GrooAuthError else { return String(describing: error) }
        switch authError {
        case .signedOut:
            return "You are signed out. Please try again."
        case .stateMismatch:
            return "That sign-in could not be verified. Please try again."
        case .userCancelled:
            return ""
        case .transport(let detail),
             .invalidResponse(let detail),
             .idTokenInvalid(let detail):
            return detail
        case .protocolError(let oauth), .interactionRequired(let oauth):
            return oauth.errorDescription ?? oauth.error
        case .insufficientScope(let scope):
            return "This app was not granted permission to \(scope)."
        case .passkeyUnavailable:
            // Never rendered — the caller hides the button instead — but the
            // switch must stay exhaustive, and a sentence is better than a crash
            // if a future caller does show it.
            return "No passkey is available on this device."
        }
    }

    #if canImport(UIKit)
    /// The foreground key window, to anchor the OAuth web session.
    @MainActor
    static func presentationAnchor() -> ASPresentationAnchor {
        let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
        let scene = scenes.first(where: { $0.activationState == .foregroundActive }) ?? scenes.first
        if let window = scene?.windows.first(where: { $0.isKeyWindow }) ?? scene?.windows.first {
            return window
        }
        // Unreachable while this view is on screen, but ASPresentationAnchor is
        // non-optional, so return a window rather than force-unwrapping.
        return UIWindow()
    }
    #else
    @MainActor
    static func presentationAnchor() -> ASPresentationAnchor { ASPresentationAnchor() }
    #endif
}
