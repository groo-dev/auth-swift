import Foundation
import GrooAuth
import Observation

/// The signed-in person's account, as the issuer holds it.
///
/// Richer than `GrooUser`, which carries only what an `id_token` puts in front
/// of an app at sign-in. This is fetched, and it can change while the app is
/// open — a name edited here, a password set on another device.
public struct GrooAccountProfile: Sendable, Equatable, Decodable {
    public let id: String
    public let email: String?
    public let phone: String?
    public let name: String?
    public let emailVerified: Bool
    public let phoneVerified: Bool
    /// Whether the account HAS a password, never anything about the password.
    /// A passkey-only account has none, and offering it "change password" is the
    /// lockout path rather than a feature.
    public let hasPassword: Bool
    public let totpEnabled: Bool
    public let lastLoginAt: String?
}

private struct ProfileEnvelope: Decodable {
    let user: GrooAccountProfile
}

/// Loads and edits the profile behind `GrooAccountView`.
///
/// Separate from `GrooAuthController` because it is a different kind of thing:
/// the controller mirrors a session that exists whether or not anyone is looking
/// at it, while this is fetched when a screen opens and is allowed to fail
/// without the person being signed out.
@MainActor
@Observable
public final class GrooAccountStore {
    public private(set) var profile: GrooAccountProfile?

    /// True only while the FIRST load is in flight. A refresh behind an already
    /// rendered profile must not replace it with a spinner — the content is still
    /// good, and blanking it makes an app feel like it lost the data.
    public private(set) var isLoading = false

    /// Surfaced, never swallowed. A screen that silently shows stale fields after
    /// a failed save is worse than one that says it could not save.
    public private(set) var error: String?

    public private(set) var isSaving = false

    private let session: GrooAuthSession

    public init(session: GrooAuthSession) {
        self.session = session
    }

    public func load() async {
        if profile == nil { isLoading = true }
        error = nil
        do {
            let data = try await session.accountRequest(path: "v1/account/profile")
            profile = try JSONDecoder().decode(ProfileEnvelope.self, from: data).user
        } catch {
            self.error = Self.message(for: error)
        }
        isLoading = false
    }

    /// Saves `name` and `phone`. An empty string clears the field; `nil` leaves it
    /// alone, which is what lets a screen send only what it edits.
    public func save(name: String?, phone: String?) async {
        isSaving = true
        error = nil
        var payload: [String: String] = [:]
        if let name { payload["name"] = name }
        if let phone { payload["phone"] = phone }
        do {
            let body = try JSONEncoder().encode(payload)
            let data = try await session.accountRequest(path: "v1/account/profile", method: "PATCH", body: body)
            profile = try JSONDecoder().decode(ProfileEnvelope.self, from: data).user
        } catch {
            self.error = Self.message(for: error)
        }
        isSaving = false
    }

    /// The issuer's own words wherever it has any: its refusals name the field or
    /// the scope, and nothing this SDK could substitute would be more useful.
    static func message(for error: Error) -> String {
        guard let authError = error as? GrooAuthError else { return String(describing: error) }
        switch authError {
        case .insufficientScope(let scope):
            return "This app was not granted permission to \(scope). Sign out and in again to approve it."
        case .signedOut:
            return "You are signed out."
        case .protocolError(let oauth), .interactionRequired(let oauth):
            return oauth.errorDescription ?? oauth.error
        case .transport(let detail), .invalidResponse(let detail), .idTokenInvalid(let detail):
            return detail
        case .stateMismatch:
            return "That request could not be verified. Please try again."
        case .userCancelled, .passkeyUnavailable:
            return ""
        }
    }
}
