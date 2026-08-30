import Foundation

public struct GrooAuthConfig: Sendable {
    public let issuer: URL
    public let clientId: String
    public let redirectURI: String
    public let scopes: [String]
    public let keychainService: String
    public let keychainAccessGroup: String?

    public init(issuer: URL, clientId: String, redirectURI: String, scopes: [String],
                keychainService: String, keychainAccessGroup: String? = nil) {
        self.issuer = issuer; self.clientId = clientId; self.redirectURI = redirectURI
        self.scopes = scopes; self.keychainService = keychainService
        self.keychainAccessGroup = keychainAccessGroup
    }
    var scopeString: String { scopes.joined(separator: " ") }
    var callbackScheme: String { String(redirectURI.prefix(while: { $0 != ":" })) }
}

public struct GrooUser: Sendable, Equatable, Codable {
    public let sub: String
    public let email: String?
    public let name: String?
}

public enum GrooAuthState: Sendable, Equatable {
    case signedOut
    case signedIn(GrooUser)
}

public enum SignOutResult: Sendable, Equatable {
    /// Tokens revoked, local storage cleared, and the issuer's browser session
    /// ended. The only outcome after which the next `signIn` is guaranteed to
    /// ask who you are.
    case revokedAndCleared
    case clearedButRevokeFailed(reason: String)
    /// Tokens were revoked and cleared, but the ISSUER'S BROWSER SESSION IS STILL
    /// LIVE — so the next `signIn` may complete with no prompt at all, as the
    /// same person, from the cookie the system browser still holds.
    ///
    /// This is a distinct case rather than a `clearedButRevokeFailed` reason
    /// because the consequence is different in kind. A failed revoke leaves a
    /// token alive somewhere the person cannot see; this leaves *the account*
    /// reachable on this device, one tap away, by whoever holds the phone next.
    /// On a shared device that is the more serious of the two, and a caller that
    /// wants to warn about it needs to be able to tell them apart.
    case clearedButBrowserSessionLive(reason: String)
}

/// OIDC Core 3.1.2.1 `prompt`, for the values this SDK sends.
///
/// Only `login` is offered because it is the only value the Groo issuer
/// implements — it refuses the others rather than ignoring them, so a case here
/// that the server would reject would be a case that always fails.
///
/// `select_account` is the value that would give a "Continue as X / use a
/// different account" picker, the way Google's chooser works. It needs a screen
/// the issuer does not have yet.
public enum GrooAuthPrompt: String, Sendable, Equatable {
    /// Re-authenticate, whatever the browser still remembers. Send this from a
    /// sign-in screen: reaching that screen means this device is signed out, and
    /// silently reusing a stale browser identity there is the bug this exists for.
    case login
}
