import Foundation

public struct OAuthProtocolError: Error, Sendable, Equatable {
    public let error: String
    public let errorDescription: String?

    private struct Wire: Decodable { let error: String; let error_description: String? }

    public static func decode(_ data: Data) throws -> OAuthProtocolError {
        let w = try JSONDecoder().decode(Wire.self, from: data)
        return OAuthProtocolError(error: w.error, errorDescription: w.error_description)
    }
}

public enum GrooAuthError: Error, Sendable {
    case transport(String)
    case protocolError(OAuthProtocolError)
    case invalidResponse(String)   // shape/validation failure — names what was wrong
    case stateMismatch
    case idTokenInvalid(String)
    case signedOut
    case userCancelled

    /// This device holds no passkey for the issuer, or the platform declined to
    /// run the ceremony.
    ///
    /// Separate from `userCancelled` because the two want opposite handling: a
    /// cancellation means the person chose not to continue and the screen should
    /// wait, while this means the method is simply not available here and the
    /// password flow should be offered instead. Collapsing them into one case
    /// forced every caller to guess which had happened.
    case passkeyUnavailable

    /// The presented token does not carry a scope the request needs, and names
    /// which one.
    ///
    /// Separate from `protocolError` because the fix is specific and the app can
    /// state it: the person was never asked to grant this, so they have to sign
    /// in again and approve it. Nothing about retrying will help.
    case insufficientScope(String)

    /// The issuer refused to complete a native sign-in and needs the person to be
    /// shown something the app cannot render — a consent screen, a step-up
    /// challenge, or an explanation that they have no access.
    ///
    /// Carries the issuer's own reason. Callers fall back to the hosted flow,
    /// which is where those screens live.
    case interactionRequired(OAuthProtocolError)
}

/// `errorDescription` deliberately surfaces the real underlying details (server
/// error codes, validation messages) rather than hiding them behind a generic
/// string — callers (including this SDK's macOS app) show this text directly
/// to users, and the specifics matter for diagnosing sign-in problems.
extension GrooAuthError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .transport(let message):
            return "A network error occurred: \(message)"
        case .protocolError(let error):
            return "\(error.error): \(error.errorDescription ?? "")"
        case .invalidResponse(let message):
            return "Received an invalid response from the server: \(message)"
        case .stateMismatch:
            return "Authentication response failed a security check (state mismatch)."
        case .idTokenInvalid(let message):
            return "The identity token could not be verified: \(message)"
        case .signedOut:
            return "You are signed out."
        case .userCancelled:
            return "Sign-in was cancelled."
        case .passkeyUnavailable:
            return "No passkey is available on this device."
        case .insufficientScope(let scope):
            return "This app was not granted permission to \(scope). Sign in again to approve it."
        case .interactionRequired(let error):
            return "\(error.error): \(error.errorDescription ?? "")"
        }
    }
}
