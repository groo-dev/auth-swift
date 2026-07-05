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
        }
    }
}
