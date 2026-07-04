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
