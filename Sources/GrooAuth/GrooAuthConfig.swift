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
    case revokedAndCleared
    case clearedButRevokeFailed(reason: String)
}
