import Foundation

public struct DiscoveryDocument: Sendable {
    public let authorizationEndpoint: URL
    public let tokenEndpoint: URL
    public let jwksURI: URL
    public let revocationEndpoint: URL?
    public let userinfoEndpoint: URL?
}

struct JWK: Decodable, Sendable { let kty: String; let crv: String?; let x: String?; let y: String?; let kid: String?; let alg: String? }
struct JWKS: Decodable, Sendable { let keys: [JWK] }

func fetchDiscovery(issuer: URL, transport: HTTPTransporting) async throws -> DiscoveryDocument {
    let url = issuer.appendingPathComponent(".well-known/openid-configuration")
    let (data, resp) = try await transport.send(URLRequest(url: url))
    guard resp.statusCode == 200 else { throw GrooAuthError.invalidResponse("discovery HTTP \(resp.statusCode)") }
    struct Wire: Decodable {
        let authorization_endpoint: URL; let token_endpoint: URL; let jwks_uri: URL
        let revocation_endpoint: URL?; let userinfo_endpoint: URL?
    }
    let w: Wire
    do { w = try JSONDecoder().decode(Wire.self, from: data) }
    catch { throw GrooAuthError.invalidResponse("discovery doc missing/invalid field: \(error)") }
    return DiscoveryDocument(authorizationEndpoint: w.authorization_endpoint, tokenEndpoint: w.token_endpoint,
                             jwksURI: w.jwks_uri, revocationEndpoint: w.revocation_endpoint, userinfoEndpoint: w.userinfo_endpoint)
}
