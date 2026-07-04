import XCTest
@testable import GrooAuth

final class DiscoveryTests: XCTestCase {
    func testParsesEndpoints() async throws {
        let body = #"{"issuer":"https://accounts.groo.dev","authorization_endpoint":"https://accounts.groo.dev/v1/oauth/authorize","token_endpoint":"https://accounts.groo.dev/v1/oauth/token","jwks_uri":"https://accounts.groo.dev/.well-known/jwks.json","revocation_endpoint":"https://accounts.groo.dev/v1/oauth/revoke","userinfo_endpoint":"https://accounts.groo.dev/v1/oauth/userinfo"}"#
        let t = MockTransport(routes: ["https://accounts.groo.dev/.well-known/openid-configuration": (200, body)])
        let doc = try await fetchDiscovery(issuer: URL(string: "https://accounts.groo.dev")!, transport: t)
        XCTAssertEqual(doc.tokenEndpoint.absoluteString, "https://accounts.groo.dev/v1/oauth/token")
        XCTAssertEqual(doc.jwksURI.absoluteString, "https://accounts.groo.dev/.well-known/jwks.json")
    }

    func testMissingJwksThrows() async {
        let body = #"{"issuer":"x","authorization_endpoint":"https://a/x","token_endpoint":"https://a/t"}"#
        let t = MockTransport(routes: ["https://accounts.groo.dev/.well-known/openid-configuration": (200, body)])
        do { _ = try await fetchDiscovery(issuer: URL(string: "https://accounts.groo.dev")!, transport: t); XCTFail() }
        catch { /* expected .invalidResponse */ }
    }
}
