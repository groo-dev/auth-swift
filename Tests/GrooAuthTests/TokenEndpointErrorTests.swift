import XCTest
@testable import GrooAuth

final class TokenEndpointErrorTests: XCTestCase {
    private let oauthBody = Data(#"{"error":"server_error","error_description":"db down"}"#.utf8)

    func testA4xxWithAnOAuthBodyIsTheIssuersVerdict() {
        guard case .protocolError(let e) = GrooAuthSession.tokenEndpointError(status: 400, body: Data(#"{"error":"invalid_grant"}"#.utf8)) else {
            return XCTFail("expected protocolError")
        }
        XCTAssertEqual(e.error, "invalid_grant")
        guard case .protocolError = GrooAuthSession.tokenEndpointError(status: 401, body: Data(#"{"error":"invalid_client"}"#.utf8)) else {
            return XCTFail("expected protocolError for 401 invalid_client")
        }
    }

    func testServerErrorsAreTransportEvenWithAnOAuthBody() {
        for status in [500, 502, 503, 504] {
            guard case .transport(let m) = GrooAuthSession.tokenEndpointError(status: status, body: oauthBody) else {
                return XCTFail("expected transport for \(status)")
            }
            XCTAssertTrue(m.contains("\(status)"), "message names the status: \(m)")
        }
    }

    func testTimeoutAndRateLimitAreTransport() {
        for status in [408, 429] {
            guard case .transport = GrooAuthSession.tokenEndpointError(status: status, body: oauthBody) else {
                return XCTFail("expected transport for \(status)")
            }
        }
    }

    func testA4xxWithoutAnOAuthBodyIsAnInvalidResponse() {
        guard case .invalidResponse(let m) = GrooAuthSession.tokenEndpointError(status: 404, body: Data("<html>nope</html>".utf8)) else {
            return XCTFail("expected invalidResponse")
        }
        XCTAssertTrue(m.contains("404"))
        XCTAssertTrue(m.contains("<html>nope</html>"))
    }

    func testARedirectIsAnInvalidResponse() {
        guard case .invalidResponse = GrooAuthSession.tokenEndpointError(status: 302, body: Data()) else {
            return XCTFail("expected invalidResponse for 302")
        }
    }

    func testTheBodySnippetIsBounded() {
        let long = Data(String(repeating: "x", count: 5_000).utf8)
        guard case .invalidResponse(let m) = GrooAuthSession.tokenEndpointError(status: 418, body: long) else {
            return XCTFail("expected invalidResponse")
        }
        XCTAssertLessThan(m.count, 400)
    }
}
