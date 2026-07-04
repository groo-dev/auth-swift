import XCTest
@testable import GrooAuth

final class GrooAuthErrorTests: XCTestCase {
    func testDecodesProtocolErrorVerbatim() throws {
        let json = #"{"error":"invalid_grant","error_description":"refresh token expired"}"#
        let err = try OAuthProtocolError.decode(Data(json.utf8))
        XCTAssertEqual(err.error, "invalid_grant")
        XCTAssertEqual(err.errorDescription, "refresh token expired")
    }

    func testNonProtocolBodyThrows() {
        XCTAssertThrowsError(try OAuthProtocolError.decode(Data("not json".utf8)))
    }
}
