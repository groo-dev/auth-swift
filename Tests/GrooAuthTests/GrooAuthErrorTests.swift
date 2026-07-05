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

    // MARK: - LocalizedError

    func testProtocolErrorDescriptionSurfacesServerValuesVerbatim() {
        let error = GrooAuthError.protocolError(
            OAuthProtocolError(error: "invalid_grant", errorDescription: "refresh token expired")
        )
        let description = error.errorDescription
        XCTAssertNotNil(description)
        XCTAssertTrue(description!.contains("invalid_grant"))
        XCTAssertTrue(description!.contains("refresh token expired"))
    }

    func testStateMismatchHasNonNilDescription() {
        XCTAssertNotNil(GrooAuthError.stateMismatch.errorDescription)
    }

    func testSignedOutHasNonNilDescription() {
        XCTAssertNotNil(GrooAuthError.signedOut.errorDescription)
    }

    func testUserCancelledHasNonNilDescription() {
        XCTAssertNotNil(GrooAuthError.userCancelled.errorDescription)
    }

    func testInvalidResponseIncludesMessage() {
        let description = GrooAuthError.invalidResponse("missing field foo").errorDescription
        XCTAssertNotNil(description)
        XCTAssertTrue(description!.contains("missing field foo"))
    }

    func testIdTokenInvalidIncludesMessage() {
        let description = GrooAuthError.idTokenInvalid("nonce mismatch").errorDescription
        XCTAssertNotNil(description)
        XCTAssertTrue(description!.contains("nonce mismatch"))
    }

    func testTransportIncludesMessage() {
        let description = GrooAuthError.transport("connection lost").errorDescription
        XCTAssertNotNil(description)
        XCTAssertTrue(description!.contains("connection lost"))
    }

    // Sanity check that `localizedDescription` (what call sites like the macOS
    // app actually read) picks up our `errorDescription` via `LocalizedError`,
    // rather than falling back to the generic system string.
    func testLocalizedDescriptionUsesErrorDescription() {
        let error = GrooAuthError.protocolError(
            OAuthProtocolError(error: "invalid_grant", errorDescription: "refresh token expired")
        )
        XCTAssertEqual(error.localizedDescription, error.errorDescription)
    }
}
