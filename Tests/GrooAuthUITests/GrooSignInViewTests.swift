import XCTest
@testable import GrooAuth
@testable import GrooAuthUI

/// The view is chrome; its one piece of real logic is turning an error into
/// something worth reading. That is what these pin.
final class GrooSignInViewMessageTests: XCTestCase {
    func testShowsTheDetailAnErrorAlreadyCarries() {
        // GrooAuthError names the step that broke. Replacing that with a
        // friendlier sentence would hide which one.
        XCTAssertEqual(
            GrooSignInView.message(for: GrooAuthError.transport("keychain save-delete -34018")),
            "keychain save-delete -34018"
        )
        XCTAssertEqual(
            GrooSignInView.message(for: GrooAuthError.idTokenInvalid("aud mismatch")),
            "aud mismatch"
        )
    }

    func testPrefersTheOAuthDescriptionOverItsCode() {
        let err = GrooAuthError.protocolError(
            OAuthProtocolError(error: "invalid_request", errorDescription: "code_challenge is required")
        )
        XCTAssertEqual(GrooSignInView.message(for: err), "code_challenge is required")
    }

    func testFallsBackToTheOAuthCodeWhenThereIsNoDescription() {
        let err = GrooAuthError.protocolError(OAuthProtocolError(error: "access_denied", errorDescription: nil))
        XCTAssertEqual(GrooSignInView.message(for: err), "access_denied")
    }

    func testRewritesTheTwoErrorsWhoseRawFormMeansNothingToAPerson() {
        XCTAssertEqual(GrooSignInView.message(for: GrooAuthError.signedOut), "You are signed out. Please try again.")
        XCTAssertEqual(
            GrooSignInView.message(for: GrooAuthError.stateMismatch),
            "That sign-in could not be verified. Please try again."
        )
    }

    func testANonAuthErrorStillProducesSomething() {
        struct Odd: Error {}
        XCTAssertFalse(GrooSignInView.message(for: Odd()).isEmpty)
    }
}
