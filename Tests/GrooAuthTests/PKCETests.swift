import XCTest
import CryptoKit
@testable import GrooAuth

final class PKCETests: XCTestCase {
    func testChallengeIsBase64URLSHA256OfVerifier() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        // RFC 7636 Appendix B expected challenge for this verifier
        XCTAssertEqual(PKCE.challenge(for: verifier), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
    }

    func testVerifierIsURLSafeAndLongEnough() {
        let v = PKCE.generateVerifier()
        XCTAssertGreaterThanOrEqual(v.count, 43)
        XCTAssertLessThanOrEqual(v.count, 128)
        XCTAssertNil(v.rangeOfCharacter(from: CharacterSet(charactersIn: "+/=").union(.whitespaces)))
    }

    func testRandomURLSafeIsUnique() {
        XCTAssertNotEqual(PKCE.randomURLSafe(byteCount: 32), PKCE.randomURLSafe(byteCount: 32))
    }
}
