import XCTest
import CryptoKit
@testable import GrooAuth

final class IDTokenTests: XCTestCase {
    func makeJWT(claims: [String: Any], key: P256.Signing.PrivateKey, kid: String) throws -> (String, JWKS) {
        func b64(_ d: Data) -> String { PKCE.base64URL(d) }
        let header = try JSONSerialization.data(withJSONObject: ["alg": "ES256", "kid": kid, "typ": "JWT"])
        let payload = try JSONSerialization.data(withJSONObject: claims)
        let signingInput = b64(header) + "." + b64(payload)
        let sig = try key.signature(for: Data(signingInput.utf8))
        let jwt = signingInput + "." + b64(sig.rawRepresentation)  // JOSE ES256 = raw r||s
        // NOTE: P256.Signing.PublicKey.rawRepresentation on this toolchain is 64 bytes (X||Y,
        // no 0x04 prefix). Use x963Representation (65 bytes: 0x04 || X(32) || Y(32)) so the
        // 1..<33 / 33..<65 slices below actually land on X and Y.
        let pub = key.publicKey.x963Representation // 65 bytes: 0x04 || X(32) || Y(32)
        let x = pub.subdata(in: 1..<33), y = pub.subdata(in: 33..<65)
        let jwks = JWKS(keys: [JWK(kty: "EC", crv: "P-256", x: b64(x), y: b64(y), kid: kid, alg: "ES256")])
        return (jwt, jwks)
    }

    func testValidTokenPasses() throws {
        let key = P256.Signing.PrivateKey()
        let exp = Date().addingTimeInterval(600).timeIntervalSince1970
        let (jwt, jwks) = try makeJWT(
            claims: ["sub": "u1", "aud": "cid", "iss": "https://accounts.groo.dev", "exp": exp, "nonce": "n1", "email": "a@b.c"],
            key: key, kid: "k1")
        let claims = try verifyIDToken(jwt, jwks: jwks, issuer: "https://accounts.groo.dev", clientId: "cid", nonce: "n1", now: Date())
        XCTAssertEqual(claims.sub, "u1")
        XCTAssertEqual(claims.email, "a@b.c")
    }

    func testWrongNonceThrows() throws {
        let key = P256.Signing.PrivateKey()
        let exp = Date().addingTimeInterval(600).timeIntervalSince1970
        let (jwt, jwks) = try makeJWT(
            claims: ["sub": "u1", "aud": "cid", "iss": "https://accounts.groo.dev", "exp": exp, "nonce": "n1"],
            key: key, kid: "k1")
        XCTAssertThrowsError(try verifyIDToken(jwt, jwks: jwks, issuer: "https://accounts.groo.dev", clientId: "cid", nonce: "different", now: Date())) { error in
            guard case GrooAuthError.idTokenInvalid = error else {
                return XCTFail("expected idTokenInvalid, got \(error)")
            }
        }
    }

    func testWrongAudThrows() throws {
        let key = P256.Signing.PrivateKey()
        let exp = Date().addingTimeInterval(600).timeIntervalSince1970
        let (jwt, jwks) = try makeJWT(
            claims: ["sub": "u1", "aud": "cid", "iss": "https://accounts.groo.dev", "exp": exp, "nonce": "n1"],
            key: key, kid: "k1")
        XCTAssertThrowsError(try verifyIDToken(jwt, jwks: jwks, issuer: "https://accounts.groo.dev", clientId: "other-client", nonce: "n1", now: Date())) { error in
            guard case GrooAuthError.idTokenInvalid = error else {
                return XCTFail("expected idTokenInvalid, got \(error)")
            }
        }
    }

    func testExpiredThrows() throws {
        let key = P256.Signing.PrivateKey()
        let exp = Date().addingTimeInterval(-600).timeIntervalSince1970
        let (jwt, jwks) = try makeJWT(
            claims: ["sub": "u1", "aud": "cid", "iss": "https://accounts.groo.dev", "exp": exp, "nonce": "n1"],
            key: key, kid: "k1")
        XCTAssertThrowsError(try verifyIDToken(jwt, jwks: jwks, issuer: "https://accounts.groo.dev", clientId: "cid", nonce: "n1", now: Date())) { error in
            guard case GrooAuthError.idTokenInvalid = error else {
                return XCTFail("expected idTokenInvalid, got \(error)")
            }
        }
    }

    func testTamperedSigThrows() throws {
        let key = P256.Signing.PrivateKey()
        let exp = Date().addingTimeInterval(600).timeIntervalSince1970
        let (jwt, jwks) = try makeJWT(
            claims: ["sub": "u1", "aud": "cid", "iss": "https://accounts.groo.dev", "exp": exp, "nonce": "n1"],
            key: key, kid: "k1")
        let parts = jwt.split(separator: ".")
        XCTAssertEqual(parts.count, 3)
        // Decode the signature to raw bytes, flip a bit in the middle of it (so the
        // mutation can't land on a base64 padding bit that happens to be a no-op),
        // and re-encode. This guarantees the signature bytes actually change.
        guard var sigBytes = base64URLDecode(String(parts[2])) else {
            return XCTFail("failed to decode signature under test")
        }
        sigBytes[sigBytes.count / 2] ^= 0xFF
        let tamperedSig = PKCE.base64URL(sigBytes)
        let tampered = "\(parts[0]).\(parts[1]).\(tamperedSig)"
        XCTAssertThrowsError(try verifyIDToken(tampered, jwks: jwks, issuer: "https://accounts.groo.dev", clientId: "cid", nonce: "n1", now: Date())) { error in
            guard case GrooAuthError.idTokenInvalid = error else {
                return XCTFail("expected idTokenInvalid, got \(error)")
            }
        }
    }

    func testWrongIssuerThrows() throws {
        let key = P256.Signing.PrivateKey()
        let exp = Date().addingTimeInterval(600).timeIntervalSince1970
        let (jwt, jwks) = try makeJWT(
            claims: ["sub": "u1", "aud": "cid", "iss": "https://accounts.groo.dev", "exp": exp, "nonce": "n1"],
            key: key, kid: "k1")
        XCTAssertThrowsError(try verifyIDToken(jwt, jwks: jwks, issuer: "https://other.example.com", clientId: "cid", nonce: "n1", now: Date())) { error in
            guard case GrooAuthError.idTokenInvalid = error else {
                return XCTFail("expected idTokenInvalid, got \(error)")
            }
        }
    }

    func testUnknownKidThrows() throws {
        let key = P256.Signing.PrivateKey()
        let exp = Date().addingTimeInterval(600).timeIntervalSince1970
        let (jwt, jwks) = try makeJWT(
            claims: ["sub": "u1", "aud": "cid", "iss": "https://accounts.groo.dev", "exp": exp, "nonce": "n1"],
            key: key, kid: "k1")
        // Swap in a JWKS whose only key has a different kid than the JWT header,
        // so lookup-by-kid fails even though the JWT itself is well-formed.
        let mismatched = JWKS(keys: jwks.keys.map { JWK(kty: $0.kty, crv: $0.crv, x: $0.x, y: $0.y, kid: "some-other-kid", alg: $0.alg) })
        XCTAssertThrowsError(try verifyIDToken(jwt, jwks: mismatched, issuer: "https://accounts.groo.dev", clientId: "cid", nonce: "n1", now: Date())) { error in
            guard case GrooAuthError.idTokenInvalid = error else {
                return XCTFail("expected idTokenInvalid, got \(error)")
            }
        }
    }

    func testMalformedJWTThrows() throws {
        XCTAssertThrowsError(try verifyIDToken("not.a.jwt.four.parts", jwks: JWKS(keys: []), issuer: "https://accounts.groo.dev", clientId: "cid", nonce: "n1", now: Date())) { error in
            guard case GrooAuthError.idTokenInvalid = error else {
                return XCTFail("expected idTokenInvalid, got \(error)")
            }
        }
    }
}
