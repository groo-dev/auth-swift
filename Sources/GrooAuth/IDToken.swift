import Foundation
import CryptoKit

/// Decoded, verified claims from an OIDC `id_token`.
struct IDTokenClaims: Sendable, Equatable {
    let sub: String
    let email: String?
    let name: String?
    let iss: String
    let aud: String
    let exp: Date
    let nonce: String?
}

/// Base64url-decodes `s`, re-padding to a multiple of 4 and mapping the
/// URL-safe alphabet (`-`/`_`) back to standard base64 (`+`/`/`).
func base64URLDecode(_ s: String) -> Data? {
    var base64 = s
        .replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")
    let remainder = base64.count % 4
    if remainder > 0 {
        base64.append(String(repeating: "=", count: 4 - remainder))
    }
    return Data(base64Encoded: base64)
}

private struct IDTokenHeader: Decodable {
    let alg: String
    let kid: String?
}

private struct IDTokenPayload: Decodable {
    let sub: String
    let email: String?
    let name: String?
    let iss: String
    let aud: String
    let exp: Double
    let nonce: String?
}

/// Internal-only verification failure, distinguishing "no JWK matches this
/// token's `kid`" from every other rejection reason. `GrooAuthSession` needs
/// this distinction to decide whether re-fetching JWKS (self-heal after an
/// IdP key rotation) could possibly help — every other reason (bad signature,
/// wrong `aud`/`iss`, expired, bad nonce) is fatal regardless of which JWKS
/// keys are cached, so re-fetching wouldn't change the outcome and must not
/// be attempted. Not `GrooAuthError` itself: callers that just want "is this
/// verification failure fixable by a re-fetch" would otherwise have to
/// string-match `idTokenInvalid`'s human-readable reason, which is brittle.
enum IDTokenFailure: Error, Sendable {
    case unknownKid(kid: String)
    case invalid(String)

    /// Translates to the public, stable `GrooAuthError.idTokenInvalid(reason)`
    /// contract that `verifyIDToken` has always thrown, preserving the exact
    /// wording each failure produced before this type existed.
    var asGrooAuthError: GrooAuthError {
        switch self {
        case .unknownKid(let kid):
            return .idTokenInvalid("no JWK matching kid: \(kid)")
        case .invalid(let reason):
            return .idTokenInvalid(reason)
        }
    }
}

/// Parses `jwt` as a JOSE-compact ES256-signed `id_token`, verifies its
/// signature against `jwks`, and checks `iss`/`aud`/`exp`/`nonce`.
///
/// Throws `GrooAuthError.idTokenInvalid(reason)` for every failure, naming
/// the specific check that failed. There is no fallback path — any failed
/// check is fatal to verification. Thin wrapper over `verifyIDTokenCore`,
/// which throws the richer `IDTokenFailure` that `GrooAuthSession` uses to
/// detect the unknown-kid case specifically (see its doc comment).
func verifyIDToken(
    _ jwt: String,
    jwks: JWKS,
    issuer: String,
    clientId: String,
    nonce: String,
    now: Date
) throws -> IDTokenClaims {
    do {
        return try verifyIDTokenCore(jwt, jwks: jwks, issuer: issuer, clientId: clientId, nonce: nonce, now: now)
    } catch let failure as IDTokenFailure {
        throw failure.asGrooAuthError
    }
}

func verifyIDTokenCore(
    _ jwt: String,
    jwks: JWKS,
    issuer: String,
    clientId: String,
    nonce: String,
    now: Date
) throws -> IDTokenClaims {
    let segments = jwt.split(separator: ".", omittingEmptySubsequences: false)
    guard segments.count == 3 else {
        throw IDTokenFailure.invalid("malformed JWT: expected 3 segments, got \(segments.count)")
    }
    let headerB64 = String(segments[0])
    let payloadB64 = String(segments[1])
    let signatureB64 = String(segments[2])

    guard let headerData = base64URLDecode(headerB64) else {
        throw IDTokenFailure.invalid("malformed JWT: header is not valid base64url")
    }
    guard let payloadData = base64URLDecode(payloadB64) else {
        throw IDTokenFailure.invalid("malformed JWT: payload is not valid base64url")
    }
    guard let signatureData = base64URLDecode(signatureB64) else {
        throw IDTokenFailure.invalid("malformed JWT: signature is not valid base64url")
    }

    let header: IDTokenHeader
    do {
        header = try JSONDecoder().decode(IDTokenHeader.self, from: headerData)
    } catch {
        throw IDTokenFailure.invalid("malformed JWT header: \(error)")
    }

    guard header.alg == "ES256" else {
        throw IDTokenFailure.invalid("unsupported alg: expected ES256, got \(header.alg)")
    }
    guard let kid = header.kid else {
        throw IDTokenFailure.invalid("JWT header missing kid")
    }
    guard let jwk = jwks.keys.first(where: { $0.kid == kid }) else {
        throw IDTokenFailure.unknownKid(kid: kid)
    }
    guard jwk.kty == "EC" else {
        throw IDTokenFailure.invalid("unsupported JWK kty: expected EC, got \(jwk.kty)")
    }
    guard jwk.crv == "P-256" else {
        throw IDTokenFailure.invalid("unsupported JWK crv: expected P-256, got \(jwk.crv ?? "nil")")
    }
    guard let xB64 = jwk.x, let xData = base64URLDecode(xB64), xData.count == 32 else {
        throw IDTokenFailure.invalid("JWK x coordinate missing or not 32 bytes")
    }
    guard let yB64 = jwk.y, let yData = base64URLDecode(yB64), yData.count == 32 else {
        throw IDTokenFailure.invalid("JWK y coordinate missing or not 32 bytes")
    }

    // X9.63 uncompressed point: 0x04 || X(32) || Y(32).
    let x963 = Data([0x04]) + xData + yData
    let publicKey: P256.Signing.PublicKey
    do {
        publicKey = try P256.Signing.PublicKey(x963Representation: x963)
    } catch {
        throw IDTokenFailure.invalid("invalid JWK public key encoding: \(error)")
    }

    guard signatureData.count == 64 else {
        throw IDTokenFailure.invalid("invalid ES256 signature length: expected 64 bytes, got \(signatureData.count)")
    }
    let signature: P256.Signing.ECDSASignature
    do {
        signature = try P256.Signing.ECDSASignature(rawRepresentation: signatureData)
    } catch {
        throw IDTokenFailure.invalid("invalid ES256 signature encoding: \(error)")
    }

    let signingInput = Data("\(headerB64).\(payloadB64)".utf8)
    guard publicKey.isValidSignature(signature, for: signingInput) else {
        throw IDTokenFailure.invalid("signature verification failed")
    }

    let payload: IDTokenPayload
    do {
        payload = try JSONDecoder().decode(IDTokenPayload.self, from: payloadData)
    } catch {
        throw IDTokenFailure.invalid("malformed JWT payload: \(error)")
    }

    guard payload.iss == issuer else {
        throw IDTokenFailure.invalid("iss mismatch: expected \(issuer), got \(payload.iss)")
    }
    guard payload.aud == clientId else {
        throw IDTokenFailure.invalid("aud mismatch: expected \(clientId), got \(payload.aud)")
    }
    let expDate = Date(timeIntervalSince1970: payload.exp)
    guard expDate > now else {
        throw IDTokenFailure.invalid("token expired: exp \(expDate) is not after now \(now)")
    }
    guard payload.nonce == nonce else {
        throw IDTokenFailure.invalid("nonce mismatch: expected \(nonce), got \(payload.nonce ?? "nil")")
    }

    return IDTokenClaims(
        sub: payload.sub,
        email: payload.email,
        name: payload.name,
        iss: payload.iss,
        aud: payload.aud,
        exp: expDate,
        nonce: payload.nonce
    )
}
