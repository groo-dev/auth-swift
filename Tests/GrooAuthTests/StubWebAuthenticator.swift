import Foundation
#if canImport(AuthenticationServices)
import AuthenticationServices
#endif
@testable import GrooAuth

/// Trivial `WebAuthenticating` test double. Not exercised by refresh tests (Task 6) —
/// `GrooAuthSession` requires an authenticator at init but refresh never calls it.
/// Task 7's sign-in tests will configure `result` to return a canned callback URL
/// or throw.
final class StubWebAuthenticator: WebAuthenticating, @unchecked Sendable {
    enum Result {
        case success(URL)
        case failure(Error)
    }

    private let result: Result

    init(result: Result = .failure(GrooAuthError.userCancelled)) {
        self.result = result
    }

    func authenticate(url: URL, callbackScheme: String, anchor: ASPresentationAnchor?) async throws -> URL {
        switch result {
        case .success(let url): return url
        case .failure(let error): throw error
        }
    }
}
