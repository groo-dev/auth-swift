import XCTest
import AuthenticationServices
@testable import GrooAuth
@testable import GrooAuthUI

/// A web authenticator that is never reached: these tests drive state through the
/// token store, not through a sign-in.
private struct UnusedWebAuthenticator: WebAuthenticating {
    func authenticate(url: URL, callbackScheme: String, anchor: ASPresentationAnchor) async throws -> URL {
        XCTFail("sign-in should not be attempted in these tests")
        throw GrooAuthError.userCancelled
    }
}

private struct UnusedTransport: HTTPTransporting {
    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        XCTFail("no network should be reached in these tests")
        throw GrooAuthError.userCancelled
    }

    func sendWithoutFollowingRedirects(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        XCTFail("no network should be reached in these tests")
        throw GrooAuthError.userCancelled
    }
}

private func makeSession(storing tokens: StoredTokens?) -> GrooAuthSession {
    GrooAuthSession(
        config: GrooAuthConfig(
            issuer: URL(string: "https://me.example.test")!,
            clientId: "client_test",
            redirectURI: "test.app://oauth-callback",
            scopes: ["openid"],
            keychainService: "test"
        ),
        tokenStore: InMemoryTokenStore(tokens: tokens),
        transport: UnusedTransport(),
        webAuthenticator: UnusedWebAuthenticator()
    )
}

private func signedInTokens(sub: String, email: String) -> StoredTokens {
    StoredTokens(
        accessToken: "at",
        refreshToken: "rt",
        tokenType: "Bearer",
        expiresAt: Date().addingTimeInterval(900),
        idToken: nil,
        scope: "openid",
        user: GrooUser(sub: sub, email: email, name: "Test Person")
    )
}

@MainActor
final class GrooAuthControllerTests: XCTestCase {
    /// The distinction the whole loading state exists for: an app that cannot
    /// tell "signed out" from "not read yet" flashes its sign-in screen at an
    /// already-signed-in person on every launch. Both apps hand-rolled this.
    func testStartsLoadingBeforeTheStoreIsRead() {
        let controller = GrooAuthController(session: makeSession(storing: nil))
        XCTAssertTrue(controller.isLoading)
        XCTAssertFalse(controller.isSignedIn)
        XCTAssertNil(controller.user)
    }

    func testPublishesTheStoredUser() async {
        let controller = GrooAuthController(session: makeSession(storing: signedInTokens(sub: "u1", email: "a@b.test")))
        await controller.waitForFirstState()
        XCTAssertFalse(controller.isLoading)
        XCTAssertTrue(controller.isSignedIn)
        XCTAssertEqual(controller.user?.sub, "u1")
        XCTAssertEqual(controller.user?.email, "a@b.test")
    }

    func testAnEmptyStoreResolvesToSignedOutRatherThanStayingLoading() async {
        let controller = GrooAuthController(session: makeSession(storing: nil))
        await controller.waitForFirstState()
        XCTAssertFalse(controller.isLoading)
        XCTAssertFalse(controller.isSignedIn)
        XCTAssertNil(controller.user)
    }

    func testSessionIsReachableAsAnEscapeHatch() {
        // An app that wants its own views must be able to build on the same
        // logic; that is what makes an opinionated component library adoptable.
        let session = makeSession(storing: nil)
        let controller = GrooAuthController(session: session)
        XCTAssertTrue(controller.session === session)
    }
}
