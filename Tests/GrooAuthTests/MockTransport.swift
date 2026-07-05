import Foundation
@testable import GrooAuth

/// Reusable test double for `HTTPTransporting`.
///
/// Constructed from a `[urlString: (status, body)]` route map. Requests are matched
/// by URL only (method is ignored), so the same instance can back GET-based discovery/JWKS
/// fetches as well as POST-based token/revoke calls in later tasks.
///
/// Not thread-safe by design choice, but marked `@unchecked Sendable` since `HTTPTransporting`
/// requires `Sendable` conformance and tests drive it from a single task/actor context.
final class MockTransport: HTTPTransporting, @unchecked Sendable {
    struct Response {
        let status: Int
        let body: String
    }

    private var routes: [String: Response]
    private(set) var calls: [String] = []
    /// Last request body seen per URL (e.g. the form-encoded POST body), keyed the
    /// same way as `routes`/`calls`. Lets tests assert on what was actually sent
    /// (e.g. that a revoke POST carried the refresh token) without needing a
    /// full request-capturing overhaul.
    private(set) var lastBodies: [String: Data] = [:]

    init(routes: [String: (status: Int, body: String)]) {
        self.routes = routes.mapValues { Response(status: $0.status, body: $0.body) }
    }

    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        guard let url = request.url else {
            throw GrooAuthError.transport("MockTransport: request has no URL")
        }
        let key = url.absoluteString
        calls.append(key)
        if let body = request.httpBody {
            lastBodies[key] = body
        }
        guard let route = routes[key] else {
            throw GrooAuthError.transport("MockTransport: no route mapped for \(key)")
        }
        let data = Data(route.body.utf8)
        guard let response = HTTPURLResponse(
            url: url,
            statusCode: route.status,
            httpVersion: "HTTP/1.1",
            headerFields: nil
        ) else {
            throw GrooAuthError.transport("MockTransport: failed to construct HTTPURLResponse for \(key)")
        }
        return (data, response)
    }

    /// Number of requests seen for a given URL string (across all HTTP methods).
    func callCount(for urlString: String) -> Int {
        calls.filter { $0 == urlString }.count
    }

    /// Total number of requests seen across all routes.
    var totalCallCount: Int { calls.count }

    /// The last request body sent to `urlString`, if any request was made to it.
    func lastRequestBody(for urlString: String) -> Data? {
        lastBodies[urlString]
    }
}
