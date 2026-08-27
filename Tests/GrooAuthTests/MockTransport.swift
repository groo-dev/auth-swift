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
        /// Response headers. Only the no-redirect path needs them — a 302's
        /// `Location` is the entire answer there.
        var headers: [String: String]? = nil
    }

    private var routes: [String: Response]
    /// Matched by URL PREFIX when no exact route applies. `/authorize` carries a
    /// freshly generated state and nonce, so an exact key cannot be written down
    /// in a test that does not also own those values.
    private var prefixRoutes: [(prefix: String, response: Response)] = []
    /// Per-URL queues of responses that take priority over `routes`, popped one
    /// per call in order (falling back to `routes` once exhausted). Lets tests
    /// simulate an endpoint's response changing across repeated fetches — e.g.
    /// stale JWKS on the first fetch and fresh JWKS (post key-rotation) on the
    /// second — without needing a full request-sequencing overhaul.
    private var sequences: [String: [Response]] = [:]
    private(set) var calls: [String] = []
    /// Last request body seen per URL (e.g. the form-encoded POST body), keyed the
    /// same way as `routes`/`calls`. Lets tests assert on what was actually sent
    /// (e.g. that a revoke POST carried the refresh token) without needing a
    /// full request-capturing overhaul.
    private(set) var lastBodies: [String: Data] = [:]

    init(routes: [String: (status: Int, body: String)]) {
        self.routes = routes.mapValues { Response(status: $0.status, body: $0.body) }
    }

    /// Queues `responses` for `urlString`, each call to that URL popping the
    /// next one in order. Once the queue is exhausted, subsequent calls fall
    /// back to the static entry in `routes` (if any).
    /// Answers any request whose URL starts with `prefix`, after exact routes.
    func setPrefixRoute(_ prefix: String, status: Int, body: String = "", headers: [String: String]? = nil) {
        prefixRoutes.append((prefix, Response(status: status, body: body, headers: headers)))
    }

    func setSequence(for urlString: String, responses: [(status: Int, body: String)]) {
        sequences[urlString] = responses.map { Response(status: $0.status, body: $0.body) }
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
        let route: Response
        if var queued = sequences[key], !queued.isEmpty {
            route = queued.removeFirst()
            sequences[key] = queued
        } else if let fixed = routes[key] {
            route = fixed
        } else if let prefixed = prefixRoutes.first(where: { key.hasPrefix($0.prefix) })?.response {
            route = prefixed
        } else {
            throw GrooAuthError.transport("MockTransport: no route mapped for \(key)")
        }
        let data = Data(route.body.utf8)
        guard let response = HTTPURLResponse(
            url: url,
            statusCode: route.status,
            httpVersion: "HTTP/1.1",
            headerFields: route.headers
        ) else {
            throw GrooAuthError.transport("MockTransport: failed to construct HTTPURLResponse for \(key)")
        }
        return (data, response)
    }

    /// Same routing. The distinction the protocol draws is about following
    /// redirects, and a mock never follows anything — so a 302 route simply
    /// arrives intact, which is exactly what the caller under test expects.
    func sendWithoutFollowingRedirects(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        try await send(request)
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
