import Foundation

public protocol HTTPTransporting: Sendable {
    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse)

    /// Sends `request` and returns the FIRST response, redirects unfollowed.
    ///
    /// The native passkey flow calls `/authorize` directly, and there the redirect
    /// IS the answer: its `Location` carries either the authorization code or the
    /// reason there is none. Following it would fetch a consent page and lose the
    /// only thing the caller wanted — or, when the target is the app's own custom
    /// scheme, fail as an unsupported URL and lose it just as thoroughly.
    ///
    /// A protocol requirement rather than an extension default, deliberately: a
    /// transport that quietly followed the redirect would break that flow in a way
    /// no type error would catch.
    func sendWithoutFollowingRedirects(_ request: URLRequest) async throws -> (Data, HTTPURLResponse)
}

public struct URLSessionTransport: HTTPTransporting {
    public init() {}

    public func sendWithoutFollowingRedirects(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let session = URLSession(configuration: .ephemeral, delegate: NoRedirects(), delegateQueue: nil)
        // URLSession retains its delegate until invalidated, so a session created
        // per call leaks one of each without this.
        defer { session.finishTasksAndInvalidate() }
        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            throw GrooAuthError.transport(error.localizedDescription)
        }
        guard let http = response as? HTTPURLResponse else {
            throw GrooAuthError.invalidResponse("non-HTTP response for \(request.url?.absoluteString ?? "unknown URL")")
        }
        return (data, http)
    }

    public func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await URLSession.shared.data(for: request)
        } catch {
            throw GrooAuthError.transport(error.localizedDescription)
        }
        guard let http = response as? HTTPURLResponse else {
            throw GrooAuthError.invalidResponse("non-HTTP response for \(request.url?.absoluteString ?? "unknown URL")")
        }
        return (data, http)
    }
}

/// Answers every redirect with "do not follow", so the 302 itself reaches the
/// caller.
private final class NoRedirects: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}
