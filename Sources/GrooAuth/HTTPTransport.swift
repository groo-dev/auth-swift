import Foundation

public protocol HTTPTransporting: Sendable {
    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse)
}

public struct URLSessionTransport: HTTPTransporting {
    public init() {}

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
