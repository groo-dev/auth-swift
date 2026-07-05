import Foundation
#if canImport(AuthenticationServices)
import AuthenticationServices
#endif

/// Abstraction over `ASWebAuthenticationSession` so the session actor's sign-in flow
/// (Task 7) can be driven by a test double. Declared here because `GrooAuthSession`
/// takes a `WebAuthenticating` at init, even though `signIn` itself lands in Task 7.
public protocol WebAuthenticating: Sendable {
    func authenticate(url: URL, callbackScheme: String, anchor: ASPresentationAnchor?) async throws -> URL
}

/// Decoded shape of a successful token-endpoint response (refresh or authorization_code grant).
struct TokenResponse: Decodable, Sendable {
    let access_token: String
    let refresh_token: String
    let token_type: String
    let expires_in: Int
    let id_token: String?
    let scope: String?
}

/// Owns the OAuth token lifecycle: discovery caching, token exchange, and refresh.
///
/// Refresh is single-flight: concurrent callers that all observe an expired access
/// token share one in-flight `performRefresh()` rather than each firing their own
/// request at the token endpoint. See `refresh()`.
public actor GrooAuthSession {
    private let config: GrooAuthConfig
    private let tokenStore: TokenStoring
    private let transport: HTTPTransporting
    private let webAuthenticator: WebAuthenticating
    private let now: @Sendable () -> Date

    /// Cached discovery document — fetched at most once per session instance.
    private var discovery: DiscoveryDocument?

    /// The in-flight refresh, if any. Concurrent `refresh()` callers await this
    /// shared task instead of starting a second one.
    private var refreshTask: Task<Void, Error>?

    public init(
        config: GrooAuthConfig,
        tokenStore: TokenStoring,
        transport: HTTPTransporting,
        webAuthenticator: WebAuthenticating,
        now: @escaping @Sendable () -> Date = Date.init
    ) {
        self.config = config
        self.tokenStore = tokenStore
        self.transport = transport
        self.webAuthenticator = webAuthenticator
        self.now = now
    }

    // MARK: - Public state

    public func currentState() async -> GrooAuthState {
        guard let tokens = (try? tokenStore.load()) ?? nil, let user = tokens.user else {
            return .signedOut
        }
        return .signedIn(user)
    }

    /// Returns a valid access token, refreshing first if the cached one is expired
    /// (or within 60s of expiry). Throws `.signedOut` if there are no stored tokens.
    public func accessToken() async throws -> String {
        guard let tokens = try tokenStore.load() else {
            throw GrooAuthError.signedOut
        }
        if tokens.expiresAt.timeIntervalSince(now()) > 60 {
            return tokens.accessToken
        }
        try await refresh()
        guard let refreshed = try tokenStore.load() else {
            throw GrooAuthError.signedOut
        }
        return refreshed.accessToken
    }

    // MARK: - Single-flight refresh

    /// Refreshes the access token using the stored refresh token.
    ///
    /// Single-flight: if a refresh is already in progress, this awaits that same
    /// task rather than starting a new one. Because `GrooAuthSession` is an actor,
    /// concurrent callers serialize on entry — the first to arrive installs
    /// `refreshTask` and suspends on `task.value`; every other caller observes the
    /// already-installed task and awaits it too. Net effect: exactly one
    /// `performRefresh()` (and therefore exactly one token-endpoint request) no
    /// matter how many callers raced in. Never auto-retries on failure.
    func refresh() async throws {
        if let existing = refreshTask {
            try await existing.value
            return
        }
        let task = Task { try await self.performRefresh() }
        refreshTask = task
        defer { refreshTask = nil }
        try await task.value
    }

    private func performRefresh() async throws {
        guard let tokens = try tokenStore.load() else {
            throw GrooAuthError.signedOut
        }
        do {
            let response = try await requestToken(parameters: [
                "grant_type": "refresh_token",
                "refresh_token": tokens.refreshToken,
                "client_id": config.clientId,
            ])
            let stored = StoredTokens(
                accessToken: response.access_token,
                refreshToken: response.refresh_token,
                tokenType: response.token_type,
                expiresAt: now().addingTimeInterval(TimeInterval(response.expires_in)),
                idToken: response.id_token,
                scope: response.scope,
                user: tokens.user
            )
            try tokenStore.save(stored)
        } catch let error as GrooAuthError {
            if case .protocolError = error {
                // Refresh token was rejected outright (e.g. invalid_grant / revoked).
                // There is no valid session to recover — clear it and sign out.
                try? tokenStore.clear()
            }
            throw error
        }
    }

    // MARK: - Token exchange (shared by refresh + Task 7's signIn)

    /// POSTs a form-encoded grant request to the discovery-provided token endpoint
    /// and decodes the result. Used for both `grant_type=refresh_token` (this task)
    /// and `grant_type=authorization_code` (Task 7's `signIn`).
    func requestToken(parameters: [String: String]) async throws -> TokenResponse {
        let doc = try await loadDiscovery()
        var request = URLRequest(url: doc.tokenEndpoint)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = Self.formEncode(parameters)

        let (data, response) = try await transport.send(request)
        guard response.statusCode == 200 else {
            let protocolError = try OAuthProtocolError.decode(data)
            throw GrooAuthError.protocolError(protocolError)
        }
        do {
            return try JSONDecoder().decode(TokenResponse.self, from: data)
        } catch {
            throw GrooAuthError.invalidResponse("token response missing/invalid field: \(error)")
        }
    }

    private func loadDiscovery() async throws -> DiscoveryDocument {
        if let discovery { return discovery }
        let doc = try await fetchDiscovery(issuer: config.issuer, transport: transport)
        discovery = doc
        return doc
    }

    private static let unreservedCharacters = CharacterSet(
        charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    )

    private static func formEncode(_ parameters: [String: String]) -> Data {
        let pairs = parameters.sorted { $0.key < $1.key }.map { key, value -> String in
            let encodedKey = key.addingPercentEncoding(withAllowedCharacters: unreservedCharacters) ?? key
            let encodedValue = value.addingPercentEncoding(withAllowedCharacters: unreservedCharacters) ?? value
            return "\(encodedKey)=\(encodedValue)"
        }
        return Data(pairs.joined(separator: "&").utf8)
    }
}
