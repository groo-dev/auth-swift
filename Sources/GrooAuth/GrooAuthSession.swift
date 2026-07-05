import Foundation
#if canImport(AuthenticationServices)
import AuthenticationServices
#endif

/// Decoded shape of a successful token-endpoint response (refresh or authorization_code grant).
struct TokenResponse: Decodable, Sendable {
    let access_token: String
    let refresh_token: String
    let token_type: String
    let expires_in: Int
    let id_token: String?
    let scope: String?
}

/// Test-only seam: fixes the PKCE verifier/challenge and the `state`/`nonce`
/// `signIn` would otherwise generate randomly, so tests can pre-sign a matching
/// `id_token` (which must carry the exact `nonce`) and assert on the exact
/// `state` echoed back in the callback URL. Only reachable via the internal
/// init below — the public init always generates fresh random values.
struct PKCEOverride: Sendable {
    let state: String
    let nonce: String
    let verifier: String
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

    /// Cached JWKS — fetched at most once per session instance, reused by every
    /// `id_token` verification (`signIn`, and future refresh-time re-verification).
    private var jwks: JWKS?

    /// The in-flight refresh, if any. Concurrent `refresh()` callers await this
    /// shared task instead of starting a second one.
    private var refreshTask: Task<Void, Error>?

    /// Fixed PKCE verifier/state/nonce for tests (`nil` in production — see `PKCEOverride`).
    private let pkceOverride: PKCEOverride?

    /// Subscribers to `stateStream`, keyed so a dropped subscriber's continuation
    /// can be pruned individually (see `stateStream`'s `onTermination`).
    /// `publish` fans a state change out to all of them.
    private var stateContinuations: [UUID: AsyncStream<GrooAuthState>.Continuation] = [:]

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
        self.pkceOverride = nil
    }

    /// Convenience init for app call sites: wires up the production
    /// `URLSessionTransport` and `ASWebAuthenticator` so callers don't need to
    /// construct them by hand. Equivalent to calling the full init with those
    /// two defaults and `now: Date.init`.
    public init(config: GrooAuthConfig, tokenStore: TokenStoring) {
        self.init(
            config: config,
            tokenStore: tokenStore,
            transport: URLSessionTransport(),
            webAuthenticator: ASWebAuthenticator(),
            now: Date.init
        )
    }

    /// Test-only seam (see `PKCEOverride`). Requires the override explicitly (no
    /// default) so this can never be selected by a production call site that omits it.
    init(
        config: GrooAuthConfig,
        tokenStore: TokenStoring,
        transport: HTTPTransporting,
        webAuthenticator: WebAuthenticating,
        now: @escaping @Sendable () -> Date = Date.init,
        pkceOverride: PKCEOverride
    ) {
        self.config = config
        self.tokenStore = tokenStore
        self.transport = transport
        self.webAuthenticator = webAuthenticator
        self.now = now
        self.pkceOverride = pkceOverride
    }

    // MARK: - Public state

    public func currentState() async -> GrooAuthState {
        computeCurrentState()
    }

    private func computeCurrentState() -> GrooAuthState {
        guard let tokens = (try? tokenStore.load()) ?? nil, let user = tokens.user else {
            return .signedOut
        }
        return .signedIn(user)
    }

    /// Emits on every state change: `signIn` success and refresh success emit
    /// `.signedIn`; refresh rejection and sign-out emit `.signedOut`. A new
    /// subscriber immediately receives the current state, then subsequent changes.
    public var stateStream: AsyncStream<GrooAuthState> {
        let id = UUID()
        var continuation: AsyncStream<GrooAuthState>.Continuation!
        let stream = AsyncStream<GrooAuthState> { continuation = $0 }
        continuation.yield(computeCurrentState())
        stateContinuations[id] = continuation
        // Without this, every subscriber that stops iterating (view disappears,
        // task cancelled, stream simply dropped) leaves its continuation in
        // `stateContinuations` forever — an unbounded leak for the actor's
        // lifetime. Pruning here keeps the dictionary sized to actual live
        // subscribers.
        continuation.onTermination = { [weak self] _ in
            Task { await self?.removeContinuation(id) }
        }
        return stream
    }

    private func removeContinuation(_ id: UUID) {
        stateContinuations.removeValue(forKey: id)
    }

    private func publish(_ state: GrooAuthState) {
        for continuation in stateContinuations.values {
            continuation.yield(state)
        }
    }

    /// Test-only introspection into subscriber count — not part of the public
    /// API. Lets tests assert that a dropped `stateStream` subscriber is
    /// actually pruned rather than leaking (see `removeContinuation`).
    func stateContinuationCountForTesting() -> Int {
        stateContinuations.count
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

    /// Forces a token refresh regardless of the cached token's expiry, then
    /// returns the refreshed access token. Callers use this after a request
    /// comes back `401` despite `accessToken()` having handed out what looked
    /// like a still-valid token (e.g. the token was revoked server-side).
    /// Single-flight, same as `accessToken()`'s own refresh path. Throws
    /// `.signedOut` if there's no session left, or if the refresh token
    /// itself is rejected (which also publishes `.signedOut` on `stateStream`).
    public func forceRefreshAccessToken() async throws -> String {
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
            if let user = stored.user {
                publish(.signedIn(user))
            }
        } catch let error as GrooAuthError {
            if case .protocolError = error {
                // Refresh token was rejected outright (e.g. invalid_grant / revoked).
                // There is no valid session to recover — clear it and sign out.
                try? tokenStore.clear()
                publish(.signedOut)
            }
            throw error
        }
    }

    // MARK: - Sign-in

    /// Drives the authorization-code + PKCE flow via `webAuthenticator`, verifies
    /// the returned `id_token`, stores the resulting tokens, and returns the user.
    ///
    /// Nothing is persisted unless every step succeeds: a cancelled/failed
    /// presentation, a `state` mismatch, an `error=` callback, a failed token
    /// exchange, or a failed `id_token` verification all leave the token store
    /// untouched.
    public func signIn(presentationAnchor: ASPresentationAnchor) async throws -> GrooUser {
        let verifier: String
        let state: String
        let nonce: String
        if let pkceOverride {
            verifier = pkceOverride.verifier
            state = pkceOverride.state
            nonce = pkceOverride.nonce
        } else {
            verifier = PKCE.generateVerifier()
            state = PKCE.randomURLSafe(byteCount: 16)
            nonce = PKCE.randomURLSafe(byteCount: 16)
        }
        let challenge = PKCE.challenge(for: verifier)

        let doc = try await loadDiscovery()

        guard var components = URLComponents(url: doc.authorizationEndpoint, resolvingAgainstBaseURL: false) else {
            throw GrooAuthError.invalidResponse("authorization_endpoint is not a valid URL: \(doc.authorizationEndpoint)")
        }
        components.queryItems = [
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "client_id", value: config.clientId),
            URLQueryItem(name: "redirect_uri", value: config.redirectURI),
            URLQueryItem(name: "scope", value: config.scopeString),
            URLQueryItem(name: "state", value: state),
            URLQueryItem(name: "nonce", value: nonce),
            URLQueryItem(name: "code_challenge", value: challenge),
            URLQueryItem(name: "code_challenge_method", value: "S256"),
        ]
        guard let authorizeURL = components.url else {
            throw GrooAuthError.invalidResponse("failed to construct authorization URL")
        }

        let callbackURL = try await webAuthenticator.authenticate(
            url: authorizeURL,
            callbackScheme: config.callbackScheme,
            anchor: presentationAnchor
        )

        let callbackItems = URLComponents(url: callbackURL, resolvingAgainstBaseURL: false)?.queryItems ?? []
        func value(_ name: String) -> String? { callbackItems.first(where: { $0.name == name })?.value }

        if let callbackError = value("error") {
            throw GrooAuthError.protocolError(OAuthProtocolError(error: callbackError, errorDescription: value("error_description")))
        }
        guard let returnedState = value("state"), returnedState == state else {
            throw GrooAuthError.stateMismatch
        }
        guard let code = value("code") else {
            throw GrooAuthError.invalidResponse("callback URL is missing code")
        }

        let response = try await requestToken(parameters: [
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": config.redirectURI,
            "client_id": config.clientId,
            "code_verifier": verifier,
        ])

        guard let idToken = response.id_token else {
            throw GrooAuthError.invalidResponse("token response missing id_token")
        }

        let claims = try await verifyIDTokenSelfHealing(idToken, doc: doc, nonce: nonce)
        let user = GrooUser(sub: claims.sub, email: claims.email, name: claims.name)

        let stored = StoredTokens(
            accessToken: response.access_token,
            refreshToken: response.refresh_token,
            tokenType: response.token_type,
            expiresAt: now().addingTimeInterval(TimeInterval(response.expires_in)),
            idToken: idToken,
            scope: response.scope,
            user: user
        )
        try tokenStore.save(stored)
        publish(.signedIn(user))
        return user
    }

    /// Verifies `idToken` against the cached JWKS, self-healing exactly once if
    /// verification fails specifically because the token's `kid` isn't in the
    /// cached JWKS (`IDTokenFailure.unknownKid`) — the IdP may have rotated its
    /// signing keys since this session's JWKS was cached, and a NEW sign-in's
    /// `id_token` will carry the new `kid`. On that specific failure, forces one
    /// cache-bypassing JWKS re-fetch and retries verification exactly once with
    /// the fresh JWKS; if it still fails (kid still absent, or now some other
    /// check fails) the failure propagates — never loops beyond one re-fetch.
    ///
    /// Any other verification failure (bad signature, wrong `aud`/`iss`, expired,
    /// bad nonce) is not a JWKS-cache problem and propagates immediately without
    /// re-fetching — re-fetching couldn't fix those regardless of which keys are
    /// cached, so retrying would just mask the real rejection behind an extra
    /// network round-trip.
    private func verifyIDTokenSelfHealing(
        _ idToken: String,
        doc: DiscoveryDocument,
        nonce: String
    ) async throws -> IDTokenClaims {
        let jwksDoc = try await loadJWKS(doc)
        do {
            return try verifyIDTokenCore(
                idToken,
                jwks: jwksDoc,
                issuer: config.issuer.absoluteString,
                clientId: config.clientId,
                nonce: nonce,
                now: now()
            )
        } catch IDTokenFailure.unknownKid {
            let freshJWKS = try await loadJWKS(doc, forceRefresh: true)
            do {
                return try verifyIDTokenCore(
                    idToken,
                    jwks: freshJWKS,
                    issuer: config.issuer.absoluteString,
                    clientId: config.clientId,
                    nonce: nonce,
                    now: now()
                )
            } catch let failure as IDTokenFailure {
                throw failure.asGrooAuthError
            }
        } catch let failure as IDTokenFailure {
            throw failure.asGrooAuthError
        }
    }

    // MARK: - Sign-out

    /// Signs out locally and, if possible, revokes the refresh-token family
    /// server-side (RFC 7009) so a leaked/cached token can't be replayed later.
    ///
    /// Never throws — whatever happens with the revoke attempt, local tokens are
    /// always cleared and `.signedOut` is always published to `stateStream`. The
    /// only way a caller learns the revoke attempt failed is via the returned
    /// `.clearedButRevokeFailed(reason:)`, whose `reason` names the real failure
    /// (HTTP status or underlying error) rather than swallowing it.
    ///
    /// A `tokenStore.load()` throw is distinguished from a genuine "no tokens
    /// stored": the former means we cannot know whether there's a refresh token
    /// to revoke, so it is reported as `.clearedButRevokeFailed` (never silently
    /// upgraded to `.revokedAndCleared`, which would misreport a revoke that
    /// never happened). Only a real nil (no error, no tokens) keeps the
    /// "nothing to revoke" `.revokedAndCleared` outcome.
    public func signOut() async -> SignOutResult {
        let loaded: StoredTokens?
        var revokeFailureReason: String?
        do {
            loaded = try tokenStore.load()
        } catch {
            loaded = nil
            revokeFailureReason = "could not read stored tokens to revoke: \(error)"
        }

        if let tokens = loaded, !tokens.refreshToken.isEmpty {
            do {
                let doc = try await loadDiscovery()
                if let revocationEndpoint = doc.revocationEndpoint {
                    do {
                        let (_, response) = try await postForm(
                            url: revocationEndpoint,
                            parameters: ["token": tokens.refreshToken, "client_id": config.clientId]
                        )
                        if response.statusCode != 200 {
                            revokeFailureReason = "revocation endpoint returned HTTP \(response.statusCode)"
                        }
                    } catch {
                        revokeFailureReason = "revocation request failed: \(error)"
                    }
                }
                // else: server advertises no revocation_endpoint — nothing to revoke.
            } catch {
                revokeFailureReason = "failed to load discovery for revocation: \(error)"
            }
        }

        do {
            try tokenStore.clear()
        } catch {
            // Clearing failed too — the most serious outcome. Still publish
            // .signedOut (the app-visible state is "signed out" either way) and
            // surface both failures in the reason rather than losing one.
            publish(.signedOut)
            let clearFailure = "failed to clear local tokens: \(error)"
            let reason = revokeFailureReason.map { "\($0); \(clearFailure)" } ?? clearFailure
            return .clearedButRevokeFailed(reason: reason)
        }

        publish(.signedOut)
        if let revokeFailureReason {
            return .clearedButRevokeFailed(reason: revokeFailureReason)
        }
        return .revokedAndCleared
    }

    // MARK: - Token exchange (shared by refresh + signIn)

    /// POSTs a form-encoded grant request to the discovery-provided token endpoint
    /// and decodes the result. Used for both `grant_type=refresh_token` (`refresh`)
    /// and `grant_type=authorization_code` (`signIn`).
    func requestToken(parameters: [String: String]) async throws -> TokenResponse {
        let doc = try await loadDiscovery()
        let (data, response) = try await postForm(url: doc.tokenEndpoint, parameters: parameters)
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

    /// POSTs a form-encoded body to `url` via the shared transport and returns the
    /// raw response. Shared plumbing for the token endpoint (`requestToken`) and
    /// the revocation endpoint (`signOut`).
    private func postForm(url: URL, parameters: [String: String]) async throws -> (Data, HTTPURLResponse) {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = Self.formEncode(parameters)
        return try await transport.send(request)
    }

    private func loadDiscovery() async throws -> DiscoveryDocument {
        if let discovery { return discovery }
        let doc = try await fetchDiscovery(issuer: config.issuer, transport: transport)
        discovery = doc
        return doc
    }

    /// Fetches and caches the JWKS from the discovery document's `jwks_uri`.
    /// `forceRefresh` bypasses the cache and re-fetches even if a value is
    /// already cached — used by `verifyIDTokenSelfHealing` to get fresh keys
    /// after an unknown-`kid` failure (e.g. the IdP rotated signing keys).
    private func loadJWKS(_ doc: DiscoveryDocument, forceRefresh: Bool = false) async throws -> JWKS {
        if !forceRefresh, let jwks { return jwks }
        let (data, response) = try await transport.send(URLRequest(url: doc.jwksURI))
        guard response.statusCode == 200 else {
            throw GrooAuthError.invalidResponse("jwks HTTP \(response.statusCode)")
        }
        let decoded: JWKS
        do {
            decoded = try JSONDecoder().decode(JWKS.self, from: data)
        } catch {
            throw GrooAuthError.invalidResponse("jwks response missing/invalid field: \(error)")
        }
        jwks = decoded
        return decoded
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
