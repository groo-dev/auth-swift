import Foundation
#if canImport(Security)
import Security
#endif

public struct StoredTokens: Codable, Sendable, Equatable {
    public let accessToken: String
    public let refreshToken: String
    public let tokenType: String
    public let expiresAt: Date
    public let idToken: String?
    public let scope: String?
    public let user: GrooUser?

    public init(accessToken: String, refreshToken: String, tokenType: String, expiresAt: Date,
                idToken: String?, scope: String?, user: GrooUser?) {
        self.accessToken = accessToken
        self.refreshToken = refreshToken
        self.tokenType = tokenType
        self.expiresAt = expiresAt
        self.idToken = idToken
        self.scope = scope
        self.user = user
    }
}

public protocol TokenStoring: Sendable {
    func load() throws -> StoredTokens?
    func save(_ tokens: StoredTokens) throws
    func clear() throws

    /// Removes the tokens but remembers whose they were, so the app can ask that
    /// person to sign in again without forgetting them — their local data stays
    /// theirs. `clear()` forgets both. Saving new tokens forgets the identity.
    func clearTokens(keeping user: GrooUser) throws

    /// The person `clearTokens(keeping:)` remembered, if they have neither signed
    /// in again nor signed out since.
    func loadIdentity() throws -> GrooUser?
}

extension TokenStoring {
    /// Stores written before reauth existed behave exactly as before: this is
    /// `clear()`. That preserves a store's own clearing rules — gr/ios's AutoFill
    /// extension wraps its store so `clear()` is a no-op, because deciding a user
    /// is signed out is not an extension's call, and that must stay true here.
    public func clearTokens(keeping user: GrooUser) throws { try clear() }

    /// Stores without identity support remember no one.
    public func loadIdentity() throws -> GrooUser? { nil }
}

/// Keychain-backed `TokenStoring` implementation. Stores a single JSON-encoded
/// `StoredTokens` value under a generic-password item keyed by (service, account[, access group]).
public final class KeychainTokenStore: TokenStoring {
    private static let account = "groo_oauth_tokens"
    private static let identityAccount = "groo_oauth_identity"

    private let service: String
    private let accessGroup: String?

    public init(service: String, accessGroup: String?) {
        self.service = service
        self.accessGroup = accessGroup
    }

    private func baseQuery(account: String = KeychainTokenStore.account) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        if let accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        return query
    }

    public func load() throws -> StoredTokens? {
        var query = baseQuery()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        // OSStatus and "found or not" are never secret — the decoded token
        // contents are, so only those two are logged here.
        GrooAuthLog.token.notice("keychain load status=\(status, privacy: .public) found=\(result != nil, privacy: .public) service=\(self.service, privacy: .public) group=\(self.accessGroup ?? "nil", privacy: .public)")

        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess else {
            throw GrooAuthError.transport("keychain load \(status)")
        }
        guard let data = result as? Data else {
            throw GrooAuthError.transport("keychain load \(status)")
        }
        return try JSONDecoder().decode(StoredTokens.self, from: data)
    }

    public func save(_ tokens: StoredTokens) throws {
        try upsert(account: Self.account, data: JSONEncoder().encode(tokens))
        // Signing in again forgets the kept identity. A failure here is logged, not
        // thrown: the tokens are saved, and a stale identity item is harmless because
        // tokens win in state computation.
        let status = SecItemDelete(baseQuery(account: Self.identityAccount) as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound {
            GrooAuthLog.token.error("keychain save: identity delete status=\(status, privacy: .public) service=\(self.service, privacy: .public)")
        }
    }

    /// Delete-then-add of one generic-password item.
    private func upsert(account: String, data: Data) throws {
        let deleteStatus = SecItemDelete(baseQuery(account: account) as CFDictionary)
        guard deleteStatus == errSecSuccess || deleteStatus == errSecItemNotFound else {
            GrooAuthLog.token.error("keychain save: delete status=\(deleteStatus, privacy: .public) service=\(self.service, privacy: .public) group=\(self.accessGroup ?? "nil", privacy: .public) (aborting before add)")
            throw GrooAuthError.transport("keychain save-delete \(deleteStatus)")
        }

        var addQuery = baseQuery(account: account)
        addQuery[kSecValueData as String] = data
        addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock

        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        // This is the prime suspect for a macOS sandbox/entitlement failure:
        // a non-zero addStatus here (e.g. -34018 errSecMissingEntitlement)
        // means the item never actually landed in the keychain even though
        // signIn() looked like it completed.
        GrooAuthLog.token.notice("keychain save: delete status=\(deleteStatus, privacy: .public) add status=\(addStatus, privacy: .public) service=\(self.service, privacy: .public) group=\(self.accessGroup ?? "nil", privacy: .public)")
        guard addStatus == errSecSuccess else {
            throw GrooAuthError.transport("keychain save \(addStatus)")
        }
    }

    public func clearTokens(keeping user: GrooUser) throws {
        // Identity FIRST: an interruption between the two steps then leaves tokens
        // and identity (still signed in) rather than neither (forgotten).
        try upsert(account: Self.identityAccount, data: JSONEncoder().encode(user))
        let status = SecItemDelete(baseQuery() as CFDictionary)
        GrooAuthLog.token.notice("keychain clearTokens(keeping:) delete status=\(status, privacy: .public) service=\(self.service, privacy: .public)")
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw GrooAuthError.transport("keychain clear-tokens \(status)")
        }
    }

    public func loadIdentity() throws -> GrooUser? {
        var query = baseQuery(account: Self.identityAccount)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else {
            throw GrooAuthError.transport("keychain load-identity \(status)")
        }
        return try JSONDecoder().decode(GrooUser.self, from: data)
    }

    public func clear() throws {
        // Both deletes run even if the first fails; every failure is reported.
        var failures: [String] = []
        for account in [Self.account, Self.identityAccount] {
            let status = SecItemDelete(baseQuery(account: account) as CFDictionary)
            GrooAuthLog.token.notice("keychain clear account=\(account, privacy: .public) status=\(status, privacy: .public) service=\(self.service, privacy: .public) group=\(self.accessGroup ?? "nil", privacy: .public)")
            if status != errSecSuccess && status != errSecItemNotFound {
                failures.append("\(account)=\(status)")
            }
        }
        guard failures.isEmpty else {
            throw GrooAuthError.transport("keychain clear \(failures.joined(separator: ", "))")
        }
    }
}

/// Simple thread-safe in-memory `TokenStoring` test double.
public final class InMemoryTokenStore: TokenStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var tokens: StoredTokens?
    private var identity: GrooUser?

    public init(tokens: StoredTokens? = nil) {
        self.tokens = tokens
    }

    public func load() throws -> StoredTokens? {
        lock.lock()
        defer { lock.unlock() }
        return tokens
    }

    public func save(_ tokens: StoredTokens) throws {
        lock.lock()
        defer { lock.unlock() }
        self.tokens = tokens
        identity = nil
    }

    public func clearTokens(keeping user: GrooUser) throws {
        lock.lock()
        defer { lock.unlock() }
        identity = user
        tokens = nil
    }

    public func loadIdentity() throws -> GrooUser? {
        lock.lock()
        defer { lock.unlock() }
        return identity
    }

    public func clear() throws {
        lock.lock()
        defer { lock.unlock() }
        tokens = nil
        identity = nil
    }
}
