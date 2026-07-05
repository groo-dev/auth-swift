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
}

/// Keychain-backed `TokenStoring` implementation. Stores a single JSON-encoded
/// `StoredTokens` value under a generic-password item keyed by (service, account[, access group]).
public final class KeychainTokenStore: TokenStoring {
    private static let account = "groo_oauth_tokens"

    private let service: String
    private let accessGroup: String?

    public init(service: String, accessGroup: String?) {
        self.service = service
        self.accessGroup = accessGroup
    }

    private func baseQuery() -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: Self.account,
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
        // Upsert: delete any existing item, then add fresh.
        let deleteStatus = SecItemDelete(baseQuery() as CFDictionary)
        guard deleteStatus == errSecSuccess || deleteStatus == errSecItemNotFound else {
            GrooAuthLog.token.error("keychain save: delete status=\(deleteStatus, privacy: .public) service=\(self.service, privacy: .public) group=\(self.accessGroup ?? "nil", privacy: .public) (aborting before add)")
            throw GrooAuthError.transport("keychain save-delete \(deleteStatus)")
        }

        let data = try JSONEncoder().encode(tokens)
        var addQuery = baseQuery()
        addQuery[kSecValueData as String] = data
        addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock

        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        // This is the prime suspect for a macOS sandbox/entitlement failure:
        // a non-zero addStatus here (e.g. -34018 errSecMissingEntitlement)
        // means the token never actually landed in the keychain even though
        // signIn() looked like it completed.
        GrooAuthLog.token.notice("keychain save: delete status=\(deleteStatus, privacy: .public) add status=\(addStatus, privacy: .public) service=\(self.service, privacy: .public) group=\(self.accessGroup ?? "nil", privacy: .public)")
        guard addStatus == errSecSuccess else {
            throw GrooAuthError.transport("keychain save \(addStatus)")
        }
    }

    public func clear() throws {
        let status = SecItemDelete(baseQuery() as CFDictionary)
        GrooAuthLog.token.notice("keychain clear status=\(status, privacy: .public) service=\(self.service, privacy: .public) group=\(self.accessGroup ?? "nil", privacy: .public)")
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw GrooAuthError.transport("keychain clear \(status)")
        }
    }
}

/// Simple thread-safe in-memory `TokenStoring` test double.
public final class InMemoryTokenStore: TokenStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var tokens: StoredTokens?

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
    }

    public func clear() throws {
        lock.lock()
        defer { lock.unlock() }
        tokens = nil
    }
}
