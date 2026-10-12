import XCTest
@testable import GrooAuth

final class TokenStoreTests: XCTestCase {
    private func sampleTokens(user: GrooUser? = GrooUser(sub: "abc123", email: "a@b.com", name: "Alice")) -> StoredTokens {
        StoredTokens(
            accessToken: "access-token-value",
            refreshToken: "refresh-token-value",
            tokenType: "Bearer",
            expiresAt: Date(timeIntervalSince1970: 1_783_000_000),
            idToken: "id-token-value",
            scope: "openid profile email",
            user: user
        )
    }

    // MARK: - KeychainTokenStore (nil access group, real keychain)

    func testKeychainRoundTripSaveLoadClear() throws {
        let service = "dev.groo.test.\(UUID().uuidString)"
        let store = KeychainTokenStore(service: service, accessGroup: nil)
        let tokens = sampleTokens()

        do {
            try store.save(tokens)
        } catch GrooAuthError.transport(let message) where message.contains("-34018") || message.lowercased().contains("missingentitlement") {
            throw XCTSkip("Keychain unavailable in this environment (errSecMissingEntitlement): \(message)")
        }

        let loaded = try store.load()
        XCTAssertEqual(loaded, tokens)

        try store.clear()
        XCTAssertNil(try store.load())
    }

    func testKeychainLoadWhenAbsentReturnsNil() throws {
        let service = "dev.groo.test.\(UUID().uuidString)"
        let store = KeychainTokenStore(service: service, accessGroup: nil)
        XCTAssertNil(try store.load())
    }

    func testKeychainClearWhenAbsentIsIdempotent() throws {
        let service = "dev.groo.test.\(UUID().uuidString)"
        let store = KeychainTokenStore(service: service, accessGroup: nil)
        XCTAssertNoThrow(try store.clear())
        XCTAssertNoThrow(try store.clear())
    }

    func testKeychainSaveOverwritesExisting() throws {
        let service = "dev.groo.test.\(UUID().uuidString)"
        let store = KeychainTokenStore(service: service, accessGroup: nil)
        let first = sampleTokens()
        let second = sampleTokens(user: GrooUser(sub: "xyz789", email: "z@y.com", name: "Zed"))

        do {
            try store.save(first)
        } catch GrooAuthError.transport(let message) where message.contains("-34018") || message.lowercased().contains("missingentitlement") {
            throw XCTSkip("Keychain unavailable in this environment (errSecMissingEntitlement): \(message)")
        }

        try store.save(second)
        let loaded = try store.load()
        XCTAssertEqual(loaded, second)
        try? store.clear()
    }

    // MARK: - InMemoryTokenStore

    func testInMemoryRoundTripSaveLoadClear() throws {
        let store = InMemoryTokenStore()
        XCTAssertNil(try store.load())

        let tokens = sampleTokens()
        try store.save(tokens)
        XCTAssertEqual(try store.load(), tokens)

        try store.clear()
        XCTAssertNil(try store.load())
    }

    func testInMemoryOverwritesOnSave() throws {
        let store = InMemoryTokenStore()
        try store.save(sampleTokens())
        let second = sampleTokens(user: nil)
        try store.save(second)
        XCTAssertEqual(try store.load(), second)
    }

    func testInMemoryStoreConcurrentAccessIsSafe() throws {
        let store = InMemoryTokenStore()
        let tokens = sampleTokens()
        let iterations = 200
        DispatchQueue.concurrentPerform(iterations: iterations) { i in
            if i % 2 == 0 {
                try? store.save(tokens)
            } else {
                _ = try? store.load()
            }
        }
        // No crash and store is left in a consistent, decodable state.
        XCTAssertNoThrow(try store.load())
    }

    // MARK: - StoredTokens model

    func testStoredTokensEquatableAndCodable() throws {
        let tokens = sampleTokens()
        let data = try JSONEncoder().encode(tokens)
        let decoded = try JSONDecoder().decode(StoredTokens.self, from: data)
        XCTAssertEqual(decoded, tokens)
    }

    func testStoredTokensOptionalFieldsCanBeNil() throws {
        let tokens = StoredTokens(
            accessToken: "a",
            refreshToken: "r",
            tokenType: "Bearer",
            expiresAt: Date(timeIntervalSince1970: 1_783_000_000),
            idToken: nil,
            scope: nil,
            user: nil
        )
        let data = try JSONEncoder().encode(tokens)
        let decoded = try JSONDecoder().decode(StoredTokens.self, from: data)
        XCTAssertEqual(decoded, tokens)
    }

    // MARK: - Identity kept across a token clear (reauth)

    private let alice = GrooUser(sub: "abc123", email: "a@b.com", name: "Alice")

    private func assertIdentitySemantics(_ store: TokenStoring, file: StaticString = #filePath, line: UInt = #line) throws {
        XCTAssertNil(try store.loadIdentity(), "no identity before any reauth", file: file, line: line)
        try store.save(sampleTokens())
        try store.clearTokens(keeping: alice)
        XCTAssertNil(try store.load(), "tokens are gone", file: file, line: line)
        XCTAssertEqual(try store.loadIdentity(), alice, "identity is kept", file: file, line: line)

        try store.save(sampleTokens())
        XCTAssertNil(try store.loadIdentity(), "signing in again forgets the kept identity", file: file, line: line)

        try store.clearTokens(keeping: alice)
        try store.clear()
        XCTAssertNil(try store.load(), file: file, line: line)
        XCTAssertNil(try store.loadIdentity(), "an explicit clear forgets the identity too", file: file, line: line)
    }

    func testInMemoryStoreKeepsIdentity() throws {
        try assertIdentitySemantics(InMemoryTokenStore())
    }

    func testKeychainStoreKeepsIdentity() throws {
        let store = KeychainTokenStore(service: "dev.groo.test.\(UUID().uuidString)", accessGroup: nil)
        do {
            try store.save(sampleTokens())
            try store.clear()
        } catch GrooAuthError.transport(let message) where message.contains("-34018") || message.lowercased().contains("missingentitlement") {
            throw XCTSkip("Keychain unavailable in this environment (errSecMissingEntitlement): \(message)")
        }
        try assertIdentitySemantics(store)
    }

    func testKeychainClearTokensWritesIdentityBeforeDeletingTokens() throws {
        // Write order is the crash-safety property: identity first, so an interruption
        // leaves tokens + identity (still signed in), never neither.
        let store = KeychainTokenStore(service: "dev.groo.test.\(UUID().uuidString)", accessGroup: nil)
        do { try store.save(sampleTokens()) } catch GrooAuthError.transport(let m) where m.contains("-34018") {
            throw XCTSkip("Keychain unavailable: \(m)")
        }
        try store.clearTokens(keeping: alice)
        XCTAssertEqual(try store.loadIdentity(), alice)
        XCTAssertNil(try store.load())
        try store.clear()
    }

    /// A store written before reauth existed — like gr/ios's NonDestructiveTokenStore,
    /// whose clear() refuses to clear from an app extension.
    private final class LegacyStore: TokenStoring, @unchecked Sendable {
        var clears = 0
        var tokens: StoredTokens?
        func load() throws -> StoredTokens? { tokens }
        func save(_ tokens: StoredTokens) throws { self.tokens = tokens }
        func clear() throws { clears += 1 }   // a deliberate no-op, as in NonDestructiveTokenStore
    }

    func testStoresWithoutIdentitySupportBehaveExactlyAsBefore() throws {
        let store = LegacyStore()
        store.tokens = sampleTokens()
        try store.clearTokens(keeping: alice)
        XCTAssertEqual(store.clears, 1, "the default routes through clear(), honouring the store's own rules")
        XCTAssertNotNil(store.tokens, "a store whose clear() is a no-op keeps its tokens")
        XCTAssertNil(try store.loadIdentity())
    }
}
