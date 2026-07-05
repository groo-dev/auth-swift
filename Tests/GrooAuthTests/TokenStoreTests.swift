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
}
