import Foundation
import GrooAuth
import Observation

// MARK: - Wire types

/// A passkey registered on the account.
public struct GrooPasskey: Sendable, Identifiable, Equatable, Decodable {
    public let id: String
    public let name: String?
    /// `singleDevice` or `multiDevice`. A single-device key is the one worth
    /// warning about: lose the device and it is gone.
    public let deviceType: String?
    public let backedUp: Bool?
    public let lastUsedAt: String?
    public let createdAt: String?
}

/// A signed-in browser session.
public struct GrooDevice: Sendable, Identifiable, Equatable, Decodable {
    public let id: String
    public let deviceInfo: String?
    public let ipAddress: String?
    public let lastActive: String
    public let createdAt: String
}

/// An application the person has granted access to.
public struct GrooConnectedApp: Sendable, Identifiable, Equatable, Decodable {
    public let id: String
    public let applicationId: String
    public let appName: String
    public let scopes: [String]
    public let consentedAt: String
    public let lastAccessedAt: String
}

/// A personal API token. Only its prefix is ever shown — the token itself is
/// returned once, at creation, and never again.
public struct GrooAPIToken: Sendable, Identifiable, Equatable, Decodable {
    public let id: String
    public let name: String
    public let description: String?
    public let tokenPrefix: String
    public let lastUsed: String?
    public let expiresAt: String?
    public let revoked: Bool
    public let createdAt: String
}

// MARK: - Store

private struct PasskeysEnvelope: Decodable { let passkeys: [GrooPasskey] }
private struct DevicesEnvelope: Decodable { let sessions: [GrooDevice] }
private struct AppsEnvelope: Decodable { let apps: [GrooConnectedApp] }
private struct TokensEnvelope: Decodable { let tokens: [GrooAPIToken] }

/// The four lists behind `GrooAccountView`'s security sections.
///
/// One store rather than four, because they share everything that matters: the
/// same surface, the same failure handling, and the same rule that a section the
/// app did not ask for is never fetched. Four stores would be four copies of that
/// rule.
@MainActor
@Observable
public final class GrooAccountListsStore {
    public private(set) var passkeys: [GrooPasskey] = []
    public private(set) var devices: [GrooDevice] = []
    public private(set) var connectedApps: [GrooConnectedApp] = []
    public private(set) var tokens: [GrooAPIToken] = []

    /// Set while the first load of any section is in flight.
    public private(set) var isLoading = false

    /// Per-section, because one section failing must not blank the other three.
    /// A missing scope is the likely case and it is per-scope: an app granted
    /// `accounts:passkeys` but not `accounts:devices` should show its passkeys.
    public private(set) var errors: [String: String] = [:]

    /// The id currently being revoked, so a row can show its own progress rather
    /// than the whole screen going busy.
    public private(set) var pendingRevoke: String?

    private let session: GrooAuthSession
    private let sections: GrooAccountSections
    private var hasLoaded = false

    public init(session: GrooAuthSession, sections: GrooAccountSections) {
        self.session = session
        self.sections = sections
    }

    public func load() async {
        if !hasLoaded { isLoading = true }
        await withTaskGroup(of: Void.self) { group in
            if sections.contains(.passkeys) { group.addTask { await self.loadPasskeys() } }
            if sections.contains(.devices) { group.addTask { await self.loadDevices() } }
            if sections.contains(.connectedApps) { group.addTask { await self.loadConnectedApps() } }
            if sections.contains(.tokens) { group.addTask { await self.loadTokens() } }
        }
        hasLoaded = true
        isLoading = false
    }

    private func loadPasskeys() async {
        do {
            let data = try await session.accountRequest(path: "v1/account/passkeys")
            passkeys = try JSONDecoder().decode(PasskeysEnvelope.self, from: data).passkeys
            errors["passkeys"] = nil
        } catch { errors["passkeys"] = GrooAccountStore.message(for: error) }
    }

    private func loadDevices() async {
        do {
            let data = try await session.accountRequest(path: "v1/account/sessions")
            devices = try JSONDecoder().decode(DevicesEnvelope.self, from: data).sessions
            errors["devices"] = nil
        } catch { errors["devices"] = GrooAccountStore.message(for: error) }
    }

    private func loadConnectedApps() async {
        do {
            let data = try await session.accountRequest(path: "v1/account/connected-apps")
            connectedApps = try JSONDecoder().decode(AppsEnvelope.self, from: data).apps
            errors["apps"] = nil
        } catch { errors["apps"] = GrooAccountStore.message(for: error) }
    }

    private func loadTokens() async {
        do {
            let data = try await session.accountRequest(path: "v1/account/tokens")
            tokens = try JSONDecoder().decode(TokensEnvelope.self, from: data).tokens
            errors["tokens"] = nil
        } catch { errors["tokens"] = GrooAccountStore.message(for: error) }
    }

    // MARK: - Revoking

    /// Removes a passkey. The list is re-read rather than edited locally: the
    /// issuer decides what remains, and a local splice would disagree with it the
    /// moment two devices are doing this at once.
    public func deletePasskey(_ id: String) async {
        await revoke(id: id, path: "v1/account/passkeys/\(id)", key: "passkeys", reload: loadPasskeys)
    }

    public func revokeDevice(_ id: String) async {
        await revoke(id: id, path: "v1/account/sessions/\(id)", key: "devices", reload: loadDevices)
    }

    /// Takes the APPLICATION id, not the consent row's id — disconnecting a
    /// product kills the refresh tokens of every client that application owns.
    public func disconnectApp(_ applicationId: String) async {
        await revoke(
            id: applicationId,
            path: "v1/account/connected-apps/\(applicationId)",
            key: "apps",
            reload: loadConnectedApps
        )
    }

    public func revokeToken(_ id: String) async {
        await revoke(id: id, path: "v1/account/tokens/\(id)", key: "tokens", reload: loadTokens)
    }

    private func revoke(id: String, path: String, key: String, reload: () async -> Void) async {
        pendingRevoke = id
        errors[key] = nil
        do {
            _ = try await session.accountRequest(path: path, method: "DELETE")
            await reload()
        } catch {
            errors[key] = GrooAccountStore.message(for: error)
        }
        pendingRevoke = nil
    }
}

/// Parses the timestamps these lists carry.
///
/// The issuer stamps them with milliseconds, which a default `ISO8601DateFormatter`
/// REFUSES — it reads `2026-01-01T00:00:00Z` and returns nil for
/// `2026-01-01T00:00:00.000Z`. Every date here is the second form, so without the
/// fractional-seconds option every row silently loses its "last used" line.
///
/// A function rather than a shared static, because `ISO8601DateFormatter` is not
/// `Sendable` and a global one is a data race waiting for two sections to parse at
/// once. These lists are short; the allocation is not the cost that matters.
enum GrooTimestamp {
    static func parse(_ iso: String) -> Date? {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = formatter.date(from: iso) { return date }
        // A timestamp WITHOUT milliseconds is still valid ISO 8601, and refusing
        // it would be the same bug in the other direction.
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.date(from: iso)
    }
}
