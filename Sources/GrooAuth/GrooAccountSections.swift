import Foundation

/// Which account sections an app shows, and the scopes they need.
///
/// Lives in `GrooAuth` rather than `GrooAuthUI` even though only the UI renders
/// them, because `requiredScopes` is used to BUILD a `GrooAuthConfig` — and in
/// `gr/ios` that construction is shared with an AutoFill extension which must
/// never link SwiftUI. A type that forces the wrong module on a caller is the
/// wrong type, wherever it feels like it belongs.
public struct GrooAccountSections: OptionSet, Sendable {
    public let rawValue: Int
    public init(rawValue: Int) { self.rawValue = rawValue }

    /// Needs `accounts:passkeys`.
    public static let passkeys = GrooAccountSections(rawValue: 1 << 0)
    /// Needs `accounts:devices`.
    public static let devices = GrooAccountSections(rawValue: 1 << 1)
    /// Needs `accounts:apps`.
    public static let connectedApps = GrooAccountSections(rawValue: 1 << 2)
    /// Needs `accounts:tokens`.
    public static let tokens = GrooAccountSections(rawValue: 1 << 3)

    public static let all: GrooAccountSections = [.passkeys, .devices, .connectedApps, .tokens]

    /// The scopes these sections require, so an app can build its scope list from
    /// the sections it shows instead of keeping the two in step by hand.
    public var requiredScopes: [String] {
        var scopes: [String] = []
        if contains(.passkeys) { scopes.append("accounts:passkeys") }
        if contains(.devices) { scopes.append("accounts:devices") }
        if contains(.connectedApps) { scopes.append("accounts:apps") }
        if contains(.tokens) { scopes.append("accounts:tokens") }
        return scopes
    }
}

