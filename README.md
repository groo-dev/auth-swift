# GrooAuth

[![CI](https://github.com/groo-dev/auth-swift/actions/workflows/release.yml/badge.svg)](https://github.com/groo-dev/auth-swift/actions/workflows/release.yml)
![Platforms](https://img.shields.io/badge/platforms-iOS%2018%20%7C%20macOS%2014-blue)
![Swift](https://img.shields.io/badge/Swift-6.0-orange)
![License](https://img.shields.io/badge/license-Proprietary-red)

A small, dependency-free **OpenID Connect (OIDC) client for Apple platforms** — authorization code flow with PKCE, built for native iOS and macOS apps. It handles the whole sign-in lifecycle (login, token storage, refresh, revoking sign-out) behind a tiny `actor` API.

Built for [Groo](https://groo.dev) Accounts. It implements standard OIDC — discovery, public (PKCE) clients, and ES256-signed ID tokens. The source is public so it can be resolved as a Swift Package in CI, but it is **proprietary, not open source** (see [License](#license)).

```swift
let session = GrooAuthSession(
    config: config,
    tokenStore: KeychainTokenStore(service: "com.example.app.auth", accessGroup: nil)
)

let user  = try await session.signIn(presentationAnchor: window)   // opens the login sheet
let token = try await session.accessToken()                        // fresh bearer token, auto-refreshed
await session.signOut()                                            // revokes server-side + clears the keychain
```

## Features

- **Authorization code + PKCE** (S256), with `state` and `nonce` for CSRF/replay protection.
- **`ASWebAuthenticationSession` login** — the callback custom scheme is owned by the session, so **no `CFBundleURLTypes` entry in `Info.plist` is required**.
- **ID token verification** — ES256 (P-256) signatures checked against the provider's JWKS, with automatic re-fetch on key rotation (unknown `kid`).
- **Automatic, single-flight token refresh** — concurrent callers awaiting `accessToken()` share one refresh; near-expiry tokens are refreshed transparently.
- **Revoking sign-out** — [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009) revocation tells the server to invalidate the whole refresh-token family, not just clear the device.
- **Keychain-backed storage** — `kSecAttrAccessibleAfterFirstUnlock`, with optional access-group sharing for app extensions.
- **Observable auth state** — subscribe to sign-in/sign-out transitions via an `AsyncStream`.
- **Concurrency-safe** — an `actor` with `Sendable` types throughout; builds clean under the Swift 6 language mode.
- **Zero third-party dependencies** — only `Foundation`, `CryptoKit`, `AuthenticationServices`, and `Security`.

## Requirements

| | |
|---|---|
| Platforms | iOS 18.0+ · macOS 14.0+ |
| Toolchain | Swift 6.0+ / Xcode 16+ |
| Provider  | OIDC with discovery (`/.well-known/openid-configuration`), public PKCE clients, and **ES256**-signed ID tokens |

## Installation

### Swift Package Manager

Add the package to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/groo-dev/auth-swift.git", from: "0.0.2")
],
targets: [
    .target(name: "YourApp", dependencies: [
        .product(name: "GrooAuth", package: "auth-swift")
    ])
]
```

### Xcode

**File → Add Package Dependencies…**, enter `https://github.com/groo-dev/auth-swift.git`, and add the **GrooAuth** library to your app target.

## Quick start

### 1. Configure

```swift
import GrooAuth

let config = GrooAuthConfig(
    issuer: URL(string: "https://accounts.groo.dev")!,   // your OIDC issuer
    clientId: "app_your_public_client_id",
    redirectURI: "com.example.app://oauth-callback",     // a custom scheme your app owns
    scopes: ["openid", "profile", "email", "offline_access"],
    keychainService: "com.example.app.auth"              // keychain service name for stored tokens
)
```

> **Redirect URI.** Use a private-use scheme (e.g. `com.example.app://oauth-callback`) registered with your provider for this client. You do **not** need to add it to `Info.plist` — `ASWebAuthenticationSession` intercepts the callback. Request the `offline_access` scope to receive a refresh token.

### 2. Create a session

```swift
let store   = KeychainTokenStore(service: config.keychainService,
                                 accessGroup: config.keychainAccessGroup)
let session = GrooAuthSession(config: config, tokenStore: store)
```

Keep a single `GrooAuthSession` for the app's lifetime.

### 3. Sign in

`signIn` presents the provider's login page in an `ASWebAuthenticationSession` anchored to a window you supply — a `UIWindow` on iOS, an `NSWindow` on macOS.

```swift
do {
    let user = try await session.signIn(presentationAnchor: window)
    print("Signed in as \(user.email ?? user.sub)")
} catch GrooAuthError.userCancelled {
    // user dismissed the sheet
} catch {
    // show error.localizedDescription
}
```

### 4. Call your APIs

`accessToken()` returns a valid bearer token, refreshing transparently if it is near expiry:

```swift
var request = URLRequest(url: apiURL)
request.setValue("Bearer \(try await session.accessToken())",
                 forHTTPHeaderField: "Authorization")
```

If the server still rejects a token that looked valid, force one refresh and retry exactly once:

```swift
var (data, response) = try await URLSession.shared.data(for: request)
if (response as? HTTPURLResponse)?.statusCode == 401 {
    let fresh = try await session.forceRefreshAccessToken()
    request.setValue("Bearer \(fresh)", forHTTPHeaderField: "Authorization")
    (data, response) = try await URLSession.shared.data(for: request)
}
```

### 5. Observe auth state

```swift
Task {
    for await state in await session.stateStream {
        switch state {
        case .signedOut:            break   // update UI to the logged-out state
        case .signedIn(let user):   break   // update UI with the user
        }
    }
}
```

`currentState()` returns the current value on demand at any point.

### 6. Sign out

```swift
switch await session.signOut() {
case .revokedAndCleared:
    break   // tokens revoked server-side and removed locally
case .clearedButRevokeFailed(let reason):
    break   // signed out locally, but server revocation failed (e.g. offline) — log `reason`
}
```

`signOut` never throws: the device is always signed out locally regardless of whether server-side revocation succeeded.

## API overview

| Type | Role |
|---|---|
| `GrooAuthSession` (`actor`) | The entry point — `signIn`, `signOut`, `accessToken`, `forceRefreshAccessToken`, `currentState`, `stateStream`. |
| `GrooAuthConfig` | Issuer, client ID, redirect URI, scopes, keychain service/access group. |
| `GrooUser` | `sub`, `email`, `name` from the verified ID token. |
| `GrooAuthState` | `.signedOut` / `.signedIn(GrooUser)`. |
| `SignOutResult` | `.revokedAndCleared` / `.clearedButRevokeFailed(reason:)`. |
| `GrooAuthError` | Typed errors, all `LocalizedError`. |
| `TokenStoring` | Protocol for token persistence. |
| `KeychainTokenStore` | Production store (Keychain, after-first-unlock). |
| `InMemoryTokenStore` | Non-persistent store — handy for tests and previews. |
| `WebAuthenticating` | Protocol over `ASWebAuthenticationSession` (inject a fake in tests). |

## Error handling

`signIn`, `accessToken`, and `forceRefreshAccessToken` throw `GrooAuthError`. Every case conforms to `LocalizedError`, and messages intentionally surface the underlying detail (server error codes, validation messages) so you can show `error.localizedDescription` directly:

| Case | Meaning |
|---|---|
| `.userCancelled` | The user dismissed the login sheet. |
| `.transport(String)` | Network/URL error. |
| `.protocolError(OAuthProtocolError)` | The provider returned an OAuth `error` response. |
| `.invalidResponse(String)` | A malformed or unexpected response. |
| `.stateMismatch` | The `state` returned didn't match — request rejected. |
| `.idTokenInvalid(String)` | The ID token failed signature/claim verification. |
| `.signedOut` | No valid session (e.g. refresh token expired/revoked). |

## Sharing tokens with an app extension

To let an extension (e.g. AutoFill, a widget, a share extension) read the same tokens, put both targets in a shared Keychain access group and pass it through:

```swift
let config = GrooAuthConfig(
    // …
    keychainService: "com.example.app.auth",
    keychainAccessGroup: "TEAMID.com.example.app.shared"
)
```

## Testing

Everything the session touches is a protocol, so it's straightforward to drive in tests without a network or browser: inject an `InMemoryTokenStore`, a fake `WebAuthenticating`, and a stub transport. The package's own suite (`swift test`) exercises the full sign-in / refresh / sign-out / state-stream flows this way.

## How it works

1. `signIn` generates a PKCE `verifier`/`challenge`, a random `state`, and a `nonce`, then opens the provider's `/authorize` page via `ASWebAuthenticationSession`.
2. On the redirect back to your custom scheme, it validates `state`, exchanges the code (+ `verifier`) at the token endpoint, and **verifies the ID token** (ES256 signature via JWKS, plus `iss` / `aud` / `exp` / `nonce`).
3. Tokens are stored in the Keychain. `accessToken()` serves the cached token and refreshes it near expiry through a single shared task.
4. `signOut` calls the revocation endpoint (RFC 7009) and clears local storage.

## License

**Proprietary — all rights reserved.** Copyright © 2026 Groo. The source is
publicly visible to support dependency resolution in CI, but no rights to use,
copy, modify, or distribute it are granted. See [LICENSE](LICENSE).
