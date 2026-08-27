# GrooAuth

[![CI](https://github.com/groo-dev/auth-swift/actions/workflows/release.yml/badge.svg)](https://github.com/groo-dev/auth-swift/actions/workflows/release.yml)
![Platforms](https://img.shields.io/badge/platforms-iOS%2018%20%7C%20macOS%2014-blue)
![Swift](https://img.shields.io/badge/Swift-6.0-orange)
![License](https://img.shields.io/badge/license-MIT-green)

A small, dependency-free **OpenID Connect (OIDC) client for Apple platforms** — authorization code flow with PKCE, built for native iOS and macOS apps. It handles the whole sign-in lifecycle (login, token storage, refresh, revoking sign-out) behind a tiny `actor` API.

Built for [Groo](https://groo.dev) Accounts, and usable against any provider that implements standard OIDC — discovery, public (PKCE) clients, and ES256-signed ID tokens. **MIT licensed** (see [License](#license)).

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

### 3b. Sign in with a passkey, natively

`signInWithPasskey` runs the platform's own ceremony — Face ID, no browser at any
point — and ends holding the same tokens `signIn` produces.

```swift
do {
    let user = try await session.signInWithPasskey(presentationAnchor: window)
} catch GrooAuthError.passkeyUnavailable {
    // No passkey on this device. Not an error: offer signIn instead.
} catch GrooAuthError.interactionRequired {
    // The issuer needs a screen this app has none of — consent, most often, and
    // only ever once. Fall back to signIn, which is where those screens live.
} catch GrooAuthError.userCancelled {
    // Sheet dismissed.
}
```

Under the hood the assertion buys a one-time ticket and the ticket buys one trip
through `/authorize`, so the issuer decides entitlement, consent and scope in the
same place it does for a browser. Nothing about that is visible to you; what is
visible is that two of the errors above mean "use `signIn`", not "something broke".

**Two prerequisites, and both fail silently.** Neither produces an error message
that names the cause — the passkey sheet simply reports that there are no
credentials.

1. **Associated domains.** The adopting app needs
   `webcredentials:<your issuer host>` in its Associated Domains entitlement — for
   example `webcredentials:me.groo.dev`. Without it the platform will not look for
   a passkey scoped to that relying party, and finds none.
2. **An `ios` client row carrying `bundle_id` and `apple_team_id`.** The issuer
   serves `/.well-known/apple-app-site-association` from those two columns, and
   Apple refuses an app's claim to a domain that does not name it. A row missing
   either column leaves the app out of the file, with the same symptom.

The relying party is always derived from `GrooAuthConfig.issuer`, never written
down as a literal — a hardcoded host would work for exactly one workspace.

### 3c. The account screen

`GrooUserButton` opens `GrooAccountView`: who you are signed in as, an editable
name and phone, a link to the hosted console, and sign-out.

```swift
GrooUserButton(
    controller: controller,
    consoleURL: URL(string: "https://me.groo.dev/account"),
    showsLabel: true   // avatar + name + email, for a settings row
)
```

**Requires the `accounts:profile` scope.** Add it to `GrooAuthConfig.scopes`; it
is a global scope, so it is granted per request rather than per application. Note
that adding ANY scope a client did not previously request means every existing
user is asked to approve again at their next sign-in — there is no way to widen a
grant silently, and that is the point.

Without it, `/v1/account/profile` answers 403 and the screen says which scope is
missing rather than showing an empty form.

Passkeys, devices, connected apps and API tokens are deliberately NOT native.
Each is a list with its own destructive actions, and a half-built version of one
is worse than an honest link to the finished one — which is what `consoleURL` is.
Pass `nil` to hide the link entirely.

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
| `GrooAuthSession` (`actor`) | The entry point — `signIn`, `signInWithPasskey`, `signOut`, `accessToken`, `forceRefreshAccessToken`, `accountRequest`, `currentState`, `stateStream`. |
| `GrooAuthConfig` | Issuer, client ID, redirect URI, scopes, keychain service/access group. |
| `GrooUser` | `sub`, `email`, `name` from the verified ID token. |
| `GrooAuthState` | `.signedOut` / `.signedIn(GrooUser)`. |
| `SignOutResult` | `.revokedAndCleared` / `.clearedButRevokeFailed(reason:)`. |
| `GrooAuthError` | Typed errors, all `LocalizedError`. |
| `TokenStoring` | Protocol for token persistence. |
| `KeychainTokenStore` | Production store (Keychain, after-first-unlock). |
| `InMemoryTokenStore` | Non-persistent store — handy for tests and previews. |
| `WebAuthenticating` | Protocol over `ASWebAuthenticationSession` (inject a fake in tests). |
| `PasskeyAuthenticating` | Protocol over `ASAuthorizationController` (inject a fake in tests). |
| `PasskeyAssertion` | One passkey assertion, base64url, as the server's verifier expects. |
| `GrooUserButton` | Avatar button that opens the account screen. |
| `GrooAccountView` | The account screen itself, if you want to present it yourself. |
| `GrooAccountStore` | `@Observable` profile load/save over `/v1/account/profile`. |
| `GrooAvatar` | The initials circle, on its own. |

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
| `.passkeyUnavailable` | No passkey on this device for the issuer. Offer `signIn`. |
| `.interactionRequired(OAuthProtocolError)` | The issuer needs a screen the app has none of. Fall back to `signIn`. |
| `.insufficientScope(String)` | The token lacks a scope the request needs, and names it. |

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

**MIT.** Copyright © 2026 Groo. See [LICENSE](LICENSE).

Relicensed from proprietary on 2026-08-23. It was previously public only so
Swift Package Manager could resolve it in CI, which granted no rights to
anyone; it is now genuinely usable.
