# GrooAuthUI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans.

**Design:** `DESIGN-UI.md`

**Goal:** A reusable SwiftUI component library for `auth-swift`, adopted by
`gr/ios` and `bt/space` before any customer sees it.

## Global Constraints

- **`GrooAuthUI` is a SEPARATE product from `GrooAuth`.** `gr/ios`'s AutoFill
  extension imports `GrooAuth` and calls only `accessToken()`; it must never be
  made to link SwiftUI it does not use. Verified 2026-08-27: the extension uses
  `makeTokenOnlySession()` and has no UI.
- **`GrooAuthSession` is additive-only.** It is an actor with shipped consumers
  in two apps and an app extension. The wrapper observes it; it does not change
  it.
- **Every step lands in BOTH apps before the next begins.** A component library
  with one consumer is a guess.
- Passkeys need `webcredentials:<issuer host>` in the adopting app's Associated
  Domains, and an `ios` client row with `bundle_id` + `apple_team_id`. Both are
  silent failures — document them in the README as they are implemented, not
  afterwards.

---

### Task 1: `GrooAuthTheme` — DONE

**Files:** Create `Sources/GrooAuthUI/GrooAuthTheme.swift`, modify `Package.swift`.

Token names mirror the React SDK's `--ga-*` so one brand definition can drive
both.

- [x] **Step 1: Add the product and target**

```swift
products: [
    .library(name: "GrooAuth", targets: ["GrooAuth"]),
    .library(name: "GrooAuthUI", targets: ["GrooAuthUI"]),
],
targets: [
    .target(name: "GrooAuth"),
    .target(name: "GrooAuthUI", dependencies: ["GrooAuth"]),
    .testTarget(name: "GrooAuthTests", dependencies: ["GrooAuth"]),
    .testTarget(name: "GrooAuthUITests", dependencies: ["GrooAuthUI"]),
]
```

- [x] **Step 2: The theme, with a default that looks deliberate**

```swift
public struct GrooAuthTheme: Sendable {
    public var accent: Color, onAccent: Color
    public var canvas: Color, surface: Color
    public var ink: Color, muted: Color, line: Color
    public var danger: Color
    public var cornerRadius: CGFloat
    public var titleFont: Font, bodyFont: Font

    public static let groo = GrooAuthTheme(/* mirrors --ga-* */)
}

public extension EnvironmentValues {
    @Entry var grooAuthTheme: GrooAuthTheme = .groo
}
```

- [x] **Step 3: Test that a supplied theme reaches a view.** The point of the
      contract is that it is overridable; assert that, not the default values.
- [x] **Step 4: Commit.**

---

### Task 2: `GrooAuthController` — the observable session wrapper — DONE

**Files:** Create `Sources/GrooAuthUI/GrooAuthController.swift`, `Tests/GrooAuthUITests/GrooAuthControllerTests.swift`.

`GrooAuthSession` is an actor; SwiftUI needs main-actor observable state. This is
exactly the `AuthService` both apps hand-rolled — `bt/space` and `gr/ios` each
wrote their own, which is the duplication this library exists to end.

- [x] **Step 1: Write the failing test** — a controller fed a stubbed session
      publishes `signedIn` and exposes the user, and starts `isLoading`.

`GrooAuthSession` is a concrete actor, so the test needs a seam. Use
`InMemoryTokenStore` and a stub `WebAuthenticating`, both already public — no
production change to create a seam.

- [x] **Step 2: Implement**

```swift
@MainActor @Observable
public final class GrooAuthController {
    public private(set) var user: GrooUser?
    public private(set) var isSignedIn = false
    /// True until the keychain has been read once. Distinguishes "signed out"
    /// from "not known yet" — without it every launch flashes the sign-in screen
    /// at an already-signed-in person.
    public private(set) var isLoading = true
    public let session: GrooAuthSession   // public: the escape hatch
    ...
}
```

- [x] **Step 3: Run, expect pass. Step 4: Commit.**

---

### Task 3: `GrooSignInView` — password only — DONE

**Files:** Create `Sources/GrooAuthUI/GrooSignInView.swift`.

- [x] Presents the hosted authorize flow via `session.signIn(presentationAnchor:)`,
      resolving the anchor from the foreground window scene.
- [x] Surfaces errors rather than swallowing them. `GrooAuthError.userCancelled`
      is NOT an error to show — the person just closed the sheet.
- [x] Themed throughout; no hardcoded colour.
- [x] **Adopt in `gr/ios`**, deleting `LoginView.swift` (144 lines), and in
      `bt/space`, deleting `SignInView.swift`. Build and run both.
- [x] Commit per app.

**Shipped as 0.1.0, then 0.1.1.** The default palette went out fixed and light,
which is a white flash in front of `bt/space` — dark end to end — and in front of
every adopter whose app is dark. 0.1.1 makes every default token adaptive via a
public `Color.grooAdaptive(light:dark:)`; a colour an app supplies is still taken
exactly as given.

`gr/ios` proves the theme contract with a second brand: `GrooAuthTheme.grooApp`
sets `accent` to its violet and maps the rest to system semantic colours.
`bt/space` configures nothing and takes the default.

Two things learned while verifying, both worth knowing before Task 4:

- **The `Groo` scheme's build action is Release.** A bare `xcodebuild build`
  writes `Release-iphonesimulator`, so installing from `Debug-iphonesimulator`
  runs a stale binary that reports itself as a successful build. Pass
  `-configuration Debug` explicitly, or install from the Release path.
- **`gr/ios` Debug cannot complete sign-in and never could.** Its redirect,
  `dev.groo.ios.debug://oauth-callback`, is registered on no client row — all
  four `dev.groo.ios` clients carry only `dev.groo.ios://oauth-callback`. Task 4
  wants device testing, so this has to be settled first: either register the
  debug redirect or test Release. Recorded in `runtime/docs/PENDING.md`.

---

### Task 4: Passkey sign-in — DONE

**Files:** Modify `Sources/GrooAuthUI/GrooSignInView.swift`; create
`Sources/GrooAuthUI/PasskeyAuthenticator.swift`.

- [x] `ASAuthorizationPlatformPublicKeyCredentialProvider` against
      `/v1/auth/passkey/authenticate/options` then `/verify`.
- [x] The relying party is the issuer host, from `GrooAuthConfig.issuer`. Never a
      literal.
- [x] Offer the passkey button only when one may exist; fall back silently to
      password when the platform has none.
- [x] **Test on a device**, not the simulator. Verify against BOTH apps, since
      each has its own bundle and therefore its own AASA entry.
- [x] Document the two silent prerequisites in the README.

**Shipped as 0.2.0, and it needed the API to change.** The plan assumed
`/v1/auth/passkey/authenticate/verify` could hand an app what it needs. It cannot:
it answers with a session cookie and a user object, and an app can use neither.

Minting a code in the passkey route was refused — `/authorize` is ~270 lines
deciding scope attribution, per-application ceilings, resource indicators,
max_age, AAL, entitlement and consent, and a second copy of that is the copy that
drifts. Instead the assertion buys a one-time ticket and the ticket buys one trip
through `/authorize`, so every gate runs where it already ran. See
`runtime` commits 3ab7a05 and 54ce23a.

Verified end to end against production in `gr/ios`, Release, with a passkey
enrolled for `e2e@groo.dev`: platform sheet → assertion → ticket → code → tokens,
no browser at any point. `bt/space` is verified as far as the workspace allows —
button, ceremony, platform sheet — but no passkey has been enrolled for
`me.groo.space` on this machine and there is no account here to enrol one with.

Two things learned, both recorded in `runtime/docs/PENDING.md`:

- A global scope added to a client AFTER consent was granted invalidates every
  existing consent row for that application, because a global joins every
  application's wanted set. `offline_access` did exactly this to a live account,
  and the symptom is a consent screen nobody expected.
- The passkey button is offered until an attempt reports `passkeyUnavailable`,
  then hidden. There is no way to ASK the platform whether a credential exists —
  it answers only by running the ceremony.

---

### Task 5: `GrooUserButton` and the account shell

Blocked on the two data prerequisites below. Sections: profile, security
(passkeys, devices), connected apps, tokens, danger. Each list is an
`@Observable` store over the existing `/v1/account/*` endpoints.

---

## Prerequisites for Task 5, both data rather than code

1. **Client scopes.** The iOS clients request `openid profile email
   offline_access`. Account management needs `accounts:profile`,
   `accounts:passkeys`, `accounts:devices`, `accounts:apps`, `accounts:tokens` —
   and only those an adopting app actually uses.
2. **Application ceiling.** `groo.space` permits `accounts:profile` and
   `accounts:handoff` only, so four of the five would be refused even if
   requested. Widen `applications.allowed_scopes`.

## Decided

- **Sign-up stays hosted for v1.** It carries workspace-approval states — our own
  signup leaves an account `blocked=1` pending an administrator, which is correct
  and copy-heavy — and it is rare next to sign-in. Native sign-up would be the
  most words for the least benefit.
- **The AutoFill extension is untouched.** It calls `accessToken()` on a
  token-only session and has no UI. The separate-product rule is what keeps it
  that way.
