# GrooAuthUI — a SwiftUI component library for `auth-swift`

**Date:** 2026-08-27
**Status:** design. Not implemented.
**Audience:** a reusable SDK. Used first by `bt/space` iOS and `gr/ios`, then by
customers.

---

## What this is for

`auth-swift` today is ten files of session, PKCE, keychain and discovery, and
**no UI at all**. Every consuming app therefore writes its own sign-in screen,
and gets no account management unless it sends people to a browser.

Both of our apps demonstrate the cost. `bt/space` had Clerk's `AuthView` and
`UserProfileView` and lost both in the migration — it now has a hand-rolled
button and a link out to `me.groo.dev/account`. `gr/ios` carries a 144-line
`LoginView` that every other adopter would end up writing again.

`@groo.dev/auth-react` already solved this for the web, and its shape is the
blueprint rather than something to invent:

| React | SwiftUI |
|---|---|
| `AuthProvider` / `useAuth` | `GrooAuthSession` (exists) + `@Observable` wrapper |
| `usePasskeys` `useDevices` `useConnectedApps` `useApiTokens` `useProfile` | one `@Observable` store each |
| `SignInScreen` `SignUpScreen` | `GrooSignInView` |
| `UserButton` | `GrooUserButton` |
| `UserProfile` + 5 tabs | `GrooAccountView` + sections |
| `ChangePassword` `RegisterPasskey` `SetupMfa` … | the same, as sheets |
| `--ga-*` CSS variables | `GrooAuthTheme` in `@Environment` |

## What is already built, and what is not

**Built:** all 22 `/v1/account/*` endpoints, WebAuthn registration and
authentication, and — as of 2026-08-27 — the
`/.well-known/apple-app-site-association` that makes native passkeys possible at
all. Nothing on the server blocks this work.

**Not built:** any SwiftUI in `auth-swift`.

## Scope: native where it shows, hosted where it does not

**Native:** sign-in (including passkeys), the account shell, and the lists —
passkeys, devices, connected apps, API tokens. These are where a native control
is visibly better than a web view, and where a token-bearing client can call the
API directly.

**Hosted, in a web view:** email change, password reset, recovery-code display,
MFA enrolment. Rare, flow-heavy, and heavy in copy that would immediately drift
from the React implementation.

The temptation for a reusable SDK is to build all 22 endpoints natively. It
should be resisted: each becomes a Swift call site maintained in parallel with a
React one, and they WILL diverge — this estate produced three comments in a
single day that asserted the opposite of the code beneath them.

## Theming: a struct, plus an escape hatch

SwiftUI has no equivalent of the CSS custom properties the React SDK themes
with. Three options were considered:

- **Opinionated, unstyleable views.** Fastest, and wrong for a reusable SDK: the
  first adopter whose brand is not green forks it.
- **Headless.** Ship the stores, let the app ship every view. Maximum
  flexibility, and it abandons the reason anyone adopts a UI library.
- **Theme struct + public stores.** Styled views that look right by default,
  themed through a fixed token set, with the stores public so an app that wants
  its own look builds on the same logic.

The third. It is also what Clerk's appearance API settles on, and adopters
arriving from Clerk will expect it.

```swift
struct GrooAuthTheme {
    var accent: Color, canvas: Color, surface: Color, ink: Color, muted: Color
    var danger: Color, line: Color
    var cornerRadius: CGFloat
    var titleFont: Font, bodyFont: Font
}
// .environment(\.grooAuthTheme, .init(accent: .indigo))
```

Token names mirror `--ga-*` deliberately, so the two SDKs can be themed from one
brand definition.

Every default colour is appearance-adaptive, via `Color.grooAdaptive(light:dark:)`.
A single fixed palette was the first attempt and it was wrong for the same reason
unstyleable views are: Space's app is dark end to end, so a fixed light default
rendered its sign-in screen as a white flash before a black app — and that is the
default every adopter gets before they configure anything. A colour an app
supplies is still taken exactly as given; nothing derives a second appearance
behind its back.

## Passkeys

The prerequisite is met: `me.groo.dev` and `me.groo.space` now serve
`webcredentials` naming each workspace's iOS app, derived from the `ios` client
rows' `bundle_id` + `apple_team_id`.

An adopting app still needs `webcredentials:<their issuer host>` in its
Associated Domains entitlement, and an `ios` client row carrying its bundle and
team id. **Both belong in the SDK's setup documentation**, because the failure
mode is silent — a passkey prompt that simply never appears, with nothing logged
on either side.

Sign-in uses `ASAuthorizationPlatformPublicKeyCredentialProvider` against
`/v1/auth/passkey/authenticate/options|verify`; registration the same against
the `/register/` pair.

## Scopes — two changes needed before any of this works

1. **The iOS client requests four scopes** (`openid profile email
   offline_access`). Account management needs `accounts:profile`,
   `accounts:passkeys`, `accounts:devices`, `accounts:apps`, `accounts:tokens`.
2. **The `groo.space` application permits only** `accounts:profile` and
   `accounts:handoff` of that set, so four would be refused even if requested.
   A data change to `applications.allowed_scopes`.

The SDK should request only what the consuming app actually uses: an app with no
token management should not be asking for `accounts:tokens`, and consent screens
that list unused permissions teach people to approve without reading.

## Order of work

1. `GrooAuthTheme` and the `@Observable` session wrapper. Everything else sits
   on these, and getting the theming contract wrong is the expensive mistake.
2. `GrooSignInView`, password only. Replaces `gr/ios`'s LoginView and
   `bt/space`'s SignInView — two real adopters before any customer.
3. Passkey sign-in, added to that view.
4. `GrooUserButton` + `GrooAccountView` shell, with the profile section.
5. The list sections: passkeys, devices, connected apps, tokens.
6. Hosted web-view sheets for the long tail.

Each step lands in both apps before the next begins. A component library with
one consumer is a guess; with two it is a contract.

## Open questions

- **Sign-UP**: hosted or native? Sign-up carries workspace-approval states
  (`blocked=1` awaiting an administrator, which our own signup flow uses), and
  those screens are copy-heavy. Leaning hosted for v1.
- **Does `gr/ios`'s AutoFill extension need any of this?** It authenticates
  through `SharedGrooAuthFactory` and has no UI of its own; probably untouched,
  but it shares a keychain and should be checked before the session wrapper
  changes.
