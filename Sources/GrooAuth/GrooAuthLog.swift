import os

/// Diagnostic-only loggers for the sign-in path. `.notice` marks flow steps
/// (so they show by default in Console.app/Xcode without debug-level
/// filtering); `.error` marks failures. Every interpolated value here is
/// explicitly reviewed for secrecy — see call sites — and marked
/// `privacy: .public` only when it is not a long-lived secret (raw
/// access/refresh/id tokens, the PKCE code verifier, and the client secret
/// are never logged, full stop).
enum GrooAuthLog {
    static let signin = Logger(subsystem: "dev.groo.auth", category: "signin")
    static let web    = Logger(subsystem: "dev.groo.auth", category: "web")
    static let token  = Logger(subsystem: "dev.groo.auth", category: "token")
}
