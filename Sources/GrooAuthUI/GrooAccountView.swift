import GrooAuth
import SwiftUI

/// The account screen: who you are signed in as, the fields you can edit, and
/// the way out.
///
/// It is deliberately not a replica of the hosted console. Passkeys, devices,
/// connected apps and tokens all live there and are reached by a link, because
/// each is a list with its own destructive actions and a half-built version of
/// one is worse than an honest link to the finished one. What is native here is
/// what an app is actually asked for: the person's name, and signing out.
public struct GrooAccountView: View {
    private let controller: GrooAuthController
    private let consoleURL: URL?
    private let sections: GrooAccountSections

    @Environment(\.grooAuthTheme) private var theme
    @Environment(\.dismiss) private var dismiss
    @Environment(\.openURL) private var openURL

    @State private var store: GrooAccountStore?
    @State private var lists: GrooAccountListsStore?
    @State private var isRegisteringPasskey = false
    @State private var passkeyNotice: String?
    /// The row awaiting confirmation. Revoking a device or a passkey is not
    /// undoable, so it is never one tap.
    @State private var confirming: PendingRevoke?
    @State private var name = ""
    @State private var phone = ""
    /// Stops a reload from overwriting what someone is in the middle of typing.
    @State private var hasLoadedFields = false
    @State private var isSigningOut = false

    /// - Parameter consoleURL: the hosted account page, for everything this
    ///   screen deliberately does not do. Pass `nil` to hide the link — an app
    ///   whose issuer has no console should not offer a dead one.
    /// - Parameter sections: which security lists to show. Each costs a scope, so
    ///   this is the app's decision — see `GrooAccountSections.requiredScopes`.
    public init(
        controller: GrooAuthController,
        consoleURL: URL? = nil,
        sections: GrooAccountSections = []
    ) {
        self.controller = controller
        self.consoleURL = consoleURL
        self.sections = sections
    }

    /// What a destructive row is asking to remove. One type for all four lists,
    /// because the confirmation differs only in its words.
    struct PendingRevoke: Identifiable {
        enum Kind { case passkey, device, app, token }
        let id: String
        let kind: Kind
        let label: String

        var title: String {
            switch kind {
            case .passkey: return "Remove this passkey?"
            case .device: return "Sign out this device?"
            case .app: return "Disconnect \(label)?"
            case .token: return "Revoke this token?"
            }
        }

        var message: String {
            switch kind {
            case .passkey:
                return "You will not be able to sign in with it again. Make sure you have another way in first."
            case .device:
                return "It will be signed out immediately."
            case .app:
                return "\(label) loses access until you approve it again, and its tokens stop working now."
            case .token:
                return "Anything using it stops working immediately."
            }
        }

        var action: String { kind == .device ? "Sign Out" : "Remove" }
    }

    public var body: some View {
        NavigationStack {
            Form {
                identitySection
                profileSection
                if sections.contains(.passkeys) { passkeysSection }
                if sections.contains(.devices) { devicesSection }
                if sections.contains(.connectedApps) { connectedAppsSection }
                if sections.contains(.tokens) { tokensSection }
                if let consoleURL { consoleSection(consoleURL) }
                signOutSection
            }
            .navigationTitle("Account")
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .confirmationDialog(
                confirming?.title ?? "",
                isPresented: Binding(get: { confirming != nil }, set: { if !$0 { confirming = nil } }),
                presenting: confirming
            ) { pending in
                Button(pending.action, role: .destructive) { revoke(pending) }
                Button("Cancel", role: .cancel) { confirming = nil }
            } message: { pending in
                Text(pending.message)
            }
            .task {
                let store = store ?? GrooAccountStore(session: controller.session)
                self.store = store
                if !sections.isEmpty {
                    let lists = lists ?? GrooAccountListsStore(session: controller.session, sections: sections)
                    self.lists = lists
                    // Not awaited before the profile: the profile is the header,
                    // and making it wait on four list fetches would leave the
                    // screen blank for the slowest of them.
                    Task { await lists.load() }
                }
                await store.load()
                // Once. A later refresh must not reach into a field being typed.
                if !hasLoadedFields, let profile = store.profile {
                    name = profile.name ?? ""
                    phone = profile.phone ?? ""
                    hasLoadedFields = true
                }
            }
        }
    }

    // MARK: - Sections

    private var identitySection: some View {
        Section {
            HStack(spacing: 12) {
                GrooAvatar(name: displayName, email: email, size: 52)
                VStack(alignment: .leading, spacing: 2) {
                    Text(displayName).font(.headline).foregroundStyle(theme.ink)
                    if let email {
                        HStack(spacing: 4) {
                            Text(email).font(.subheadline).foregroundStyle(theme.muted)
                            // Shown only when TRUE. An unverified address is not a
                            // problem this screen can solve, and a warning badge
                            // with no action beside it is just an accusation.
                            if store?.profile?.emailVerified == true {
                                Image(systemName: "checkmark.seal.fill")
                                    .font(.caption)
                                    .foregroundStyle(theme.accent)
                                    .accessibilityLabel("Verified")
                            }
                        }
                    }
                }
            }
            .padding(.vertical, 4)
        }
    }

    private var profileSection: some View {
        Section {
            LabeledContent("Name") {
                TextField("Your name", text: $name)
                    .multilineTextAlignment(.trailing)
                    .textContentType(.name)
                    .accessibilityIdentifier("grooAccount.name")
            }
            LabeledContent("Phone") {
                TextField("Optional", text: $phone)
                    .multilineTextAlignment(.trailing)
                    .textContentType(.telephoneNumber)
                    .accessibilityIdentifier("grooAccount.phone")
            }
            Button(action: save) {
                HStack {
                    if store?.isSaving == true { ProgressView().controlSize(.small) }
                    Text("Save")
                }
            }
            .disabled(store?.isSaving == true || !hasEdits)
            .accessibilityIdentifier("grooAccount.save")
        } header: {
            Text("Profile")
        } footer: {
            if let error = store?.error, !error.isEmpty {
                Text(error)
                    .foregroundStyle(theme.danger)
                    .accessibilityIdentifier("grooAccount.error")
            }
        }
    }

    // MARK: - Security lists

    private var passkeysSection: some View {
        Section {
            ForEach(lists?.passkeys ?? []) { passkey in
                row(
                    title: passkey.name ?? "Passkey",
                    detail: passkeyDetail(passkey),
                    id: passkey.id,
                    revoke: PendingRevoke(id: passkey.id, kind: .passkey, label: passkey.name ?? "this passkey")
                )
            }
            Button(action: registerPasskey) {
                HStack {
                    if isRegisteringPasskey { ProgressView().controlSize(.small) }
                    Label("Add a passkey", systemImage: "plus.circle")
                }
            }
            .disabled(isRegisteringPasskey)
            .accessibilityIdentifier("grooAccount.addPasskey")
        } header: {
            Text("Passkeys")
        } footer: {
            // The only account action a console cannot do for you, which is why
            // it is here rather than behind the link.
            listFooter(
                key: "passkeys",
                empty: lists?.passkeys.isEmpty == true ? "Add a passkey to sign in with Face ID instead of a password." : nil,
                extra: passkeyNotice
            )
        }
    }

    private var devicesSection: some View {
        Section {
            ForEach(lists?.devices ?? []) { device in
                row(
                    title: device.deviceInfo ?? "Unknown browser",
                    detail: [device.ipAddress, shortDate(device.lastActive).map { "last active \($0)" }]
                        .compactMap { $0 }
                        .joined(separator: " · "),
                    id: device.id,
                    revoke: PendingRevoke(id: device.id, kind: .device, label: device.deviceInfo ?? "this device")
                )
            }
        } header: {
            Text("Devices")
        } footer: {
            // This app is NOT in the list and cannot be: these are browser
            // sessions, and the app holds tokens. Saying so beats leaving someone
            // hunting for the device in their hand.
            listFooter(
                key: "devices",
                empty: lists?.devices.isEmpty == true ? "No browser sessions. This app signs in with tokens, so it does not appear here." : "This app signs in with tokens, so it does not appear here."
            )
        }
    }

    private var connectedAppsSection: some View {
        Section {
            ForEach(lists?.connectedApps ?? []) { app in
                row(
                    title: app.appName,
                    detail: shortDate(app.lastAccessedAt).map { "last used \($0)" } ?? "",
                    id: app.applicationId,
                    revoke: PendingRevoke(id: app.applicationId, kind: .app, label: app.appName)
                )
            }
        } header: {
            Text("Connected apps")
        } footer: {
            listFooter(
                key: "apps",
                empty: lists?.connectedApps.isEmpty == true ? "Nothing is connected to your account." : nil
            )
        }
    }

    private var tokensSection: some View {
        Section {
            ForEach(lists?.tokens ?? []) { token in
                row(
                    title: token.name,
                    detail: token.tokenPrefix + "…",
                    id: token.id,
                    revoke: PendingRevoke(id: token.id, kind: .token, label: token.name)
                )
            }
        } header: {
            Text("API tokens")
        } footer: {
            // No "create" here on purpose: a token is shown once and must be
            // copied somewhere safe, which is a desk job, not a phone one.
            listFooter(
                key: "tokens",
                empty: lists?.tokens.isEmpty == true ? "No API tokens. Create them on the web, where you can copy one somewhere safe." : nil
            )
        }
    }

    /// One row shape for all four lists: what it is, what it was, and the way to
    /// remove it.
    private func row(title: String, detail: String, id: String, revoke: PendingRevoke) -> some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(title).foregroundStyle(theme.ink)
                if !detail.isEmpty {
                    Text(detail).font(.caption).foregroundStyle(theme.muted)
                }
            }
            Spacer()
            if lists?.pendingRevoke == id {
                ProgressView().controlSize(.small)
            } else {
                Button(revoke.action) { confirming = revoke }
                    .font(.callout)
                    .foregroundStyle(theme.danger)
                    .buttonStyle(.borderless)
            }
        }
    }

    /// An error if there is one, otherwise the section's own sentence. The error
    /// wins: a "nothing here" message over a failed fetch is a lie.
    @ViewBuilder
    private func listFooter(key: String, empty: String?, extra: String? = nil) -> some View {
        if let error = lists?.errors[key], !error.isEmpty {
            Text(error).foregroundStyle(theme.danger)
        } else if let extra {
            Text(extra).foregroundStyle(theme.muted)
        } else if let empty {
            Text(empty)
        }
    }

    private func passkeyDetail(_ passkey: GrooPasskey) -> String {
        var parts: [String] = []
        // Worth saying, because it changes what losing the device costs.
        if passkey.deviceType == "singleDevice" { parts.append("this device only") }
        else if passkey.backedUp == true { parts.append("synced") }
        if let used = shortDate(passkey.lastUsedAt) { parts.append("last used \(used)") }
        return parts.joined(separator: " · ")
    }

    private func shortDate(_ iso: String?) -> String? {
        guard let iso, let date = GrooTimestamp.parse(iso) else { return nil }
        return date.formatted(.relative(presentation: .named))
    }

    private func registerPasskey() {
        isRegisteringPasskey = true
        passkeyNotice = nil
        Task {
            do {
                try await controller.session.registerPasskey(presentationAnchor: GrooSignInView.presentationAnchor())
                await lists?.load()
            } catch GrooAuthError.userCancelled {
                // Closing the sheet is not a failure.
            } catch {
                passkeyNotice = GrooAccountStore.message(for: error)
            }
            isRegisteringPasskey = false
        }
    }

    private func revoke(_ pending: PendingRevoke) {
        confirming = nil
        Task {
            switch pending.kind {
            case .passkey: await lists?.deletePasskey(pending.id)
            case .device: await lists?.revokeDevice(pending.id)
            case .app: await lists?.disconnectApp(pending.id)
            case .token: await lists?.revokeToken(pending.id)
            }
        }
    }

    private func consoleSection(_ url: URL) -> some View {
        Section {
            Button {
                openURL(url)
            } label: {
                HStack {
                    Text("Manage security and devices")
                    Spacer()
                    // An outward arrow, not a chevron: this leaves the app.
                    Image(systemName: "arrow.up.forward.square")
                        .font(.footnote.weight(.semibold))
                        .foregroundStyle(theme.muted)
                }
            }
            .accessibilityIdentifier("grooAccount.console")
        } footer: {
            Text("Passkeys, active devices, connected apps and API tokens are managed on the web.")
        }
    }

    private var signOutSection: some View {
        Section {
            Button(role: .destructive, action: signOut) {
                HStack {
                    if isSigningOut { ProgressView().controlSize(.small) }
                    Text("Sign Out")
                }
            }
            .disabled(isSigningOut)
            .accessibilityIdentifier("grooAccount.signOut")
        }
    }

    // MARK: - Actions

    private var hasEdits: Bool {
        guard let profile = store?.profile else { return false }
        return name != (profile.name ?? "") || phone != (profile.phone ?? "")
    }

    private func save() {
        guard let store else { return }
        Task { await store.save(name: name, phone: phone) }
    }

    private func signOut() {
        isSigningOut = true
        Task {
            // The result says whether the issuer was reached; this device is
            // signed out either way, so the screen closes either way.
            //
            // THE ANCHOR IS WHAT ENDS THE BROWSER SESSION. Without it the issuer's
            // cookie survives sign-out and the next sign-in silently returns the
            // same person -- on a shared device, to whoever holds it next.
            await controller.signOut(presentationAnchor: GrooSignInView.presentationAnchor())
            isSigningOut = false
            dismiss()
        }
    }

    // MARK: - Display

    private var email: String? { store?.profile?.email ?? controller.user?.email }

    /// Name, then the email's local part, then a generic label. Never an empty
    /// header — a blank line where a person's name belongs reads as a bug.
    private var displayName: String {
        if let name = store?.profile?.name ?? controller.user?.name, !name.isEmpty { return name }
        if let email, let local = email.split(separator: "@").first { return String(local) }
        return "Your Account"
    }
}
