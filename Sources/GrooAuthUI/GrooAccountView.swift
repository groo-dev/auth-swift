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

    @Environment(\.grooAuthTheme) private var theme
    @Environment(\.dismiss) private var dismiss
    @Environment(\.openURL) private var openURL

    @State private var store: GrooAccountStore?
    @State private var name = ""
    @State private var phone = ""
    /// Stops a reload from overwriting what someone is in the middle of typing.
    @State private var hasLoadedFields = false
    @State private var isSigningOut = false

    /// - Parameter consoleURL: the hosted account page, for everything this
    ///   screen deliberately does not do. Pass `nil` to hide the link — an app
    ///   whose issuer has no console should not offer a dead one.
    public init(controller: GrooAuthController, consoleURL: URL? = nil) {
        self.controller = controller
        self.consoleURL = consoleURL
    }

    public var body: some View {
        NavigationStack {
            Form {
                identitySection
                profileSection
                if let consoleURL { consoleSection(consoleURL) }
                signOutSection
            }
            .navigationTitle("Account")
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .task {
                let store = store ?? GrooAccountStore(session: controller.session)
                self.store = store
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
            await controller.signOut()
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
