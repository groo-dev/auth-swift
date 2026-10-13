import Testing
@testable import GrooAuthUI

@MainActor
struct GrooSignOutHookTests {
    @Test func withoutAHookSignOutStaysDirect() {
        #expect(GrooAccountView.SignOutAction.resolve(hook: nil) == .signOutDirectly)
    }

    @Test func aHookReplacesTheDirectSignOut() {
        #expect(GrooAccountView.SignOutAction.resolve(hook: {}) == .callHook)
    }

    @Test func theButtonRunsTheHookOnlyAfterTheSheetCloses() {
        var calls = 0
        var pending = GrooUserButton.PendingSignOut()
        pending.request()                     // the account screen asked for a sign-out
        #expect(calls == 0)                   // nothing yet: the sheet is still up
        pending.sheetDismissed { calls += 1 }
        #expect(calls == 1)
        pending.sheetDismissed { calls += 1 } // a later dismissal with no request does nothing
        #expect(calls == 1)
    }
}
