import XCTest
@testable import KeysCoreFFI

/// Slice 9 — observer callbacks end-to-end from Swift. The
/// load-bearing test for the uniffi `with_foreign` callback path.
final class VaultObserverTests: XCTestCase {
    private static func fixture(_ rel: String) -> String {
        let here = URL(fileURLWithPath: #file)
        let keysCore = here
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        return keysCore
            .deletingLastPathComponent()
            .appendingPathComponent("KeepassCore/tests/fixtures")
            .appendingPathComponent(rel)
            .path
    }

    private func openBasic() throws -> Vault {
        try Vault(
            path: Self.fixture("keepassxc/kdbx3-basic.kdbx"),
            password: "test-basic-002"
        )
    }

    /// Swift-side observer that records every event.
    final class Recorder: VaultObserver {
        let lock = NSLock()
        var events: [VaultChange] = []

        func onChange(change: VaultChange) {
            lock.lock()
            defer { lock.unlock() }
            events.append(change)
        }

        func snapshot() -> [VaultChange] {
            lock.lock()
            defer { lock.unlock() }
            return events
        }
    }

    func testUpdateEntryFiresEntryModified() throws {
        let vault = try openBasic()
        let uuid = try vault.listEntries(groupUuid: nil)[0].uuid
        let recorder = Recorder()
        vault.setObserver(observer: recorder)

        let patch = EntryPatch(
            title: "renamed",
            username: nil,
            url: nil,
            notes: nil,
            tags: nil,
            customFields: nil
        )
        try vault.updateEntry(uuid: uuid, patch: patch)

        let events = recorder.snapshot()
        XCTAssertEqual(events.count, 1)
        guard case .entryModified(let firedUuid) = events[0] else {
            return XCTFail("expected entryModified, got \(events[0])")
        }
        XCTAssertEqual(firedUuid, uuid)
    }

    func testLockFiresLockedEvent() throws {
        let vault = try openBasic()
        let recorder = Recorder()
        vault.setObserver(observer: recorder)
        try vault.lock()

        let events = recorder.snapshot()
        XCTAssertTrue(events.contains { event in
            if case .locked = event { return true } else { return false }
        })
    }

    func testClearObserverSilencesSubsequentEvents() throws {
        let vault = try openBasic()
        let uuid = try vault.listEntries(groupUuid: nil)[0].uuid
        let recorder = Recorder()
        vault.setObserver(observer: recorder)

        let patch1 = EntryPatch(
            title: "first",
            username: nil,
            url: nil,
            notes: nil,
            tags: nil,
            customFields: nil
        )
        try vault.updateEntry(uuid: uuid, patch: patch1)
        XCTAssertEqual(recorder.snapshot().count, 1)

        vault.clearObserver()

        let patch2 = EntryPatch(
            title: "second",
            username: nil,
            url: nil,
            notes: nil,
            tags: nil,
            customFields: nil
        )
        try vault.updateEntry(uuid: uuid, patch: patch2)
        XCTAssertEqual(recorder.snapshot().count, 1, "post-clear update is silent")
    }
}
