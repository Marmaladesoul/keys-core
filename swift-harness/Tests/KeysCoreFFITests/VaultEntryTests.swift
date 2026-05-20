import XCTest
@testable import KeysCoreFFI

/// Slice 5 — entry mutation (create / update / delete / touch / move)
/// round-tripped from Swift. Save+reopen lives in the Rust integration
/// tests; this harness covers the in-memory contract.
final class VaultEntryTests: XCTestCase {
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
            password: "tëst pässwörd 🔑/\\"
        )
    }

    private func groupUuid(_ vault: Vault, named name: String) throws -> String {
        let groups = try vault.listGroups()
        guard let g = groups.first(where: { $0.name == name }) else {
            throw XCTSkip("group \(name) missing")
        }
        return g.uuid
    }

    func testCreateEntryAppearsInListing() throws {
        let vault = try openBasic()
        let group = try groupUuid(vault, named: "Personal")
        let create = EntryCreate(
            title: "Brand New",
            username: "u",
            url: "https://example.test",
            notes: "",
            tags: [],
            groupUuid: group,
            customFields: []
        )
        let newUuid = try vault.createEntry(entry: create)

        let entries = try vault.listEntries(groupUuid: group)
        XCTAssertTrue(entries.contains { $0.uuid == newUuid })
        XCTAssertTrue(entries.contains { $0.title == "Brand New" })
    }

    func testUpdateTitleOnlyLeavesOthersAlone() throws {
        let vault = try openBasic()
        let summaries = try vault.listEntries(groupUuid: nil)
        guard let target = summaries.first(where: { $0.title == "Acme Banking" }) else {
            return XCTFail("Acme Banking not present")
        }
        let original = try vault.getEntry(uuid: target.uuid)

        let patch = EntryPatch(
            title: "Acme Banking (renamed)",
            username: nil,
            url: nil,
            notes: nil,
            tags: nil,
            customFields: nil
        )
        try vault.updateEntry(uuid: target.uuid, patch: patch)

        let after = try vault.getEntry(uuid: target.uuid)
        XCTAssertEqual(after.title, "Acme Banking (renamed)")
        XCTAssertEqual(after.username, original.username)
        XCTAssertEqual(after.url, original.url)
    }

    func testDeleteEntryRemovesFromListing() throws {
        let vault = try openBasic()
        let summaries = try vault.listEntries(groupUuid: nil)
        guard let target = summaries.first else { return XCTFail("no entries") }
        try vault.deleteEntry(uuid: target.uuid)
        let after = try vault.listEntries(groupUuid: nil)
        XCTAssertFalse(after.contains { $0.uuid == target.uuid })
    }

    func testTouchDoesNotAdvanceLastModified() throws {
        let vault = try openBasic()
        let uuid = try vault.listEntries(groupUuid: nil)[0].uuid
        let before = try vault.getEntry(uuid: uuid)
        try vault.touchEntry(uuid: uuid)
        let after = try vault.getEntry(uuid: uuid)
        XCTAssertEqual(after.lastModifiedMs, before.lastModifiedMs)
    }

    func testMoveEntryToNewGroup() throws {
        let vault = try openBasic()
        let work = try groupUuid(vault, named: "Work")
        let personal = try groupUuid(vault, named: "Personal")
        let target = try vault.listEntries(groupUuid: personal)[0].uuid

        try vault.moveEntry(uuid: target, newGroupUuid: work)

        let inWork = try vault.listEntries(groupUuid: work)
        XCTAssertTrue(inWork.contains { $0.uuid == target })
    }

    func testCreateEntryWithBogusGroupThrowsNotFound() throws {
        let vault = try openBasic()
        let create = EntryCreate(
            title: "Doomed",
            username: "",
            url: "",
            notes: "",
            tags: [],
            groupUuid: "00000000-0000-0000-0000-000000000000",
            customFields: []
        )
        XCTAssertThrowsError(try vault.createEntry(entry: create)) { error in
            guard case VaultError.NotFound = error else {
                return XCTFail("expected NotFound, got \(error)")
            }
        }
    }
}
