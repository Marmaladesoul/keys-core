import XCTest
@testable import KeysCoreFFI

/// Slice 3 — read surface (`listEntries`, `listGroups`, `getEntry`,
/// `search`) round-tripped from Swift. Reuses the `#file`-relative
/// fixture-path trick from `VaultOpenTests`.
final class VaultReadTests: XCTestCase {
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

    func testListEntriesReturnsAll() throws {
        let vault = try openBasic()
        let entries = try vault.listEntries(groupUuid: nil)
        XCTAssertEqual(entries.count, 6)
        XCTAssertTrue(entries.contains { $0.title == "Acme Banking" })
    }

    func testListEntriesScopedToGroup() throws {
        let vault = try openBasic()
        let groups = try vault.listGroups()
        guard let personal = groups.first(where: { $0.name == "Personal" }) else {
            return XCTFail("Personal group missing")
        }
        let entries = try vault.listEntries(groupUuid: personal.uuid)
        XCTAssertEqual(entries.count, 3)
        XCTAssertTrue(entries.allSatisfy { $0.groupUuid == personal.uuid })
    }

    func testGetEntryReturnsPasswordFieldWithoutValue() throws {
        let vault = try openBasic()
        let summaries = try vault.listEntries(groupUuid: nil)
        guard let first = summaries.first else { return XCTFail("no entries") }

        let entry = try vault.getEntry(uuid: first.uuid)
        let password = entry.passwordField
        XCTAssertEqual(password.name, "Password")
        XCTAssertFalse(password.revealed)
        XCTAssertNil(password.value, "no plaintext crosses the boundary on get_entry")
    }

    func testSearchIsCaseInsensitive() throws {
        let vault = try openBasic()
        let hits = try vault.search(query: "ACME")
        let titles = hits.map(\.title)
        XCTAssertTrue(titles.contains("Acme Banking"))
        XCTAssertTrue(titles.contains("Acme Cloud"))
    }

    func testGetEntryNotFound() throws {
        let vault = try openBasic()
        XCTAssertThrowsError(
            try vault.getEntry(uuid: "00000000-0000-0000-0000-000000000000")
        ) { error in
            guard case VaultError.NotFound = error else {
                return XCTFail("expected NotFound, got \(error)")
            }
        }
    }
}
