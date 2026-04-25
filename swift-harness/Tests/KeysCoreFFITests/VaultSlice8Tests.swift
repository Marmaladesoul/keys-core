import XCTest
@testable import KeysCoreFFI

/// Slice 8 — entry history + cross-vault export/import.
final class VaultSlice8Tests: XCTestCase {
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

    private func openCustom() throws -> Vault {
        try Vault(
            path: Self.fixture("pykeepass/custom-fields.kdbx"),
            password: "test-custom-104"
        )
    }

    private func rootUuid(_ vault: Vault) throws -> String {
        let groups = try vault.listGroups()
        return groups.first(where: { $0.parentUuid == nil })!.uuid
    }

    func testEntryHistoryGrowsAfterUpdate() throws {
        let vault = try openBasic()
        let uuid = try vault.listEntries(groupUuid: nil)[0].uuid

        XCTAssertEqual(try vault.entryHistory(entryUuid: uuid).count, 0)

        let patch = EntryPatch(
            title: "rename-1",
            username: nil,
            url: nil,
            notes: nil,
            tags: nil,
            customFields: nil
        )
        try vault.updateEntry(uuid: uuid, patch: patch)
        XCTAssertEqual(try vault.entryHistory(entryUuid: uuid).count, 1)
    }

    func testHistoryRecordCarriesNoPlaintext() throws {
        let vault = try openBasic()
        let uuid = try vault.listEntries(groupUuid: nil)[0].uuid
        let patch = EntryPatch(
            title: "edit",
            username: nil,
            url: nil,
            notes: nil,
            tags: nil,
            customFields: nil
        )
        try vault.updateEntry(uuid: uuid, patch: patch)
        let history = try vault.entryHistory(entryUuid: uuid)
        // protectedFieldNames is the no-plaintext summary; structurally
        // there's no plaintext-bearing field on HistoryRecord.
        XCTAssertTrue(history[0].protectedFieldNames.contains("Password"))
    }

    func testExportImportAcrossVaults() throws {
        let src = try openCustom()
        let dst = try openBasic()
        let srcUuid = try src.listEntries(groupUuid: nil)[0].uuid
        let srcEntry = try src.getEntry(uuid: srcUuid)

        let portable = try src.exportEntry(entryUuid: srcUuid)
        let newUuid = try dst.importEntry(portable: portable, groupUuid: try rootUuid(dst))

        let imported = try dst.getEntry(uuid: newUuid)
        XCTAssertEqual(imported.title, srcEntry.title)
        XCTAssertNotEqual(imported.uuid, srcEntry.uuid, "minted UUID")

        // Protected plaintext survived the round-trip.
        let pwSrc = try src.revealField(entryUuid: srcUuid, fieldName: "Password")
        let pwDst = try dst.revealField(entryUuid: newUuid, fieldName: "Password")
        XCTAssertEqual(pwSrc, pwDst)
    }

    func testPortableCarrierIsSingleUse() throws {
        let src = try openCustom()
        let dst = try openBasic()
        let srcUuid = try src.listEntries(groupUuid: nil)[0].uuid
        let portable = try src.exportEntry(entryUuid: srcUuid)

        _ = try dst.importEntry(portable: portable, groupUuid: try rootUuid(dst))

        XCTAssertThrowsError(
            try dst.importEntry(portable: portable, groupUuid: try rootUuid(dst))
        ) { error in
            guard case VaultError.NotFound = error else {
                return XCTFail("expected NotFound, got \(error)")
            }
        }
    }
}
