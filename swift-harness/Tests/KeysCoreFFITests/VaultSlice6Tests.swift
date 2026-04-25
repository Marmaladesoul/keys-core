import XCTest
@testable import KeysCoreFFI

/// Slice 6 — group / recycle-bin / meta / icon mutation
/// round-tripped from Swift. Save+reopen lives in the Rust
/// integration tests; this harness covers the in-memory contract.
final class VaultSlice6Tests: XCTestCase {
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

    private func rootUuid(_ vault: Vault) throws -> String {
        let groups = try vault.listGroups()
        guard let root = groups.first(where: { $0.parentUuid == nil }) else {
            throw XCTSkip("no root group")
        }
        return root.uuid
    }

    func testCreateAndDeleteGroup() throws {
        let vault = try openBasic()
        let root = try rootUuid(vault)
        let newUuid = try vault.createGroup(name: "Throwaway", parentUuid: root)
        XCTAssertTrue(try vault.listGroups().contains { $0.uuid == newUuid })
        try vault.deleteGroup(uuid: newUuid)
        XCTAssertFalse(try vault.listGroups().contains { $0.uuid == newUuid })
    }

    func testUpdateGroupSparsePatch() throws {
        let vault = try openBasic()
        guard let target = try vault.listGroups().first(where: { $0.name == "Personal" }) else {
            return XCTFail("no Personal group")
        }
        let patch = GroupPatch(name: "Personal (renamed)", notes: nil)
        try vault.updateGroup(uuid: target.uuid, patch: patch)

        let after = try vault.listGroups().first { $0.uuid == target.uuid }
        XCTAssertEqual(after?.name, "Personal (renamed)")
    }

    func testRecycleBinEnableDisable() throws {
        let vault = try openBasic()
        let root = try rootUuid(vault)
        let bin = try vault.createGroup(name: "Bin", parentUuid: root)
        try vault.setRecycleBin(enabled: true, groupUuid: bin)
        try vault.setRecycleBin(enabled: false, groupUuid: nil)
        // No throwing means the toggle path works end-to-end.
    }

    func testMetaSettersAreInfallible() throws {
        let vault = try openBasic()
        try vault.setDatabaseName(name: "Renamed")
        try vault.setDatabaseDescription(description: "Test description.")
        try vault.setDefaultUsername(username: "alice")
        try vault.setColor(hex: "#abcdef")
    }

    func testCustomIconRoundTripInMemory() throws {
        let vault = try openBasic()
        let bytes = Data([1, 2, 3, 4, 5])
        let id = try vault.addCustomIcon(data: bytes)
        let got = try vault.customIcon(iconUuid: id)
        XCTAssertEqual(got, bytes)
        XCTAssertTrue(try vault.removeCustomIcon(iconUuid: id))
        XCTAssertFalse(try vault.removeCustomIcon(iconUuid: id))
    }
}
