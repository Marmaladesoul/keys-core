import XCTest
@testable import KeysCoreFFI

/// Slice 4 — protected-field reveal & sparse-patch write round-tripped
/// from Swift. The save+reopen round-trip lives in the Rust integration
/// tests (gated behind the `test_helpers` Cargo feature) — this harness
/// covers in-memory contract: reveal returns plaintext, set is observed
/// by reveal, clear removes the field from `getEntry`.
final class VaultProtectedTests: XCTestCase {
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

    private func openCustom() throws -> Vault {
        try Vault(
            path: Self.fixture("pykeepass/custom-fields.kdbx"),
            password: "test-custom-104"
        )
    }

    private func firstEntryUuid(_ vault: Vault) throws -> String {
        let entries = try vault.listEntries(groupUuid: nil)
        guard let first = entries.first else {
            throw XCTSkip("fixture had no entries")
        }
        return first.uuid
    }

    func testRevealPasswordReturnsPlaintext() throws {
        let vault = try openCustom()
        let uuid = try firstEntryUuid(vault)
        let pw = try vault.revealField(entryUuid: uuid, fieldName: "Password")
        XCTAssertFalse(pw.isEmpty)
    }

    func testRevealUnprotectedFieldThrowsFieldNotFound() throws {
        let vault = try openCustom()
        let uuid = try firstEntryUuid(vault)
        XCTAssertThrowsError(
            try vault.revealField(entryUuid: uuid, fieldName: "API Key ID")
        ) { error in
            guard case VaultError.FieldNotFound = error else {
                return XCTFail("expected FieldNotFound, got \(error)")
            }
        }
    }

    func testSetProtectedFieldThenRevealReturnsNewValue() throws {
        let vault = try openCustom()
        let uuid = try firstEntryUuid(vault)
        try vault.setProtectedField(
            entryUuid: uuid,
            fieldName: "Password",
            newValue: "rotated-pw"
        )
        XCTAssertEqual(
            try vault.revealField(entryUuid: uuid, fieldName: "Password"),
            "rotated-pw"
        )
    }

    func testSetInsertsNewProtectedField() throws {
        let vault = try openCustom()
        let uuid = try firstEntryUuid(vault)
        try vault.setProtectedField(
            entryUuid: uuid,
            fieldName: "TOTP Seed",
            newValue: "JBSWY3DPEHPK3PXP"
        )

        let entry = try vault.getEntry(uuid: uuid)
        let totp = entry.protectedFields.first { $0.name == "TOTP Seed" }
        XCTAssertNotNil(totp)
        XCTAssertEqual(totp?.value, nil, "no plaintext on the read path")

        XCTAssertEqual(
            try vault.revealField(entryUuid: uuid, fieldName: "TOTP Seed"),
            "JBSWY3DPEHPK3PXP"
        )
    }

    func testClearProtectedCustomFieldRemovesIt() throws {
        let vault = try openCustom()
        let uuid = try firstEntryUuid(vault)
        try vault.clearProtectedField(entryUuid: uuid, fieldName: "API Secret")

        let entry = try vault.getEntry(uuid: uuid)
        XCTAssertFalse(entry.protectedFields.contains { $0.name == "API Secret" })
    }

    func testClearPasswordSetsEmptyString() throws {
        let vault = try openCustom()
        let uuid = try firstEntryUuid(vault)
        try vault.clearProtectedField(entryUuid: uuid, fieldName: "Password")

        let entry = try vault.getEntry(uuid: uuid)
        XCTAssertTrue(entry.protectedFields.contains { $0.name == "Password" })

        let pw = try vault.revealField(entryUuid: uuid, fieldName: "Password")
        XCTAssertEqual(pw, "")
    }
}
