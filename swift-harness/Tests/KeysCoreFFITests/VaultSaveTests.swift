import XCTest
@testable import KeysCoreFFI

/// Slice 7 — `save`, `saveToBytes`, `rekey` round-tripped from Swift.
final class VaultSaveTests: XCTestCase {
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

    /// Copy the fixture into a temp dir and open the copy. `save()`
    /// writes back to the constructor path so we mustn't clobber the
    /// real fixture.
    private func openBasicInTemp() throws -> (Vault, URL) {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("keys-slice7-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        let dest = tmp.appendingPathComponent("basic.kdbx")
        try FileManager.default.copyItem(
            at: URL(fileURLWithPath: Self.fixture("keepassxc/kdbx3-basic.kdbx")),
            to: dest
        )
        let vault = try Vault(path: dest.path, password: "tëst pässwörd 🔑/\\")
        return (vault, tmp)
    }

    func testSaveAndReopen() throws {
        let (vault, tmp) = try openBasicInTemp()
        defer { try? FileManager.default.removeItem(at: tmp) }
        let path = vault.path()
        try vault.save()
        let reopened = try Vault(path: path, password: "tëst pässwörd 🔑/\\")
        XCTAssertFalse(reopened.isLocked())
    }

    func testSaveToBytesRoundTrip() throws {
        let (vault, tmp) = try openBasicInTemp()
        defer { try? FileManager.default.removeItem(at: tmp) }
        let bytes = try vault.saveToBytes()
        XCTAssertGreaterThan(bytes.count, 0)
    }

    func testRekeyThenSaveThenReopenWithNewPassword() throws {
        let (vault, tmp) = try openBasicInTemp()
        defer { try? FileManager.default.removeItem(at: tmp) }
        let path = vault.path()
        try vault.rekey(newPassword: "new-pw")
        try vault.save()

        // Reopen with new password works.
        let reopened = try Vault(path: path, password: "new-pw")
        XCTAssertFalse(reopened.isLocked())

        // Reopen with old password fails.
        XCTAssertThrowsError(try Vault(path: path, password: "tëst pässwörd 🔑/\\")) { error in
            guard case VaultError.WrongKey = error else {
                return XCTFail("expected WrongKey, got \(error)")
            }
        }
    }
}
