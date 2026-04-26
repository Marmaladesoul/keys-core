import XCTest
@testable import KeysCoreFFI

/// Slice 7.5a — `mergeExternal` end-to-end through the Swift binding.
final class VaultMergeTests: XCTestCase {
    private static let password = "test-basic-002"

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

    private func openBasicInTemp() throws -> (Vault, URL) {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("keys-slice7-5a-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        let dest = tmp.appendingPathComponent("basic.kdbx")
        try FileManager.default.copyItem(
            at: URL(fileURLWithPath: Self.fixture("keepassxc/kdbx3-basic.kdbx")),
            to: dest
        )
        let vault = try Vault(path: dest.path, password: Self.password)
        return (vault, tmp)
    }

    /// Mint two on-disk vaults that share a baseline edit history so the
    /// merge crate's `<History>`-LCA logic can find a common ancestor.
    /// Same trick as the Rust integration tests.
    private func makePair(seedTarget: Bool = true) throws -> (Vault, URL, Vault, URL) {
        let (local, ldir) = try openBasicInTemp()
        let (remote, rdir) = try openBasicInTemp()
        if seedTarget, let target = try local.listEntries(groupUuid: nil).first?.uuid {
            var patch = EntryPatch(title: nil, username: nil, url: nil, notes: nil, tags: nil, customFields: nil)
            patch.notes = "__merge-seed__"
            try local.updateEntry(uuid: target, patch: patch)
            try remote.updateEntry(uuid: target, patch: patch)
            try local.save()
            try remote.save()
        }
        let localPath = local.path()
        let remotePath = remote.path()
        let reopenedLocal = try Vault(path: localPath, password: Self.password)
        let reopenedRemote = try Vault(path: remotePath, password: Self.password)
        return (reopenedLocal, ldir, reopenedRemote, rdir)
    }

    func testMergeExternalAutoApplicableDiskOnly() throws {
        let (local, ldir, remote, rdir) = try makePair()
        defer {
            try? FileManager.default.removeItem(at: ldir)
            try? FileManager.default.removeItem(at: rdir)
        }
        let target = try local.listEntries(groupUuid: nil).first!.uuid

        var patch = EntryPatch(title: nil, username: nil, url: nil, notes: nil, tags: nil, customFields: nil)
        patch.title = "remote-only"
        try remote.updateEntry(uuid: target, patch: patch)
        try remote.save()

        let outcome = try local.mergeExternal(otherPath: remote.path(), otherPassword: Self.password)
        let summary = try outcome.summary()
        XCTAssertEqual(summary.diskOnlyCount, 1)
        XCTAssertEqual(summary.entryConflictCount, 0)
        XCTAssertTrue(try outcome.isAutoApplicable())
    }

    func testMergeExternalEntryConflictSurfacesFieldDeltas() throws {
        let (local, ldir, remote, rdir) = try makePair()
        defer {
            try? FileManager.default.removeItem(at: ldir)
            try? FileManager.default.removeItem(at: rdir)
        }
        let target = try local.listEntries(groupUuid: nil).first!.uuid

        var lp = EntryPatch(title: nil, username: nil, url: nil, notes: nil, tags: nil, customFields: nil); lp.title = "local-side"
        try local.updateEntry(uuid: target, patch: lp)
        var rp = EntryPatch(title: nil, username: nil, url: nil, notes: nil, tags: nil, customFields: nil); rp.title = "remote-side"
        try remote.updateEntry(uuid: target, patch: rp)
        try remote.save()

        let outcome = try local.mergeExternal(otherPath: remote.path(), otherPassword: Self.password)
        XCTAssertFalse(try outcome.isAutoApplicable())
        let conflicts = try outcome.entryConflicts()
        XCTAssertEqual(conflicts.count, 1)
        XCTAssertEqual(conflicts[0].entryUuid, target)
        XCTAssertTrue(conflicts[0].fieldDeltas.contains {
            $0.key == "Title" && $0.kind == .bothDiffer
        })
    }

    func testMergeExternalWrongPasswordThrowsWrongKey() throws {
        let (local, ldir, remote, rdir) = try makePair(seedTarget: false)
        defer {
            try? FileManager.default.removeItem(at: ldir)
            try? FileManager.default.removeItem(at: rdir)
        }
        XCTAssertThrowsError(
            try local.mergeExternal(otherPath: remote.path(), otherPassword: "totally-wrong")
        ) { error in
            guard case VaultError.WrongKey = error else {
                return XCTFail("expected VaultError.WrongKey, got \(error)")
            }
        }
    }

    // -----------------------------------------------------------------
    // Slice 7.5b — applyMergeOutcome
    // -----------------------------------------------------------------

    func testApplyMergeOutcomeAutoApplicable() throws {
        let (local, ldir, remote, rdir) = try makePair()
        defer {
            try? FileManager.default.removeItem(at: ldir)
            try? FileManager.default.removeItem(at: rdir)
        }
        let target = try local.listEntries(groupUuid: nil).first!.uuid

        var patch = EntryPatch(
            title: "remote-only", username: nil, url: nil,
            notes: nil, tags: nil, customFields: nil
        )
        try remote.updateEntry(uuid: target, patch: patch)
        _ = patch
        try remote.save()

        let outcome = try local.mergeExternal(otherPath: remote.path(), otherPassword: Self.password)
        try local.applyMergeOutcome(outcome: outcome, resolution: ResolutionFfi(entryFieldChoices: [], deleteEditChoices: []))

        let after = try local.getEntry(uuid: target)
        XCTAssertEqual(after.title, "remote-only")
    }

    func testApplyMergeOutcomeEntryConflictResolution() throws {
        let (local, ldir, remote, rdir) = try makePair()
        defer {
            try? FileManager.default.removeItem(at: ldir)
            try? FileManager.default.removeItem(at: rdir)
        }
        let target = try local.listEntries(groupUuid: nil).first!.uuid

        let lp = EntryPatch(
            title: "local-keeps", username: nil, url: nil,
            notes: nil, tags: nil, customFields: nil
        )
        try local.updateEntry(uuid: target, patch: lp)
        let rp = EntryPatch(
            title: "remote-loses", username: nil, url: nil,
            notes: nil, tags: nil, customFields: nil
        )
        try remote.updateEntry(uuid: target, patch: rp)
        try remote.save()

        let outcome = try local.mergeExternal(otherPath: remote.path(), otherPassword: Self.password)
        let resolution = ResolutionFfi(
            entryFieldChoices: [
                EntryFieldChoiceFfi(
                    entryUuid: target,
                    fieldChoices: [FieldChoiceFfi(key: "Title", side: .local)]
                )
            ],
            deleteEditChoices: []
        )
        try local.applyMergeOutcome(outcome: outcome, resolution: resolution)

        XCTAssertEqual(try local.getEntry(uuid: target).title, "local-keeps")
    }

    func testApplyMergeOutcomeFiresBulkMerge() throws {
        let (local, ldir, remote, rdir) = try makePair()
        defer {
            try? FileManager.default.removeItem(at: ldir)
            try? FileManager.default.removeItem(at: rdir)
        }
        let target = try local.listEntries(groupUuid: nil).first!.uuid

        let patch = EntryPatch(
            title: "auto", username: nil, url: nil,
            notes: nil, tags: nil, customFields: nil
        )
        try remote.updateEntry(uuid: target, patch: patch)
        try remote.save()

        let recorder = SwiftRecorder()
        local.setObserver(observer: recorder)
        let outcome = try local.mergeExternal(otherPath: remote.path(), otherPassword: Self.password)
        try local.applyMergeOutcome(outcome: outcome, resolution: ResolutionFfi(entryFieldChoices: [], deleteEditChoices: []))

        let bulkCount = recorder.events.filter { if case .bulkMerge = $0 { return true } else { return false } }.count
        XCTAssertEqual(bulkCount, 1, "expected one BulkMerge event; got \(recorder.events)")
    }
}

/// Recorder for VaultObserver — Swift mirror of the Rust integration
/// test recorder.
final class SwiftRecorder: VaultObserver, @unchecked Sendable {
    private let lock = NSLock()
    private var _events: [VaultChange] = []
    var events: [VaultChange] {
        lock.lock(); defer { lock.unlock() }
        return _events
    }
    func onChange(change: VaultChange) {
        lock.lock(); defer { lock.unlock() }
        _events.append(change)
    }
}
