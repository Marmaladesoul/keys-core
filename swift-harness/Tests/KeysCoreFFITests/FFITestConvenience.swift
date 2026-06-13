// Test-only convenience initialisers that pin the harness to the FFI
// signatures it predates.
//
// Several FFI constructors grew newer parameters on the Rust side without
// the harness call sites being updated (the macOS Swift CI runs weekly,
// so the drift went unnoticed):
//
//   * `Vault.init` gained `fieldProtector: VaultFieldProtector?`.
//   * `EntryPatch` gained slice-4/8 fields (iconId, customIconUuid,
//     foregroundColor, backgroundColor, overrideUrl, expiryTimeMs,
//     autoType), all with "`None` leaves alone" semantics.
//   * `ResolutionFfi` gained `entryAttachmentChoices` and
//     `entryIconChoices` alongside the existing choice lists.
//   * `GroupPatch` gained `iconId` and `customIconUuid`, both with
//     "`None` leaves alone" semantics.
//
// Each newer parameter reproduces the behaviour the tests assumed before
// it existed when defaulted: `nil` (no field protector; leave the newer
// entry fields alone) or `[]` (no extra merge resolution choices). Rather
// than thread those defaults through ~30 call sites, these overloads
// supply them — keeping the call sites focused on what they actually
// exercise. Callers that need the newer parameters use the generated
// initialisers, which still require every argument.

import KeysCoreFFI

extension Vault {
    convenience init(path: String, password: String) throws {
        try self.init(path: path, password: password, fieldProtector: nil)
    }
}

extension EntryPatch {
    init(
        title: String? = nil,
        username: String? = nil,
        url: String? = nil,
        notes: String? = nil,
        tags: [String]? = nil,
        customFields: [CustomField]? = nil
    ) {
        self.init(
            title: title,
            username: username,
            url: url,
            notes: notes,
            tags: tags,
            customFields: customFields,
            iconId: nil,
            customIconUuid: nil,
            foregroundColor: nil,
            backgroundColor: nil,
            overrideUrl: nil,
            expiryTimeMs: nil,
            autoType: nil
        )
    }
}

extension GroupPatch {
    init(name: String? = nil, notes: String? = nil) {
        self.init(name: name, notes: notes, iconId: nil, customIconUuid: nil)
    }
}

extension ResolutionFfi {
    init(
        entryFieldChoices: [EntryFieldChoiceFfi],
        deleteEditChoices: [DeleteEditChoiceEntryFfi]
    ) {
        self.init(
            entryFieldChoices: entryFieldChoices,
            entryAttachmentChoices: [],
            entryIconChoices: [],
            deleteEditChoices: deleteEditChoices
        )
    }
}
