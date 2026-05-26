//! Bin shim around `uniffi::uniffi_bindgen_swift()` pinned to uniffi 0.29.
//! Parallels `uniffi-bindgen-swift` (0.28) so the iroh-sync xcframework
//! pipeline can read 0.29 metadata without disturbing the 0.28-locked
//! keys-ffi pipeline.

fn main() {
    uniffi::uniffi_bindgen_swift();
}
