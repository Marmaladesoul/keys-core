//! Bin shim around `uniffi::uniffi_bindgen_swift()`. Mozilla's Swift
//! bindgen ships as a function in the `uniffi` crate's `cli` feature rather
//! than as a published binary; each consumer owns a tiny bin like this one.

fn main() {
    uniffi::uniffi_bindgen_swift();
}
