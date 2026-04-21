# KeysCore — private FFI workspace for Keys

Private workspace containing the uniffi FFI facade (`keys-ffi`) that bridges the public [`keepass-core`](https://github.com/Marmaladesoul/keepass-core) library into the native Swift and C# frontends of the Keys password manager.

Not open source. Not published to crates.io.

## Layout

```
KeysCore/
├── Cargo.toml                 workspace manifest
├── crates/
│   └── keys-ffi/              uniffi facade, shaped by Keys' UI needs
├── bindgen/                   binding regeneration scripts
└── _reference/                (gitignored) reference material — other Rust
                               KeePass libraries, for study during development
```

The public crates `keepass-core` and `keepass-merge` live in a separate public repo and are consumed here via path dependencies during initial co-development. Once `keepass-core` v0.1 is published to crates.io, the path deps flip to version deps.

## Design reference

See `_design/rust-core-architecture.md` in the `Keys` repo for the full architecture design.
