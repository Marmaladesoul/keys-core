# keys-core

The open-source Rust core of the **Keys** password manager: the vault
engine, the FFI surface its client applications build on, and the
device-to-device sync transport.

It builds on the public
[`keepass-core`](https://github.com/Marmaladesoul/keepass-core) KDBX
library and exposes a stable, uniffi-generated API that the Keys client
applications consume.

## Workspace layout

```
keys-core/
├── crates/
│   ├── keys-engine/        vault model + SQLCipher-backed query/mutation engine
│   ├── keys-ffi/           uniffi FFI facade consumed by the Keys clients
│   ├── keys-iroh-sync/     iroh-based device-to-device sync transport
│   └── uniffi-bindgen-*/   uniffi binding generators (Swift)
├── keyhole/                headless test driver for the FFI seam
└── bindgen/                binding-regeneration scripts
```

## Building

`keys-core` depends on `keepass-core` and `keepass-merge` as **git
dependencies** on the public repo, so a clean clone builds directly — no
side-by-side checkout required:

```sh
git clone https://github.com/Marmaladesoul/keys-core
cd keys-core
cargo build --workspace
```

It is **not published to crates.io**: it's consumed by the Keys client
applications (and depended on via git), not distributed as a registry
crate.

## keyhole

`keyhole/` is a headless test driver that exercises the same `keys-ffi`
seam the client applications use, minus the UI. It is the default entry
point for proving behaviour changes (CRUD, recycle bin, sync, conflict
handling, import/export) independently of any GUI. See
[`keyhole/DESIGN.md`](keyhole/DESIGN.md).

## Security

This is a password manager's core. Please report security issues
privately — see **[SECURITY.md](SECURITY.md)**.

## Contributing

External code contributions are not accepted, but security reports are
welcome. See **[CONTRIBUTING.md](CONTRIBUTING.md)**.

## Licence

keys-core is licensed under the **GNU General Public License v3.0 only**
— see [LICENSE](LICENSE).

It builds on
[`keepass-core`](https://github.com/Marmaladesoul/keepass-core), which is
separately available under `MIT OR Apache-2.0`.
