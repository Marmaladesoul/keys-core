# Known security limitations

> An honest, up-front inventory of the security limitations we are aware
> of in `keys-core`. We publish it so that anyone evaluating the code can
> see the boundaries clearly rather than discovering them by reading the
> source. It is **not** a list of unfixed vulnerabilities — each item is a
> documented trade-off with a stated mitigation and the reason it is not
> simply fixed (it is blocked on an upstream dependency, or on a current
> language/binding constraint, rather than on a fix we are declining to
> make).

## Threat-model recap (so the severities make sense)

The crown jewels are **vault contents** — usernames, passwords, notes,
attachments. These are protected by the KDBX (KeePass) encryption that
`keepass-core` provides: the vault master key is held in the platform
secret store and never touches the sync transport. Vault payloads travel
and rest **as KDBX ciphertext**, and the sync endpoint identity is a
*random* ed25519 key, never derived from the master password, so the
ciphertext has no key-recovery hole.

The sync layer (`keys-iroh-sync`) carries those ciphertext payloads and
the metadata needed to route them. The material *it* manages — endpoint
identity, document write-capabilities, author signing keys — is what the
limitations below concern. Compromising it lets an attacker **impersonate
a device or forge writes to a synced document**; it does **not**, on its
own, decrypt vault contents.

Both items below require an attacker who already has **read access to the
application's on-device data directory** (item 1) or **live process
memory** (item 2). On a platform with at-rest protection (full-disk
encryption, an app sandbox, a file data-protection class) that implies
those protections have already been defeated — a high bar. **Neither item
is a confidentiality break of vault contents** (those stay KDBX-encrypted);
they are device-impersonation and sync-integrity concerns.

---

## 1. The `iroh-docs` writable-capability store is unencrypted at rest

**What it is.** `keys-iroh-sync` uses `iroh-docs` for replicated documents
(`Docs::persistent(doc_dir)` in `crates/keys-iroh-sync/src/node.rs`).
`iroh-docs` keeps its replica state — including **document
write-capabilities (namespace secret keys)**, the **default author signing
key**, and the persisted peer set — in a `redb` database under the
caller-chosen `doc_dir`. As of the pinned `iroh-docs` version, **that store
is not encrypted at rest.** No such store is committed to this repository;
it exists only at runtime on a user's device, in the directory the
application chooses.

**What an attacker with read access to `doc_dir` gains:** the ability to
**forge writes** to documents the device can write to, to **impersonate
the device's author**, and the persisted peer list (routing metadata).
**What they do *not* gain:** vault plaintext — vault payloads are KDBX
ciphertext in the blob store, and the KDBX master key is never in this
store.

**Severity:** Medium. It widens the blast radius of an already-compromised
data directory. It is inherited from `iroh-docs`, not introduced here.

**Why it is documented rather than fixed.** The secret material lives
inside `iroh-docs`'s own `redb` store, which `keys-iroh-sync` does not
control. A clean fix needs either upstream encryption-at-rest support in
`iroh-docs` or a wrapper built around `doc_dir`. Mitigations:

- **Rely on OS-level at-rest protection** for `doc_dir`: place it inside an
  app sandbox/container with full-disk encryption and a file
  data-protection class enabled. This is the consuming application's
  responsibility; the `NodeConfig::doc_dir` documentation states the
  requirement.
- **Track upstream:** adopt `iroh-docs` encryption-at-rest / sealed-store
  support when it lands. This crate already tracks the iroh stack in
  lockstep.
- **Defence in depth:** an OS-keyed wrapper around the `doc_dir` contents
  if upstream support does not arrive in a reasonable timeframe.

---

## 2. In-memory identity bytes are not heap-zeroized on drop

**What it is.** The `Identity` type holds the secret bytes in a `Vec<u8>`.
uniffi's `Record` derive requires the type to be movable-out-of, which
conflicts with `Drop` / `ZeroizeOnDrop`, so that heap allocation is **not**
automatically wiped on drop. Stack copies *are* wiped and `Debug` is
redacted; this is documented inline in
`crates/keys-iroh-sync/src/identity.rs`.

**Severity:** Low. Exploiting it requires reading freed heap of a live (or
core-dumped) process — a much higher bar than the at-rest item above, and
already partially mitigated (stack scrubbing, redacted `Debug`).

**Why it is documented rather than fixed.** It is a current uniffi
constraint (`Record` versus `Drop`), not a design choice. The crate already
tells Rust-API callers to `zeroize()` the `Vec` before dropping `Identity`,
and tells FFI callers to clear their source storage. To be revisited if a
future uniffi version removes the `Drop`-versus-`Record` constraint.

---

## Summary

| # | Limitation | Severity | Why not simply fixed |
|---|------------|----------|----------------------|
| 1 | Unencrypted `iroh-docs` redb capability store | Medium | Secret lives in `iroh-docs`'s own store — needs upstream encryption-at-rest or a `doc_dir` wrapper; OS at-rest protection mitigates meanwhile |
| 2 | Heap identity bytes not zeroized on drop | Low | uniffi `Record`-versus-`Drop` constraint; revisit when upstream lifts it |

**Neither item is a confidentiality break of vault contents** — vault data
syncs and rests only as KDBX ciphertext. Both are device-impersonation /
sync-integrity concerns gated behind an already-compromised device, and
both are blocked on an external dependency (`iroh-docs`, `uniffi`) rather
than on a fix we are choosing not to make.
