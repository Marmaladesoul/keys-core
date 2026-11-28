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

**What the author no longer proves.** An author signature therefore says
only "someone with this store wrote this". So `keys-account` doesn't treat
it as proof of which device wrote anything: a device signs what it
publishes in a vault document (its head record, naming its copy's content
hash and size) with its own device signing key, which the account's
enrolment of that device certifies, and a reader acts on a head only if
that device signed it for this document, it sits under the author the
enrolment binds to that device, and its sequence is above the last one the
reader accepted (`keys_account::vault_head`); that last sequence is the
reader's to keep, so a reader that has none yet, or lost it, accepts any
genuine head. Someone holding a copy of `doc_dir` can still write under
the device's author. What that buys them is suppression, not forgery:
their entries fail the check and are ignored, but iroh-docs keeps one
entry per author and key, newest first, so they can overwrite the device's
own head or copy entry in replicas and hide it until the device writes
again, and can put an older genuine head back in front of a reader that
never saw the newer one. `iroh-docs` accepts timestamps up to ten minutes
ahead, so a holder who keeps writing can keep winning those slots. They
can also write a head entry recording a small size for a large blob: the
reader's fetch cap bounds what it reads into memory, not what reaches its
disk before the blob's size is known (`IrohNode::fetch_checked_blob`).
The remedy, replacing the device's author by removing it from the account
and enrolling it again, is not built yet: today an enrolment, once made,
binds its author for good.

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

## 3. Pairing and account secrets: some transient stack copies, and every copy the foreign side holds, are not wiped

**What it is.** `keys-pairing` keeps each long-lived secret (of a pairing run: the code digits, the CPace scalar, the intermediate key, the confirmation key and both session keys; of a key set: the signing seeds, the X25519 secrets and the recovery secret) in a heap allocation of its own that is wiped in place when dropped, so moving the state that owns them never copies them. A test-only allocator checks that no block is freed with one of them in it. Three kinds of copy are outside that:

- **Transient stack copies inside dependencies.** `hmac`'s keyed constructor builds its padded key block in a local it does not wipe; `curve25519-dalek`'s scalar multiplication leaves the scalar's digit expansion on the stack; `aes-gcm`'s constructor copies the key into a local, and the `aes` crate's runtime-detected cipher is a union whose unused half is not wiped (which is why a session holds raw keys and builds its cipher per frame, never storing one). These live in stack frames that later calls overwrite.
- **A few transient values of our own** that pass through the stack: a freshly sampled scalar and a freshly generated key seed on their way into their allocations, the Diffie-Hellman result K as it is returned to the one call that hashes it, the password-derived generator, which only ever lives on the stack, the copy of an X25519 secret that is made, and clamped, each time its public key is computed, and the recovery secret as it is packed into a recovery code or read back out of one (the intermediates of its 128-bit value and the byte array built from it). Each is wiped where it ends up; the places it passed through are not. Stale stack bytes can also be carried into the heap later, in the unused padding of some unrelated value that is moved there.
- **Everything that crosses the FFI as a plain value.** The displayed code, the typed code, and each session payload in the clear are handed to (or come from) the Swift / Kotlin side as ordinary strings and byte arrays. So are the stored forms of the account and device keys, which the client must put in its secure storage, and the recovery code, which it must show once. Rust wipes its own copy of the typed code, of a typed recovery code, and of a stored form handed back in. Byte arrays and optional strings travel through the binding generator's own buffers on the Rust heap, which are freed unwiped, and neither those nor the copies the foreign runtime holds can be wiped from here.

**Severity:** Low. Reading any of these needs the memory of a live (or core-dumped) process. For a pairing run, that means during or shortly after the run: the code is single-use and worthless once its run ends, and the scalar and session keys matter more, since with one of them and a recording of that run's messages the run's session payloads can be read. The account and device keys are long-lived, so their stale copies matter for longer: each time the client stores or reads back a stored form, or shows the recovery code, plain copies are left behind that hold, until overwritten, keys that act as the account, sign as the device or (the recovery code) restore the account outright. That is still a reader of the app's own memory, which while the app is unlocked can read the open vault anyway; what the stale copies add is a window after the app locks. Keeping the account keys and the recovery code out of memory except where they are used (reading the stored form only when the account signs, showing the code once) keeps that window small.

**Why it is documented rather than fixed.** Wiping another crate's stack frames is not possible from safe Rust, and the workspace denies `unsafe`. The foreign-side copies are the client's to minimise: show the code and drop it, and don't log anything named in the lists of secrets that cross the seam in `crates/keys-ffi/src/pairing.rs` and `crates/keys-ffi/src/account.rs`.

---

## 4. Pairing discovery: what finding the other device gives away, and who can get in the way

**What it is.** Before two devices can run the code exchange they have to find each other, and every way of doing that is unauthenticated by design: the code is the only thing a person verifies. Nothing below lets anyone complete a pairing without the code, or learn a secret. These are the things discovery does expose or allow.

- **Opening a link contacts whatever it names.** An invite or an address link names an endpoint and, optionally, a relay. A device that opens an invite knocks on that endpoint, and one that reads an address link approaches it. Either way it connects to an endpoint and a relay chosen by whoever made the link, which learn its endpoint id and its network address. A link that was swapped or made up by someone else therefore gets the opener's device to call them. The relay must be a plain `https://` URL naming a public host: not an IP address, not a one-label name, and not a name reserved for a machine or its own network (`localhost`, `.local`, `.home.arpa`, `.internal`). That keeps a link from naming a device's own machine or network outright, but it is a check on the name only: a public name can resolve to a private address, so a link can still get a device to open an HTTPS connection to a service on its own network. Nothing restricts which public host.
- **An invite names its issuer, lastingly.** An invite carries the inviter's account identity public key and the issuing device's endpoint id and relay. Pairing runs on the device's own endpoint, so that id is the device's permanent one: every invite from one device carries the same id, invites from one account carry the same identity key, and both outlive the invite's expiry. Whoever sees two invites can tell they came from the same device or account, and whoever keeps one can go on dialling that endpoint.
- **An advertisement is public on its network.** While a pairing sheet is open for a device joining an account, the device advertises its endpoint id (and relay, if it has one) to the local network, under a service name the client chooses. Anyone on that network sees a device is pairing. It stops when the sheet closes.
- **Whoever reaches a waiting device first is the one it talks to.** A device waiting to type a code takes the first endpoint that approaches it and tells later ones it is busy, until the person turns the first away. On a shared network a stranger can get in first. The person then types the code their own device shows into a run with the stranger: that run fails, the stranger has had one counted guess (the one-in-a-million chance the exchange already allows), and the real device has been kept out meanwhile.
- **The first endpoint to knock is an invite's opener.** Someone who obtains an invite and knocks before the invited person takes their place on the issuer's record, and the invited person's device is told the invite isn't outstanding. The verification then runs against the interloper, who doesn't have the code. Nothing pairs, and the invite has to be sent again.
- **Connection slots can be used up.** A device serves a bounded number of pairing connections at once, and a displaying sheet a bounded number of callers. Anyone who can reach the endpoint and knows its id can hold them: for up to half a minute each with connections that never say what they want or won't take the answer, and for as long as they keep a connection up once an open sheet has accepted them. That keeps a genuine pairing, or an invite's knock, waiting. They can equally spend an open displaying sheet's three runs on wrong guesses, which the exchange has always allowed.
- **A connection's peer can make the device buffer data nobody reads.** The limits on pairing messages bound what the pairing code itself holds. Underneath, the QUIC layer grants each connection flow-control credit when it is set up, and the node's endpoint grants generously because sync needs it: a peer can open many streams and fill each to its window, and that data stays buffered for as long as the connection lasts, whether or not anything reads it. This was already true of the node's sync protocols for anyone who knew its endpoint id; pairing puts that id in links and on the local network. Bounding it means giving the whole endpoint finite windows, which changes how sync behaves and is not done here.
- **An open sheet can be detected.** Anyone who knows a device's endpoint id can learn whether a pairing sheet is open on it, and for which role and kind of pairing, by trying each greeting and seeing which is accepted. A refusal gives one answer for "no sheet" and "a sheet of another kind", which hides nothing from someone who tries them all.
- **A knock says whether an invite is live.** Anyone holding an invite's id and the issuer's address (that is, anyone who has seen the invite) can ask whether it is still outstanding, by knocking; if nobody has opened it yet, that knock opens it. An id that was never issued, was cancelled, has expired or was opened by another device all get one answer.

- **A name is only a claim, before and after.** The name in an invite and the name a device advertises are chosen by their senders. The library strips control, format and invisible characters and caps the length of an invite's name when it is written and when it is read, and offers the same function for an advertised name, which reaches the client from the platform's browser and which the client must pass through it. That stops a name disguising itself; it doesn't stop a plausible lie or lookalike letters. Nor does a successful pairing vouch for it: the exchange doesn't cover the invite, so an invite's name altered on the way is still there afterwards.

**Severity:** Low. Each of these costs a person a failed attempt, a delay or a fact about their network presence; none yields a pairing, a key or vault data.

**Why it is documented rather than fixed.** Finding a device you have never spoken to, with no server that knows both of you, means acting on unauthenticated hints. The design answers that by making the hints worthless without the code, not by trying to authenticate them. Clients should say so where it matters: show an invite's name as a claim and don't keep it as the contact's name, show a code only once the person has chosen to accept, treat the endpoint a knock recorded as somewhere to dial and never as someone who was verified, and let the person dismiss a device that approached.

---

## 5. The fleet document: what the fleet key, a device's store and the write ticket each let someone do

**What it is.** An account's fleet document (`keys_account::fleet`) holds the roster, the tombstones of removed devices, the vault index, what each device holds, and the account's settings. Every value is sealed under the account's fleet key, bound to its document and entry key, and every entry key is the fleet key's name for the record's slot, so the document's id, its write ticket or a device's `iroh-docs` store shows ciphertext under opaque keys. Inside each seal is a statement signed by the device that wrote it; enrolments, tombstones and vault epochs are also signed by the account identity key. None of the following yields vault contents or a key that unlocks one. They are what each kind of holder can still do:

- **Whoever holds the write ticket** sees how many entries there are, their sizes, their authors and when they change, though not what they are. They can also write any number of entries small enough to be a fleet record under authors of their own, and a reader fetches and tries to open every one (the roster that says which authors count is itself in the document, so the reader can't filter by author before fetching). Each is refused, but each costs the reader a fetch and a failed open.
- **Whoever holds the fleet key** (every device of the account, and, until the document is replaced, every device removed from it) reads the whole document: device names, platforms and when each was last seen, vault names, icons and colours, which device holds which vault at which head, and the settings. They can seal values that open, but not sign them, so nothing they write counts unless it is a copy of a record the account or a current device already signed. A removed device's signatures stop counting at once; its reading of the document stops only when the account replaces the document under a new fleet key, which is not built yet.
- **Whoever holds a copy of a device's store** can write under that device's author. As with vault heads (§1), that buys suppression, not forgery: they can overwrite that device's entries and so hide them from a reader that hasn't already kept them, including a tombstone or a vault epoch that device wrote. Suppressing a tombstone shows the removed device as current to a reader with nothing kept; suppressing an epoch shows a vault at an older one.
- **A reader's memory is its own.** `read_fleet` hands back the entries that make its view (`FleetRead::kept`) and the reader passes them in again next time, so an overwritten entry, or an older epoch's record put back, changes nothing for it. A reader that has kept nothing (a new device, or one that lost its state) sees what the document says now.
- **Latest means the writer's clock.** Where any device may set a record (a device's name, a vault's look, a setting) the highest sequence wins, and a device's sequence is its own clock. A current device whose clock runs far ahead wins those slots until the others' clocks pass it. Only a current device's records count there, so this is a member being unruly, not a stranger getting in.

**Severity:** Low. Reading the document needs the fleet key, which only the account's devices have; changing what it says needs a device's or the account's signing key; and suppression needs the store of the very device whose entry is hidden, which already means that device is compromised.

**Why it is documented rather than fixed.** Suppression and the fetch cost come from `iroh-docs` keeping one entry per author and key, and from a reader needing the document to learn which authors count (§1). The rest is the remedy not being built yet: replacing the fleet document under a new fleet key when a device is removed is a later step of the sync rollout. Meanwhile a client can narrow suppression by having each device copy the account's records (the enrolments, tombstones and vault epochs, which count whoever writes them) under its own author, so that hiding one takes every copier's store, and by keeping `FleetRead::kept` with the rest of its sync state.

---

## Summary

| # | Limitation | Severity | Why not simply fixed |
|---|------------|----------|----------------------|
| 1 | Unencrypted `iroh-docs` redb capability store | Medium | Secret lives in `iroh-docs`'s own store — needs upstream encryption-at-rest or a `doc_dir` wrapper; OS at-rest protection mitigates meanwhile |
| 2 | Heap identity bytes not zeroized on drop | Low | uniffi `Record`-versus-`Drop` constraint; revisit when upstream lifts it |
| 3 | Pairing and account keys: transient stack copies and FFI-side copies of secrets not wiped | Low | Dependencies' stack frames can't be wiped from safe Rust; foreign-runtime copies are the client's to minimise |
| 4 | Pairing discovery: links and advertisements are unauthenticated; first to reach a waiting device or knock on an invite wins; connection slots can be held and unread data buffered | Low | Finding an unknown device without a server means acting on unauthenticated hints; they are made worthless without the code instead |
| 5 | Fleet document: write-ticket holders cost readers fetches; fleet-key holders (removed devices included) read it; a device's store can hide that device's entries from a reader with nothing kept; latest-wins follows the writer's clock | Low | Inherited from `iroh-docs`' one-entry-per-author model; replacing the document when a device is removed is a later rollout step |

**Items 1 and 2 are not a confidentiality break of vault contents** — vault data
syncs and rests only as KDBX ciphertext. Both are device-impersonation /
sync-integrity concerns gated behind an already-compromised device, and
both are blocked on an external dependency (`iroh-docs`, `uniffi`) rather
than on a fix we are choosing not to make.

**Item 3** is about what a pairing run's session carries, and likewise needs the memory of one of the two devices at the time.

**Item 4** yields no pairing, key or vault data: it is about delay, failed attempts and what a device reveals of its network presence while pairing.

**Item 5** yields no vault data and no key: it is about what the account's own devices, removed ones included, can read of its fleet document, and what a compromised device can hide.
