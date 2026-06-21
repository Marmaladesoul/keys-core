# Security Policy

`keys-core` is the cryptographic and synchronisation core of the **Keys**
password manager — it handles credential material, the vault encryption
seam, and device-to-device sync. We take security reports seriously and
appreciate the work of the security community in keeping users safe.

## Reporting a Vulnerability

Please report security vulnerabilities **privately** — do not open public
GitHub issues, pull requests, or discussions for security bugs.

You have two options:

1. **GitHub Private Vulnerability Reporting** — use the
   ["Report a vulnerability"](https://github.com/Marmaladesoul/keys-core/security/advisories/new)
   button on this repository's Security tab. This is the preferred
   channel: it keeps the report and discussion private until disclosure
   and provides structured triage.
2. **Email** — send details to **security@marmaladesoul.com**.

## What to include

- A clear description of the vulnerability and its security impact
- Steps to reproduce — a proof-of-concept or a failing `keyhole` scenario
  is ideal
- The affected component (`keys-engine`, `keys-ffi`, `keys-iroh-sync`) and
  the version / commit
- Your preferred disclosure timeline (default: 90 days)

Please use **synthetic test vaults only** in any proof-of-concept — never
attach a real vault or real credentials.

## What to expect

- **Acknowledgement within 7 days** of receipt.
- A rough remediation timeline within 14 days.
- Credit in the release notes (or anonymously, if you prefer).
- Coordinated disclosure — we'll agree the public-announcement timing with
  you, with a default window of 90 days.

## Scope

In scope — the code in *this* repository:

- `keys-engine` — vault model, ingest/serialise, reconcile, key-provider seam
- `keys-ffi` — the uniffi FFI facade and bridge layer
- `keys-iroh-sync` — the iroh-based sync transport

Examples of in-scope issues: memory-safety defects; incorrect or weakened
cryptographic use; secret material leaking into logs, errors, or
serialised output; authentication or capability bypass in sync; parsing
flaws that panic or corrupt memory on attacker-controlled input;
algorithmic-complexity denial-of-service with a concrete proof-of-concept.

Out of scope:

- **The Keys GUI applications** (Keys-Mac, Keys-iOS, and any Windows
  client) — these live in separate repositories with their own channels.
  Platform secret-store handling (Keychain, Credential Manager) and
  app-level key handling belong there, not here.
- **Third-party dependencies** (e.g. `iroh`, `keepass-core`, `rusqlite`) —
  report these upstream. If a dependency flaw is reachable *specifically
  because of how `keys-core` uses it*, we do want to hear about that.
- Reports without a plausible security impact (e.g. theoretical issues
  with no proof-of-concept), social engineering, and physical attacks.

## Threat model

The crown jewels are **vault contents** — usernames, passwords, notes,
attachments. These are protected by the KDBX (KeePass) encryption that
`keepass-core` provides: the vault master key lives in the platform secret
store and never touches the sync transport, and vault payloads travel and
rest as KDBX **ciphertext**.

`keys-core` is responsible for:

- parsing and serialising vaults correctly (including resisting malicious
  input);
- applying KDBX cryptographic primitives correctly;
- mediating the key-provider seam without retaining secrets;
- not leaking secrets via logging, error messages, or debug output.

It is **not** responsible for platform key storage (the caller's job) or
for protecting against an already-compromised host or process.

## Safe harbour

We will not pursue or support legal action against researchers who act in
good faith — testing only against their **own** accounts and synthetic
vaults, avoiding privacy violations and data destruction, and giving us
reasonable time to respond before public disclosure. If you are unsure
whether an action is authorised, ask first at the contact above.
