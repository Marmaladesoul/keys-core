# Formal models

Machine-checked symbolic models of this workspace's protocols, written for [ProVerif](https://proverif.inria.fr/). So far there is one: the code-authenticated pairing protocol of the `keys-pairing` crate (protocol version 1), under `pairing/`. The models are written from the protocol's definition and stand on their own. CI re-runs the proofs whenever the models or the crate's sources change. Nothing checks that the Rust code conforms to the model: keeping the two in step is the job of review, and where they disagree, one of them has a bug.

A symbolic model treats cryptography as perfect and asks whether the protocol's logic holds against an attacker who controls the network. It finds and rules out logical attacks: relays, replays, reflections, mix-ups between runs, kinds and roles, misbound identities. It says nothing about the strength of a primitive, about side channels, or about whether the Rust code matches the model. Those need other tools.

## Running

```sh
formal/run.sh
```

`run.sh` takes ProVerif from `$PROVERIF`, or `proverif` on `PATH`. It runs every model in every configuration listed in `pairing/expected.txt` and compares each query's result with the one that file declares. It exits non-zero if any query differs: one expected to hold that doesn't, an attack witness expected to fail that doesn't, a query ProVerif can't decide, a missing or extra query, or a ProVerif error. It also refuses a manifest that is missing or empty, that repeats a run, that lists a run with no expected results, or that leaves out any model in `pairing/` under either transport.

The models were written against ProVerif 2.05. The runs are independent and go in parallel (`JOBS`, by default one per CPU). The whole suite is 26 runs: about eight minutes of CPU time, and about two minutes of wall time on a ten-core laptop.

To run one model by hand, from `formal/pairing/`:

```sh
proverif -lib primitives.pvl -lib transport-claimed.pvl -lib binding-current.pvl -lib protocol.pvl agreement.pv
```

## The pairing protocol, as modelled

Two roles. The displaying side (D) made up a six-digit code and shows it; the typing side (T) is told the code by a person and types it. The model follows protocol version 1 of `keys-pairing`.

```text
typing (T)                                displaying (D)
Hello   { version, kind, nonce_T }   -->
                                     <--  Share   { nonce_D, Y_D, AD_D }
Reply   { Y_T, tag_T, AD_T }         -->
                                     <--  Confirm { tag_D }
```

- The exchange is CPace with D as initiator. The code is the password. The channel identifier CI binds the version, the kind (device or Person) and the two endpoint ids in their roles; each side uses its own endpoint id and the one its transport reports for the peer. The session id is both nonces. The generator is hashed from (code, CI, sid), each share is the generator raised to a fresh scalar, and the session secret ISK is a hash over sid, the Diffie-Hellman value, both shares and both ADs.
- AD is empty in a device pairing. In a Person pairing it is the side's account identity, recovery and encryption public keys with an identity-key signature over the role, CI, sid, the three keys and the signer's own CPace share.
- Each side's confirmation tag is an HMAC, keyed from ISK, over its own share and AD. D checks T's tag before sending its own. T holds a session only after checking D's.
- The session has one AEAD key per direction, derived from ISK, and numbered frames. D may not send until it has opened a frame from T.

Three payload flows run over the session:

- **Device pairing, trusted device displays.** The new device (T) sends its public keys; the trusted device (D) enrols them, signing the enrolment with the account identity key, and sends the bundle (account identity and encryption private keys, recovery public key, fleet ticket, fleet key).
- **Device pairing, new device displays.** The trusted device (T) must speak first, so it sends a fixed opening frame; the new device (D) sends its public keys; the trusted device enrols them and sends the bundle.
- **Person pairing.** The invitee displays, the inviter types. The inviter sends the friendship's ticket and pairwise key; the invitee answers with its profile. Each side records the other account's three public keys from its AD.

`keys-pairing` treats payloads as opaque, so the order of frames in each flow is this model's reading of what the session's rules allow, not something the crate fixes.

**Frames are typed, and that is a contract on the payload layer.** A device pairing's AD is empty, so nothing in the exchange says which side is the trusted device: two trusted devices, of the same account or of different ones, can complete an exchange with each other on one code, as can two new devices. What keeps that harmless is that a trusted device enrols only a frame that parses as device keys and a new device installs only a frame that parses as a bundle. Without the check, two trusted devices paired in opposite directions would each take the other's frame for the wrong kind of payload, and one account's bundle could end up inside an enrolment the other publishes. The models make the check, and `device-roles.pv` proves it is enough. Whatever carries payloads over the session must make it too.

## The attacker

A Dolev-Yao attacker: it reads, drops, replays, reorders and forges every message, runs any number of sessions, and has accounts, devices and endpoints of its own. On top of that the models give it four levers, each of which a model file opens or shuts:

- **A lucky guess.** For each code, once, while the code is live, the attacker may be handed the code, and the event `Lucky(code)` records it. This stands for the one correct online guess a balanced PAKE can't prevent. Properties are stated as "violation implies `Lucky` for that run's code".
- **Being the counterparty.** In a Person pairing the attacker may be the party the code was meant for: the displaying person shows it the code (`AdversaryPeer(code)`), and any honest device may then type that code, as if told to by the attacker. This is the malicious contact, who learns codes rightfully and can run two pairings at once and relay between them.
- **A code leaked after use.** In a second phase, after every run has ended, the attacker is handed every code.
- **Long-term compromise.** The attacker may take any account's long-term secrets (`LongTermLeaked(account)`), as a compromised device of that account would give them up.

The transport is modelled twice, because the protocol takes "the endpoint id the transport authenticated" as an input and the model has to say what that is worth:

- **`transport-claimed.pvl`, conservative.** The endpoint id a party is told for its peer is whatever the attacker claims.
- **`transport-authenticated.pvl`.** A party accepts a message as coming from an endpoint only if that endpoint's key authenticated it for this destination. This is deliberately weaker than a real mutually authenticated channel (no confidentiality, and an authenticated message can be replayed on a later connection to the same destination), so what holds here holds over a real one.

In both, discovery is untrusted: the attacker chooses which endpoint a typing side dials. A property that holds under the claimed transport does not depend on the transport at all.

## What is proven

Every query is run under both transports. The two right-hand columns give the result under each.

"Holds" means ProVerif proves it for an unbounded number of accounts, devices, codes and runs. Except in `device-roles.pv` and `offline-guess.pv`, which have worlds of their own, device pairings in both directions and Person pairings all run at once among the same parties.

| File | Query | Property | Claimed transport | Authenticated transport |
| --- | --- | --- | --- | --- |
| `agreement.pv` | A1 | D accepts only a run T replied to, agreeing on kind, both endpoint ids in their roles, sid, both shares and both ADs; injectively; unless `Lucky` or `AdversaryPeer` for that code | holds | holds |
| | A2 | T accepts only a run D accepted, same agreement; injectively; same exceptions | holds | holds |
| `payload.pv` | P1 | A trusted device enrols only device keys the new device sent in that run; injectively; unless `Lucky` | holds | holds |
| | P2 | A new device installs only a bundle the trusted device sent in that run; injectively; unless `Lucky` | holds | holds |
| | P3 | An invitee installs only the friendship the inviter sent in that run; injectively; unless `Lucky` or `AdversaryPeer` | holds | holds |
| | P4 | An inviter installs only the profile the invitee sent in that run; injectively; same exceptions | holds | holds |
| `secrecy.pv` | S1–S4 | Account identity private key, account encryption private key, fleet key and fleet ticket stay secret unless the attacker guessed the code of a device pairing of that same account, or compromised a device of that account | holds | holds |
| | S5–S6 | A friendship's ticket and pairwise key stay secret unless `Lucky` or `AdversaryPeer` for that run's code | holds | holds |
| | S7–S10 | Both session keys, as each side holds them, stay secret under the same condition | holds | holds |
| `device-roles.pv` | X1–X4 | S1–S4 in a world where any trusted device of any account, or any new device, displays a code and any others type it | holds | holds |
| | X5–X6 | P1 and P2 in that world | holds | holds |
| `separation.pv` | K1 | A displaying and a typing side holding the same key ran with the same code and agree on everything, kind and roles included | holds | holds |
| | K2–K3 | Two runs in the same role never hold the same key | holds | holds |
| | K4–K6 | A display-to-type key is never anyone's type-to-display key | holds | holds |
| `offline-guess.pv` | O1 | The code is not open to an offline dictionary attack (ProVerif's `weaksecret`), against an active attacker who sees T's tag before D has proved anything | holds | holds |
| `misbinding.pv` | U1 | No lucky guess. T has recorded an honest account as its peer, yet the attacker holds the key T sends under | holds | holds |
| | U2 | The same for D | holds | holds |
| | I1 | No lucky guess. A T that records an honest account as its peer is in a run a D accepted with the same code and parameters (so a device of that account, since the parameters include its AD); injectively | holds | holds |
| | I2 | A D that records an honest account as its peer is in a run a T of that account replied to, same code and parameters; injectively | holds | holds |
| `misbinding-guess.pv` | G1–G4 | U1, U2, I1 and I2 with the lucky guess open (unless that account's identity key was stolen through a guessed device pairing; I1 and I2 not injectively) | holds | holds |

`misbinding.pv` and `misbinding-guess.pv` are also run with a weakened signature, `binding-noshare.pvl`, under which all eight of their queries fail on the claimed transport; Findings below says why that variant is kept. U1 and U2 state the harm (the attacker holds the session); I1 and I2 state the guarantee a side is owed (the account it recorded is the one it ran with). Neither pair follows from the other in ProVerif's terms, so both are kept.

How to read these:

- **Long-term compromise and leaked codes earn no exception.** `agreement.pv`, `payload.pv` and `separation.pv` run with long-term compromise open, and `secrecy.pv` with long-term compromise and the after-use leak both open. None of A1, A2, P1–P4, S5–S10 or K1–K6 has an exception for either. Pairing rests on the code alone: a compromised device of the same account, or of another account, reaches no session it was not in, and a code that leaks after its run gives up nothing from that run (forward secrecy).
- **The S1–S4 exception is exact.** A guess at some other account's code, or at a Person pairing's code, does not expose an account's bundle.
- **Without a lucky guess, everything holds outright.** There is no separate model with the oracle shut, because none is needed: shutting a lever only removes behaviours, so a property proven with the lever open and an "unless `Lucky`" exception holds with no exception once `Lucky` can't happen.
- **Replay across runs** is covered by injectivity: each acceptance corresponds to a distinct matching step on the other side.
- **Of K1–K6 only K1 carries weight.** It has no exception: even when the attacker knows the code, a device run never completes against a Person run and the two sides are never mistaken about who displayed. K2–K6 follow almost directly from how keys are derived (fresh scalars, a direction label in each key) and are there as guards against a regression in the model.
- **The models are not evidence that every transcript field is needed.** Take the kind out of CI, or the freshness out of sid, and every query here still passes, because other things cover for them: the shape of AD separates the kinds, and fresh scalars and one displaying run per code separate the runs. Those fields are defence in depth as far as this model can tell. It can show that the protocol as designed is sound; it can't rank its parts.

### Checks that are expected to fail

A model in which nothing can happen proves everything. These queries are declared `false` in `expected.txt`, and `run.sh` fails if any of them stops failing.

| File | Query | What it shows |
| --- | --- | --- |
| `witness-runs.pv` | R1–R3 | Each of the three flows can run to completion, in the full world with every lever shut |
| `witness-guess.pv` | W1 | With a lucky guess the attacker does extract the account identity private key from a bundle |
| | W2 | With a lucky guess the attacker does get a friendship's pairwise key |
| | W3 | With a lucky guess the attacker does hold a session key |
| | W4 | With a lucky guess T does accept a run D never accepted |
| `witness-levers.pv` | L1 | The attacker can be the counterparty a Person code was shown to |
| | L2 | Long-term compromise does hand over an account's identity private key |
| | L3 | The after-use leak does hand over the code of a finished run |
| `device-roles.pv` | X7–X8 | Both device flows can run to completion in that file's own world |
| `offline-guess.pv` | O2 | A typing side does accept a run in that file's own world |

W1–W4 show the oracle is wired and that the `Lucky` exception is needed: a man in the middle who guesses right wins. L1–L3 do the same for the other three levers, and R1–R3, X7–X8 and O2 show that every world used here has complete runs in it.

## Findings

### Why the Person-keys signature covers the signer's share

In a Person pairing each side's AD carries its account keys and an identity-key signature over the role, CI, sid, the three keys and the signer's own CPace share. The share is there because of what these models show without it.

`binding-noshare.pvl` is the same signature with the share left out. Under it, on the claimed transport, U1, U2, I1, I2 and G1–G4 all fail: a signed AD is then tied to its run only by CI, and CI is only as good as the endpoint ids in it. A party that legitimately knows a code (the other end of the pairing, or a correct guesser) could have an honest side record a third account's genuine keys as its own, while holding the session itself. Under the authenticated transport the weakened signature is enough, but only for as long as endpoint private keys stay secret, and nothing else stands in for the transport: not the secrecy of the third account's own code, since a side signs before any proof of the code, and not an expected-identity check, since the keys presented are genuine.

With the share covered, a signed AD verifies only beside the share its signer made, and whoever completes the exchange beside that share is the signer. All eight queries hold on the claimed transport, so the account a side records is the party it ran with whatever the transport is worth, and even a correct guess cannot place an attacker between two honest accounts that record each other's real keys. It costs nothing on the wire.

The consumer contract that follows: `keys-pairing` still asks its transport for authenticated endpoint ids, and binds them into CI, but none of the properties proven here depends on that. The weakened variant stays in the suite so that the reason for the share stays checked: `run.sh` fails if those eight queries ever stop failing without it.

### The exchange does not say which device is the trusted one

See "Frames are typed" above: this is a contract on the payload layer, proven sufficient in `device-roles.pv`.

## What is assumed or argued, not proven

- **One displaying run per code.** Every world here gives each code exactly one displaying run, by construction. That is an assumption the sheet must enforce (a code is spent the moment a run starts with it), not a result.
- **The number of guesses.** ProVerif does not count. The models show that an attack needs a correct guess and that a transcript gives no offline test of a guess (O1). That a wrong guess costs the attacker the code, that a sheet allows three runs, and that codes expire and runs time out are properties of the sheet's state machine, for the implementation's sheet state machine to enforce and its tests to exercise, and are not modelled. Nor is the probability of a guess: one in a million per run.
- **Guesses against the typing side.** A typing run answers a Share with its tag, which gives whoever sent the Share one test of one guess. The models let a typing side start any number of runs with the same code, which is more than the sheet allows, and every property holds regardless; but each such run is one more guess. Those guesses are counted on the typing sheet and never show on the displaying side, whose code stays live. So the run budget is per sheet, not per pairing: an attacker working both sides gets both budgets.
- **Who the person meant.** Nothing in a code-based pairing tells a device which human its person believes is on the other end. If someone is talked into typing a code, or into showing theirs, the devices pair correctly with whoever that turns out to be.

## Abstractions and limits

- **Perfect primitives.** The hashes, HMAC, the AEAD and signatures are ideal: no collisions, no forgeries, no malleability, nothing learnt from a ciphertext or tag without the key. Terms have no lengths, so nothing here speaks to length leakage or to the injectivity of the byte encodings (`lv_cat`).
- **The group.** A generator `g` is an opaque hash of (code, CI, sid); a share is `exp(g, y)`; the shared value is `dh(Y, y)`, with the one equation `dh(exp(g, x), y) = dh(exp(g, y), x)`. That captures what CPace needs (only someone who knows the code can make a share whose Diffie-Hellman value with an honest share they can compute) and no more. The attacker can't relate two generators, multiply elements or exponents, or use the neutral element; the implementation's rejection of invalid and neutral shares is not modelled. In particular the theory can't express raising both honest shares to one power of the attacker's choosing, which leaves the two ends with the same Diffie-Hellman value; it is ISK and the tags covering both shares that defeats that, and this model would not notice if they stopped. CPace's security against such algebraic attacks is the business of its own proofs.
- **Expected identities.** `keys-pairing` lets a side hold an expected identity for the other account, from an invite, and refuses any other. The models leave the check out, which is the most permissive setting: a side that holds an expectation accepts a subset of the runs modelled, so every property above holds with it. It also shows that no property rests on the invite, which is unauthenticated.
- **Refusals, timing, expiry, the run budget.** Not modelled. A refusal is unauthenticated and only ever stops a run, which the attacker can do anyway by dropping messages.
- **Frames.** Sent on the open network in both transport variants, protected only by the AEAD, with sequence numbers checked. Stronger for the attacker than the real session, which also listens only to its peer's endpoint.
- **The after-use leak is global.** It hands over every code at once, after every run and every session has ended. A code that leaks while anything is still live, its own run or another, counts as the lucky guess.
- **Device pairings have no adversary counterparty.** A person who types an attacker's code into a device, or shows a trusted device's code to an attacker, has paired with the attacker; for a trusted device that is the lucky guess. The worst case is the flipped direction: a trusted device that has a code typed into it sends the bundle to whoever displayed that code. The Person flows model the adversary counterparty because there it is the ordinary case.
- **Person ceremonies are over-approximated.** Any honest device may type any Person code, any number of times, including the device displaying it.
- **Name arguments.** `protocol.pvl` tells ProVerif which earlier values distinguish two instances of a fresh name, to keep terms small enough to verify quickly. ProVerif's abstraction stays sound whatever is chosen; a poor choice can only make a proof fail.

## Files

| File | What it holds |
| --- | --- |
| `run.sh` | Runs everything and checks it against the manifest |
| `pairing/expected.txt` | The manifest: every run and the result expected of each of its queries |
| `pairing/primitives.pvl` | Types, cryptographic primitives, message and payload formats, events |
| `pairing/transport-claimed.pvl`, `pairing/transport-authenticated.pvl` | The two transport variants; exactly one is loaded |
| `pairing/binding-current.pvl`, `pairing/binding-noshare.pvl` | What the Person-keys signature covers: the protocol's signature, or a weakened one without the signer's share, loaded only by the misbinding models; exactly one is loaded |
| `pairing/protocol.pvl` | The two roles, the three payload flows, the attacker's levers and the world |
| `pairing/*.pv` | One group of queries each, with the world it is asked in |
