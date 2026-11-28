#!/usr/bin/env bash
#
# Scenario: a vault document's signed head records, over real document sync.
#
# Alice and Bob are two devices of one account, each a node of its own on
# the loopback interface, enrolled with its node's real endpoint and author
# ids. Alice publishes her copy (under the copy key) and a head naming it
# (under the head key), signed by her device key. Bob joins with nothing
# downloaded by default, asks the roster about every entry, fetches only
# heads from bound authors, and fetches a copy only once its head checks
# out, by the hash the head names. A copy's owner is the device that signed
# its head. "Never fetched" below means the reader never asked for it; that
# the document engine doesn't fetch it on its own under a nothing-by-default
# policy is pinned by keys-iroh-sync's own tests.
#
# Each case adds one thing that must not work:
#  - a stranger (another account's device with the write ticket) publishes:
#    its entries are never fetched;
#  - a thief with Alice's author writes a head a key of its own signed: it
#    is fetched (the author is bound) and refused, and its copy never
#    fetched; Alice finds the head under her author isn't one she signed,
#    and writes hers again;
#  - Alice's genuine head for another document is written into this one;
#  - an older head of Alice's is put back after Bob accepted a newer one;
#  - a head names a copy larger than Bob will fetch;
#  - a head names a copy no entry offers yet: Bob's fetch of it fails, he
#    still reads Alice's later entries, and once she offers the copy he
#    accepts the same head again (its sequence was not recorded).

set -euo pipefail
source "$(dirname "$0")/account-common.inc"

heads() { run account-heads --case "$1"; }

# The honest read.
heads honest
expect "bob: fetch head author=alice"
expect "bob: accepted head author=alice owner=alice"
expect "bob: copy owner=alice content=alice-1"
expect "alice: own head is hers=yes"
# The copy entry itself is never fetched as anything: only by the head's hash.
expect "bob: ignored author=alice entry=keys/v1/vault/copy reason=not-a-head"
expect "result: done"

# A stranger in the document: nothing of hers is fetched, Alice's still is.
heads stranger
expect "bob: ignored author=mallory entry=keys/v1/vault/head reason=unbound-author"
expect "bob: ignored author=mallory entry=keys/v1/vault/copy reason=not-a-head"
refute_re "^bob: fetch .*mallory"
refute_re "owner=mallory"
expect "bob: copy owner=alice content=alice-1"

# A forged head under Alice's author: refused, the thief's copy never
# fetched, nothing attributed to Alice until she writes her own again.
heads forged
expect "bob: refused head author=alice reason=not-its-device"
refute_re "content=thief"
expect "alice: own head is hers=no"
expect "bob: copy owner=alice content=alice-2"
[ "$(grep -c '^bob: fetch copy' <<<"$OUT")" = "1" ] \
    || { echo "FAIL: expected one copy fetched, Alice's second:"; echo "$OUT"; exit 1; }

# A head signed for another document: refused, nothing fetched for it.
heads moved
expect "bob: refused head author=alice reason=not-signed"
refute_re "^bob: fetch copy"

# An old head put back: refused, and the newer copy stands.
heads replayed
expect "bob: copy owner=alice content=alice-1"
expect "bob: copy owner=alice content=alice-2"
expect "bob: refused head author=alice reason=not-newer"
[ "$(tail -n 2 <<<"$OUT" | head -1)" = "bob: refused head author=alice reason=not-newer" ] \
    || { echo "FAIL: the replayed head wasn't the last thing read:"; echo "$OUT"; exit 1; }

# A head naming a copy over the cap: refused before the copy is fetched.
heads oversize
expect "bob: refused head author=alice reason=copy-too-large"
refute_re "^bob: fetch copy"

# A head whose copy isn't offered yet: the failure is that entry's alone,
# and the head isn't spent until its copy arrives.
heads unserved
expect "bob: copy owner=alice content=alice-2"
refute_re "reason=not-newer"
grep -A1 '^bob: failed author=alice' <<<"$OUT" | grep -q '^bob: ignored author=alice entry=zz-after-head' \
    || { echo "FAIL: Bob stopped reading at the failed fetch:"; echo "$OUT"; exit 1; }

echo "PASS: a reader asks for a copy only once its head is signed by the device its author is bound to, for this document, newer than the last accepted and within the cap, and spends a head only once its copy arrives; it never asks for strangers' entries"
