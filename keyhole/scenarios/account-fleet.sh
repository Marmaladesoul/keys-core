#!/usr/bin/env bash
#
# Scenario: the account's fleet document, sealed under the fleet key, over
# real document sync.
#
# Alice creates the account and its fleet document, and writes her
# enrolment, her name, what she says about herself, a vault's epoch and look,
# and a setting. Bob is enrolled by the account and writes his own enrolment,
# name, what he says about himself, and what he holds of the vault. Bob joins
# with nothing downloaded by default and fetches every entry small enough to
# be a record, from any author; each reader passes back what it kept from its
# last read.
#
# Each case adds one thing that must not work:
#  - a stranger with the write ticket but not the fleet key writes records:
#    none opens, and nothing of hers counts;
#  - a thief with Alice's store and the fleet key, but not her device key,
#    writes a name for her over her own: refused, and a reader that had her
#    name keeps it;
#  - the account removes Bob, who writes his enrolment back and goes on
#    writing: he stays removed, and nothing he signs counts;
#  - the vault moves to epoch 2, then Alice's epoch-1 record is put back: a
#    reader that kept epoch 2 stays there (one that lost what it kept sees
#    what the document now says, which is why it keeps it);
#  - Bob renames Alice: both readers settle on the new name.

set -euo pipefail
source "$(dirname "$0")/account-common.inc"

fleet() { run account-fleet --case "$1"; }

# The honest read, both ways.
fleet honest
for who in alice bob; do
    expect "$who: device alice name=Alice's Mac platform=macos"
    expect "$who: device bob name=Bob's Phone platform=android"
    expect "$who: vault epoch=1 doc=first name=Family icon=house colour=2a7ab0"
    expect "$who: holding device=bob epoch=1 secrets=no"
    expect "$who: setting cellular-cap=on"
    expect "$who: roster alice,bob"
done
refute_re "refused"
expect "result: done"

# A stranger in the document: nothing of hers opens.
fleet stranger
expect "bob: refused author=mallory reason=not-sealed"
refute_re "device mallory|name=Mallory"
expect "bob: roster alice,bob"

# A thief under Alice's author, signing with a key that is no device's.
fleet thief
expect "bob: refused author=alice reason=unbound"
refute_re "name=Thief"
[ "$(grep -c "^bob: device alice name=Alice's Mac" <<<"$OUT")" = "2" ] \
    || { echo "FAIL: Bob didn't keep Alice's name through the thief's write:"; echo "$OUT"; exit 1; }

# Bob removed: he stays removed, whatever he writes.
fleet removed
for who in alice bob; do
    expect "$who: removed bob"
    expect "$who: roster alice"
    expect "$who: device alice name=Alice's Mac platform=macos"
    expect "$who: refused author=bob reason=removed"
done
refute_re "device bob|name=Still Bob|name=Bob was here|holding device=bob"

# An old epoch put back: a reader that kept the newer one stays there.
fleet replayed
before="$(sed -n '1,/^bob: forgets what it kept$/p' <<<"$OUT")"
after="$(sed -n '/^bob: forgets what it kept$/,$p' <<<"$OUT")"
grep -q "^bob: vault epoch=2 doc=second " <<<"$before" \
    || { echo "FAIL: Bob never read epoch 2:"; echo "$OUT"; exit 1; }
if grep -q "^bob: vault epoch=1 " <<<"$before"; then
    echo "FAIL: Bob went back to epoch 1 while he kept epoch 2:"; echo "$OUT"; exit 1
fi
grep -q "^bob: vault epoch=1 doc=first " <<<"$after" \
    || { echo "FAIL: a reader without what it kept should see the document's record:"; echo "$OUT"; exit 1; }

# A rename from another device reaches both.
fleet renamed
expect "alice: device alice name=Kitchen Mac platform=macos"
expect "bob: device alice name=Kitchen Mac platform=macos"
refute_re "name=Alice's Mac"

echo "PASS: another account's fleet values never open here; a name a thief signed under a device's author doesn't count, and a reader keeps the device's own; a tombstone outranks the device's enrolment and nothing it signs counts; a kept epoch never goes back; the latest name reaches every device"
