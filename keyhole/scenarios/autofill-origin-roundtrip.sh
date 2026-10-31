#!/usr/bin/env bash
#
# Scenario: a credential saved under `url_origin(page)` — the URL a
# client's AutoFill "add new" records — is found again by `service` (the
# AutoFill lookup) for that page, and keeps the page's scheme and port
# on disk.
#
# What's proven, per page (http + port, https subdomain, IPv4 + port,
# IPv6 + port):
#
#   1. `origin` keeps scheme, host and port and drops path / query.
#   2. An entry saved with that URL survives a close+reopen from disk
#      (mirror nuked → fresh ingest) with the scheme and port intact.
#   3. Looking the page up again returns that entry and no other — so
#      recording the origin rather than the full URL loses no match.

set -euo pipefail

KEYHOLE="$(cd "$(dirname "$0")/../.." && pwd)/target/debug/keyhole"
PW="keyhole-scenario-pw"
export KEYHOLE_PASSWORD="$PW"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
VAULT="$TMP/scenario.kdbx"

"$KEYHOLE" create "$VAULT" >/dev/null

# title | page | expected origin
CASES=(
    "LocalDev-svc|http://localhost:8765/login.html|http://localhost:8765"
    "Dash-svc|https://dash.example.com/login?next=/home|https://dash.example.com"
    "Router-svc|http://192.168.1.1:8080/admin|http://192.168.1.1:8080"
    "Loopback6-svc|http://[::1]:8080/|http://[::1]:8080"
)

# --- save each page's entry the way a client's "add new" does ---------
for c in "${CASES[@]}"; do
    IFS='|' read -r title page want <<<"$c"
    got="$("$KEYHOLE" origin "$page")"
    [ "$got" = "$want" ] || { echo "FAIL: origin($page) = $got, want $want"; exit 1; }

    "$KEYHOLE" create-entry "$VAULT" "$title" --username u >/dev/null
    uuid="$("$KEYHOLE" list "$VAULT" | awk -v t="$title" '$2 == t {print $1; exit}')"
    [ -n "$uuid" ] || { echo "FAIL: could not find $title"; exit 1; }
    "$KEYHOLE" update-entry "$VAULT" "$uuid" --url "$got" >/dev/null
done

# --- fresh ingest from the KDBX, then look each page up -----------------
rm -rf "$VAULT.mirror"
for c in "${CASES[@]}"; do
    IFS='|' read -r title page want <<<"$c"
    # Full-read greps (never grep -q — an early-closed pipe SIGPIPEs
    # keyhole and pipefail misreads it; see DESIGN.md).
    hits="$("$KEYHOLE" service "$VAULT" "$page" | { grep -- "-svc" || true; })"
    [ "$(printf '%s\n' "$hits" | grep -c -- "-svc")" = "1" ] \
        || { echo "FAIL: service($page) hits:"; echo "$hits"; exit 1; }
    printf '%s\n' "$hits" | grep -- " $title " >/dev/null \
        || { echo "FAIL: service($page) did not return $title: $hits"; exit 1; }
    "$KEYHOLE" search "$VAULT" "$want" | grep -- " $title " >/dev/null \
        || { echo "FAIL: $title's URL lost $want across reopen"; exit 1; }
done

[ "$("$KEYHOLE" origin "file:///etc/hosts")" = "(none)" ] \
    || { echo "FAIL: file: URL produced an origin"; exit 1; }

echo "PASS: url_origin keeps scheme + port, survives a fresh ingest, and every saved origin is found again by its page's service lookup"
