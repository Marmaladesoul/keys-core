#!/usr/bin/env bash
#
# Scenario: a credential saved under `url_origin(page)` — the URL a
# client's AutoFill "add new" records — is found again by `service` (the
# AutoFill lookup) for that page, and keeps the page's scheme and port
# on disk.
#
# What's proven, per page (http + port, https subdomain, `www.` host,
# IPv4 + port, IPv6 + port):
#
#   1. `origin` keeps scheme, host and port and drops path / query.
#   2. An entry saved with that URL is in the KDBX with exactly that URL
#      (read back by keepassxc-cli, independent of the engine).
#   3. After a close+reopen from disk (mirror nuked → fresh ingest),
#      looking the page up returns that entry first — so recording the
#      origin rather than the full URL loses no match or rank. Each page
#      is the only one on its site here; how the lookup ranks several
#      entries on one host is search_by_service's own concern.

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
    "Www-svc|https://www.example.org/signin|https://www.example.org"
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

# --- the URL on disk, read without the engine --------------------------
for c in "${CASES[@]}"; do
    IFS='|' read -r title page want <<<"$c"
    stored="$(printf '%s\n' "$PW" | keepassxc-cli show -q -a URL "$VAULT" "$title")"
    [ "$stored" = "$want" ] || { echo "FAIL: $title stored URL '$stored', want '$want'"; exit 1; }
done

# --- fresh ingest from the KDBX, then look each page up -----------------
rm -rf "$VAULT.mirror"
for c in "${CASES[@]}"; do
    IFS='|' read -r title page want <<<"$c"
    # Full-read (never grep -q / head — an early-closed pipe SIGPIPEs
    # keyhole and pipefail misreads it; see DESIGN.md).
    hits="$("$KEYHOLE" service "$VAULT" "$page")"
    first="$(printf '%s\n' "$hits" | awk 'NR == 1 {print $2}')"
    [ "$first" = "$title" ] || { echo "FAIL: service($page) ranked '$first' first, want $title:"; echo "$hits"; exit 1; }
done

[ "$("$KEYHOLE" origin "file:///etc/hosts")" = "(none)" ] \
    || { echo "FAIL: file: URL produced an origin"; exit 1; }

echo "PASS: url_origin keeps scheme + port, survives a fresh ingest, and every saved origin is found again by its page's service lookup"
