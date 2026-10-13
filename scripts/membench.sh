#!/usr/bin/env bash
# Peak-RSS memory harness for bergshamra's XML-DSig hot paths.
#
# Generates deterministic SAML-shaped fixtures at three size classes, signs and
# verifies each through the release CLI, and records elapsed time and peak RSS
# via /usr/bin/time -v. Mirrors the methodology in performance.md (which showed
# ~24x input-size memory scaling on the 9.9 MB fixture) so regressions in
# allocation behavior are caught before release.
#
# Usage: scripts/membench.sh [BIN]   (default: target/release/bergshamra)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${1:-$ROOT/target/release/bergshamra}"
KEY="$ROOT/test-data/keys/rsa/rsa-2048-key.pem"
PUBKEY="$ROOT/test-data/keys/rsa/rsa-2048-pubkey.pem"
OUT="${MEMBENCH_DIR:-$ROOT/target/membench}"
TIME_BIN="/usr/bin/time"

if [[ ! -x "$BIN" ]]; then
    echo "error: $BIN not found — build it first: cargo build --release" >&2
    exit 1
fi
if [[ ! -f "$KEY" ]]; then
    echo "error: $KEY not found — test-data must be checked out" >&2
    exit 1
fi

mkdir -p "$OUT"

run_timed() {
    # run_timed LABEL CMD...
    local label="$1"; shift
    local log="$OUT/${label//\//_}.time"
    "$TIME_BIN" -f "elapsed_s=%e maxrss_kib=%M" -o "$log" "$@" >/dev/null
    printf '%-28s %s\n' "$label" "$(cat "$log")"
}

echo "== bergshamra peak-RSS harness =="
echo "binary: $BIN"
echo

for class in small medium large; do
    python3 "$ROOT/scripts/gen_fixture.py" "$class" "$OUT" > /dev/null
    signed="$OUT/${class}_signed.xml"

    run_timed "sign/$class" "$BIN" sign \
        "$OUT/${class}_template.xml" \
        --key "$KEY" --output "$signed"

    run_timed "verify/$class" "$BIN" verify \
        --key "$PUBKEY" "$signed"

    in_bytes=$(stat -c%s "$OUT/${class}_unsigned.xml")
    out_bytes=$(stat -c%s "$signed")
    printf '%-28s input=%dKiB signed=%dKiB\n' "sizes/$class" \
        $((in_bytes / 1024)) $((out_bytes / 1024))
    echo
done

echo "results in $OUT/*.time (raw); full -v logs: re-run with MEMBENCH_VERBOSE=1"
