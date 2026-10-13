#!/usr/bin/env bash
# CLI wall-time harness (hyperfine) for bergshamra verify.
#
# Two modes:
#   1. Single binary: warm-path latency of `bergshamra verify` on the small
#      (≈30 KB, SAML-shaped) and large (≈10 MB) fixtures, plus a startup
#      (`--version`) measurement. Startup is a first-class metric: library
#      init and key parsing all show up here.
#   2. A/B: pass two binaries as arguments to compare them on the same
#      workloads (hyperfine interleaves and reports the speedup ratio).
#
# Usage:
#   scripts/hyperfine.sh [BIN_A [BIN_B]]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KEY="$ROOT/test-data/keys/rsa/rsa-2048-pubkey.pem"
OUT="${MEMBENCH_DIR:-$ROOT/target/membench}"

if ! command -v hyperfine > /dev/null; then
    echo "error: hyperfine not found (see https://github.com/sharkdp/hyperfine)" >&2
    exit 1
fi

python3 "$ROOT/scripts/gen_fixture.py" small "$OUT" > /dev/null
python3 "$ROOT/scripts/gen_fixture.py" large "$OUT" > /dev/null

SMALL="$OUT/small_signed.xml"
LARGE="$OUT/large_signed.xml"
if [[ ! -f "$SMALL" || ! -f "$LARGE" ]]; then
    echo "error: signed fixtures missing — run scripts/membench.sh first" >&2
    exit 1
fi

if [[ $# -ge 2 ]]; then
    A="$1"; B="$2"
    echo "== A/B: $A vs $B =="
    hyperfine --warmup 5 --runs 50 \
        "$A verify --key $KEY $SMALL" \
        "$B verify --key $KEY $SMALL" \
        "$A verify --key $KEY $LARGE" \
        "$B verify --key $KEY $LARGE" \
        "$A --version" \
        "$B --version"
else
    BIN="${1:-$ROOT/target/release/bergshamra}"
    echo "== warm-path timing: $BIN =="
    hyperfine --warmup 5 --runs 50 \
        "$BIN verify --key $KEY $SMALL" \
        "$BIN verify --key $KEY $LARGE" \
        "$BIN --version"
fi
