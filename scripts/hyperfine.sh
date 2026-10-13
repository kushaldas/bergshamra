#!/usr/bin/env bash
# CLI wall-time harness (hyperfine) for bergshamra verify.
#
# Workloads, each timed as its own hyperfine run so the ratios hyperfine
# reports are always between the same workload on different binaries, never
# between unrelated commands:
#   - verify small: warm-path latency on the ~30 KB SAML-shaped fixture
#   - verify large: the ~10 MB fixture
#   - startup: `bergshamra --version`, which exits during CLI argument parsing
#     before any key or document is read. It measures process start, dynamic
#     loading, and library/CLI initialisation only.
#
# Two modes:
#   1. Single binary: report the three workloads for one binary.
#   2. A/B: pass two binaries to compare them on each workload (hyperfine
#      interleaves the two and prints the A-vs-B speedup per workload).
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
    echo "error: signed fixtures missing - run scripts/membench.sh first" >&2
    exit 1
fi

# Workload table: label and the argument string appended to a binary path.
WORKLOADS=(
    "verify/small|verify --key $KEY $SMALL"
    "verify/large|verify --key $KEY $LARGE"
    "startup|--version"
)

if [[ $# -ge 2 ]]; then
    A="$1"; B="$2"
    echo "== A/B: $A vs $B (one hyperfine run per workload) =="
    for entry in "${WORKLOADS[@]}"; do
        label="${entry%%|*}"; args="${entry#*|}"
        echo
        echo "-- $label --"
        hyperfine --warmup 5 --runs 50 \
            --command-name "A: $label" "$A $args" \
            --command-name "B: $label" "$B $args"
    done
else
    BIN="${1:-$ROOT/target/release/bergshamra}"
    echo "== warm-path timing: $BIN =="
    for entry in "${WORKLOADS[@]}"; do
        label="${entry%%|*}"; args="${entry#*|}"
        echo
        echo "-- $label --"
        hyperfine --warmup 5 --runs 50 --command-name "$label" "$BIN $args"
    done
fi
