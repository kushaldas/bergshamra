#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ "$#" -ne 0 ]]; then
    echo "usage: run-provider-interop.sh" >&2
    exit 2
fi

dsig_expected='--- TOTAL OK: 447; OK (percent): 99; TOTAL FAILED: 0; TOTAL SKIPPED: 3'
enc_expected='--- TOTAL OK: 701; OK (percent): 100; TOTAL FAILED: 0; TOTAL SKIPPED: 0'

# XMLSEC compatibility is a contract of Bergshamra's default RustCrypto
# configuration. Alternate providers have focused capability and policy tests.
cargo build --locked --release
export BERGSHAMRA="$root/target/release/bergshamra"

run_suite() {
    local suite="$1"
    local expected="$2"
    local output
    output="$(mktemp)"

    set +e
    bash "$root/test-data/testrun.sh" \
        "$root/test-data/$suite" openssl "$root/test-data" \
        "$root/tests/xmlsec1-shim.py" pem 2>&1 | tee "$output"
    local status="${PIPESTATUS[0]}"
    set -e

    local actual
    actual="$(grep -- '--- TOTAL OK:' "$output" | tail -n 1 || true)"
    if [[ "$actual" != "$expected" ]]; then
        echo "Unexpected default RustCrypto $suite totals" >&2
        echo "expected: $expected" >&2
        echo "actual:   ${actual:-<missing>}" >&2
        echo "harness status: $status" >&2
        exit 1
    fi
    if [[ "$status" -ne 0 ]]; then
        echo "Default RustCrypto $suite unexpectedly returned $status" >&2
        exit 1
    fi
}

run_suite testDSig.sh "$dsig_expected"
run_suite testEnc.sh "$enc_expected"
