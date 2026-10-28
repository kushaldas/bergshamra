#!/usr/bin/env bash
# Regenerate the certificate-rollover fixture used by tests/trusted_key_set.rs.
#
# One RSA-2048 / SHA-256 root and two leaves it issued, accepted by every
# supported provider (RustCrypto and AWS-LC, with or without
# legacy-algorithms):
#
#   root.pem      ~100 years
#   old-cert.pem  10 years   (the certificate being rolled out)
#   new-cert.pem  ~99 years  (the certificate being rolled in)
#
# The tests pin DsigContext::verification_time instead of relying on the
# wall clock: 20 years after generation the old leaf has expired while the
# root and the new leaf are still valid. Keys are test-only.
set -euo pipefail
cd "$(dirname "$0")"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

cat > "$tmp/ca.ext" <<'EXT'
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
EXT
cat > "$tmp/leaf.ext" <<'EXT'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
EXT

for name in root old new; do
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$name-key.pem"
done

openssl req -new -key root-key.pem -subj "/O=Bergshamra Test/CN=Rollover Test Root" \
    -out "$tmp/root.csr"
openssl x509 -req -sha256 -days 36500 -in "$tmp/root.csr" -signkey root-key.pem \
    -extfile "$tmp/ca.ext" -set_serial 1 -out root.pem

issue() {
    local name=$1 days=$2 serial=$3
    openssl req -new -key "$name-key.pem" \
        -subj "/O=Bergshamra Test/CN=eidas.example.eu metadata signer" -out "$tmp/$name.csr"
    openssl x509 -req -sha256 -days "$days" -in "$tmp/$name.csr" \
        -CA root.pem -CAkey root-key.pem -set_serial "$serial" \
        -extfile "$tmp/leaf.ext" -out "$name-cert.pem"
}
issue old 3650 2
issue new 36000 3

# The root only signs leaves here; its key is not needed by the tests.
rm root-key.pem
