# Bergshamra — build, test, and integration test recipes
_default:
  @just --list


# Paths
shim := justfile_directory() / "tests/xmlsec1-shim.py"
topfolder := justfile_directory() / "test-data"

# Build
build:
    cargo build

build-release:
    cargo build --release

# Unit tests
test:
    cargo test

test-crate crate:
    cargo test -p {{crate}}

# Lint and format
clippy:
    cargo clippy --workspace

fmt-check:
    cargo fmt --all -- --check

fmt:
    cargo fmt --all

# Integration tests (xmlsec test suite via shim)
# All integration tests require a release build and run from the project root.

# Run DSig integration tests, log to /tmp
test-dsig: build-release
    bash {{topfolder}}/testrun.sh {{topfolder}}/testDSig.sh openssl "{{topfolder}}" "{{shim}}" pem \
        > /tmp/dsig-results.txt 2>&1
    grep 'TOTAL OK' /tmp/dsig-results.txt

# Run Enc integration tests, log to /tmp
test-enc: build-release
    bash {{topfolder}}/testrun.sh {{topfolder}}/testEnc.sh openssl "{{topfolder}}" "{{shim}}" pem \
        > /tmp/enc-results.txt 2>&1
    grep 'TOTAL OK' /tmp/enc-results.txt

# Run both DSig and Enc integration tests
test-all: test-dsig test-enc

# Run a single DSig test by name (e.g., just test-one aleksey-xmldsig-01/enveloped-sha1-rsa-sha1)
test-one name: build-release
    XMLSEC_TEST_NAME={{name}} \
        bash {{topfolder}}/testrun.sh {{topfolder}}/testDSig.sh openssl "{{topfolder}}" "{{shim}}" pem

# Run a single Enc test by name
test-one-enc name: build-release
    XMLSEC_TEST_NAME={{name}} \
        bash {{topfolder}}/testrun.sh {{topfolder}}/testEnc.sh openssl "{{topfolder}}" "{{shim}}" pem

# Run a single DSig test with debug output (shows pre-digest and pre-signature data)
test-debug name: build-release
    XMLSEC_SHIM_DEBUG=1 XMLSEC_TEST_NAME={{name}} \
        bash {{topfolder}}/testrun.sh {{topfolder}}/testDSig.sh openssl "{{topfolder}}" "{{shim}}" pem

# Show the latest failed.log for DSig tests
dsig-failures:
    @ls -t /tmp/xmlsec-testDSig.sh-openssl-*/failed.log 2>/dev/null | head -1 | xargs cat 2>/dev/null || echo "No DSig failed.log found. Run 'just test-dsig' first."

# Show the latest failed.log for Enc tests
enc-failures:
    @ls -t /tmp/xmlsec-testEnc.sh-openssl-*/failed.log 2>/dev/null | head -1 | xargs cat 2>/dev/null || echo "No Enc failed.log found. Run 'just test-enc' first."

# Show summary of latest test runs
summary:
    @echo "=== DSig ===" && grep 'TOTAL OK' /tmp/dsig-results.txt 2>/dev/null || echo "No DSig results. Run 'just test-dsig' first."
    @echo "=== Enc ===" && grep 'TOTAL OK' /tmp/enc-results.txt 2>/dev/null || echo "No Enc results. Run 'just test-enc' first."
