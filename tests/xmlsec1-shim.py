#!/usr/bin/env python3
"""
xmlsec1-shim.py — Translates xmlsec1 CLI flags into bergshamra CLI calls.

This allows the xmlsec test scripts (testDSig.sh, testEnc.sh) to drive
the bergshamra binary via testrun.sh. The shim parses xmlsec1-style
arguments and invokes bergshamra with the equivalent flags.

Usage (from the xmlsec test runner):
    bash tests/testrun.sh tests/testDSig.sh openssl tests \
        /path/to/bergshamra/tests/xmlsec1-shim.py pem

Or directly:
    ./xmlsec1-shim.py --verify --hmackey keys/hmackey.bin file.xml
    ./xmlsec1-shim.py --sign --output out.xml --privkey-pem:name key.pem file.tmpl
    ./xmlsec1-shim.py --decrypt --keys-file keys/keys.xml --output out.txt file.xml
"""

import os
import subprocess
import sys

BERGSHAMRA = os.environ.get(
    "BERGSHAMRA",
    os.path.join(os.path.dirname(__file__), "..", "target", "release", "bergshamra"),
)


def parse_xmlsec1_args(args):
    """Parse xmlsec1-style arguments into a structured dict."""
    ctx = {
        "command": None,
        "input_file": None,
        "output": None,
        "hmac_key": None,  # (name, path) or (None, path)
        "aes_keys": [],  # (name, file) or (None, file)
        "priv_keys": [],  # (name, file)
        "pub_keys": [],  # (name, file)
        "pub_cert_keys": [],  # (name, file)
        "pkcs12_keys": [],  # (name, file)
        "trusted_pem": [],
        "keys_file": None,
        "url_maps": [],  # (url, file) pairs
        "password": None,
        "id_attrs": [],
        "verbose": False,
        "debug": False,
        "binary_data": None,
        "xml_data": None,
        "session_key": None,
        "node_id": None,
        "node_name": None,
        "no_cipher_reference": False,
        # Flags we accept but don't translate
        "enabled_key_data": None,
        "lax_key_search": False,
        "x509_skip_strict": False,
        "x509_skip_time_checks": False,
        "hmac_min_out_len": None,
        "crypto": None,
        "crypto_config": None,
        "insecure": False,
        "verification_gmt_time": None,
        "verify_keys": False,
        "crl_files": [],
        # Unsupported flags we silently ignore
        "skipped_flags": [],
    }

    i = 0
    while i < len(args):
        arg = args[i]

        # Command
        if arg in ("--verify", "verify"):
            ctx["command"] = "verify"
        elif arg in ("--sign", "sign"):
            ctx["command"] = "sign"
        elif arg in ("--decrypt", "decrypt"):
            ctx["command"] = "decrypt"
        elif arg in ("--encrypt", "encrypt"):
            ctx["command"] = "encrypt"
        elif arg == "version":
            print("bergshamra-shim 0.1.0 (bergshamra)")
            sys.exit(0)
        elif arg in ("--help", "--help-all") or arg.startswith("--help-"):
            print("xmlsec1-shim: use bergshamra --help")
            sys.exit(0)
        elif arg == "check-transforms" or arg == "check-key-data":
            # The test runner calls these to check if features are supported.
            # Reject unsupported algorithms so the test runner skips them.
            # To re-enable a family, remove its entry from UNSUPPORTED.
            UNSUPPORTED = ("gost",)  # GOST R 34.10/34.11 — no RustCrypto crate yet
            remaining = [a for a in args[i + 1 :] if not a.startswith("-")]
            for name in remaining:
                if any(u in name.lower() for u in UNSUPPORTED):
                    print(f"xmlsec1-shim: unsupported {arg}: {name}", file=sys.stderr)
                    sys.exit(1)
            sys.exit(0)

        # Output
        elif arg == "--output":
            i += 1
            ctx["output"] = args[i]

        # Key loading
        elif arg == "--hmackey" or arg.startswith("--hmackey:"):
            name = arg.split(":", 1)[1] if ":" in arg else None
            i += 1
            ctx["hmac_key"] = (name, args[i])
        elif arg.startswith("--aeskey:") or arg == "--aeskey":
            name = arg.split(":", 1)[1] if ":" in arg else None
            i += 1
            ctx["aes_keys"].append((name, args[i]))
        elif arg.startswith("--privkey-pem:") or arg == "--privkey-pem":
            name = arg.split(":", 1)[1] if ":" in arg else None
            i += 1
            ctx["priv_keys"].append((name, args[i]))
        elif arg.startswith("--privkey-der:") or arg == "--privkey-der":
            name = arg.split(":", 1)[1] if ":" in arg else None
            i += 1
            ctx["priv_keys"].append((name, args[i]))
        elif arg.startswith("--pubkey-pem:") or arg == "--pubkey-pem":
            name = arg.split(":", 1)[1] if ":" in arg else None
            i += 1
            ctx["pub_keys"].append((name, args[i]))
        elif arg.startswith("--pubkey-der:") or arg == "--pubkey-der":
            name = arg.split(":", 1)[1] if ":" in arg else None
            i += 1
            ctx["pub_keys"].append((name, args[i]))
        elif arg.startswith("--pubkey-cert-pem:") or arg == "--pubkey-cert-pem":
            name = arg.split(":", 1)[1] if ":" in arg else None
            i += 1
            ctx["pub_cert_keys"].append((name, args[i]))
        elif arg.startswith("--pubkey-cert-der:") or arg == "--pubkey-cert-der":
            name = arg.split(":", 1)[1] if ":" in arg else None
            i += 1
            ctx["pub_cert_keys"].append((name, args[i]))
        elif arg.startswith("--pkcs12:") or arg == "--pkcs12":
            name = arg.split(":", 1)[1] if ":" in arg else None
            i += 1
            ctx["pkcs12_keys"].append((name, args[i]))
        elif arg.startswith("--pkcs8-pem:") or arg == "--pkcs8-pem":
            name = arg.split(":", 1)[1] if ":" in arg else None
            i += 1
            ctx["priv_keys"].append((name, args[i]))
        elif arg.startswith("--pkcs8-der:") or arg == "--pkcs8-der":
            name = arg.split(":", 1)[1] if ":" in arg else None
            i += 1
            ctx["priv_keys"].append((name, args[i]))
        elif arg == "--keys-file":
            i += 1
            ctx["keys_file"] = args[i]
        elif arg == "--pwd":
            i += 1
            ctx["password"] = args[i]
        elif arg.startswith("--trusted-pem") or arg.startswith("--trusted-der"):
            i += 1
            ctx["trusted_pem"].append(args[i])
        elif arg.startswith("--untrusted-pem") or arg.startswith("--untrusted-der"):
            i += 1
            if "untrusted_pem" not in ctx:
                ctx["untrusted_pem"] = []
            ctx["untrusted_pem"].append(args[i])

        # ID attrs
        elif arg.startswith("--id-attr"):
            i += 1
            ctx["id_attrs"].append(args[i])

        # Data flags
        elif arg == "--binary-data" or arg == "--binary":
            i += 1
            ctx["binary_data"] = args[i]
        elif arg == "--xml-data":
            i += 1
            ctx["xml_data"] = args[i]
        elif arg == "--session-key":
            i += 1
            ctx["session_key"] = args[i]
        elif arg == "--node-id":
            i += 1
            ctx["node_id"] = args[i]
        elif arg == "--node-name":
            i += 1
            ctx["node_name"] = args[i]

        # Flags we accept but handle implicitly
        elif arg == "--lax-key-search":
            ctx["lax_key_search"] = True
        elif arg == "--X509-skip-strict-checks":
            ctx["x509_skip_strict"] = True
        elif arg == "--X509-skip-time-checks":
            ctx["x509_skip_time_checks"] = True
        elif arg == "--verification-gmt-time":
            i += 1
            ctx["verification_gmt_time"] = args[i]
        elif arg == "--insecure":
            ctx["insecure"] = True
        elif arg == "--verify-keys":
            ctx["verify_keys"] = True
        elif arg == "--verbose":
            ctx["verbose"] = True
        elif arg == "--enabled-key-data":
            i += 1
            ctx["enabled_key_data"] = args[i]
        elif arg == "--hmac-min-out-len":
            i += 1
            ctx["hmac_min_out_len"] = args[i]
        elif arg == "--crypto":
            i += 1
            ctx["crypto"] = args[i]
        elif arg == "--crypto-config":
            i += 1
            ctx["crypto_config"] = args[i]
        elif arg == "--print-crypto-library-errors":
            pass  # silently ignore
        elif arg.startswith("--crl-pem") or arg.startswith("--crl-der"):
            i += 1
            ctx["crl_files"].append(args[i])
        elif arg == "--store-references":
            ctx["debug"] = True
        elif arg == "--store-signatures":
            ctx["debug"] = True
        elif arg == "--pkcs12-persist":
            pass  # silently ignore
        elif arg == "--repeat":
            i += 1  # silently skip
        elif arg.startswith("--enabled-reference-uris"):
            i += 1  # skip
        elif arg.startswith("--enabled-cipher-reference-uris"):
            i += 1
            if args[i] == "empty":
                ctx["no_cipher_reference"] = True
        elif arg.startswith("--url-map:"):
            url = arg.split(":", 1)[1]
            i += 1
            ctx["url_maps"].append((url, args[i]))
        elif arg.startswith("--concatkdf-key") or arg.startswith("--pbkdf2-key"):
            # --concatkdf-key:Name FILE or --pbkdf2-key:Name FILE
            # These load raw binary key files as named symmetric keys
            name = arg.split(":", 1)[1] if ":" in arg else None
            i += 1
            file_path = args[i]
            ctx["aes_keys"].append((name, file_path))
        elif arg.startswith("--privkey-openssl"):
            i += 1
            ctx["skipped_flags"].append(arg)

        # Positional: input file (last non-flag argument)
        elif not arg.startswith("-"):
            ctx["input_file"] = arg
        else:
            # Unknown flag — skip it, and consume next arg if it looks like a value
            ctx["skipped_flags"].append(arg)
            if i + 1 < len(args) and not args[i + 1].startswith("-"):
                i += 1
                ctx["skipped_flags"].append(args[i])

        i += 1

    return ctx


def _abs(path):
    """Resolve a file path to absolute (handles testrun.sh cd into subdirs).

    testrun.sh does `cd $topfolder/$folder` before calling the shim, but some
    paths (e.g. tests/keys/hmackey.bin) are relative to an ancestor directory,
    not the test subdirectory.  When the CWD-based resolution doesn't exist,
    walk up from CWD through parent directories, then try the bergshamra
    project root.
    """
    resolved = os.path.abspath(path)
    if os.path.exists(resolved):
        return resolved

    # Walk up from CWD through parent directories
    parent = os.getcwd()
    for _ in range(5):  # up to 5 levels
        parent = os.path.dirname(parent)
        if not parent or parent == os.path.dirname(parent):
            break
        alt = os.path.join(parent, path)
        if os.path.exists(alt):
            return os.path.abspath(alt)

    # Project root = parent of the directory containing this shim script
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    alt = os.path.join(project_root, path)
    if os.path.exists(alt):
        return os.path.abspath(alt)
    return resolved


def build_bergshamra_cmd(ctx):
    """Convert parsed context into a bergshamra command list."""
    cmd = [BERGSHAMRA]

    if not ctx["command"]:
        print("xmlsec1-shim: no command specified", file=sys.stderr)
        return None

    cmd.append(ctx["command"])

    # Key flags — resolve all paths to absolute
    if ctx["hmac_key"]:
        name, path = ctx["hmac_key"]
        if name:
            cmd.extend(["--hmac-key", f"{name}:{_abs(path)}"])
        else:
            cmd.extend(["--hmac-key", _abs(path)])

    for name, path in ctx["aes_keys"]:
        if name:
            cmd.extend(["-K", f"{name}:{_abs(path)}"])
        else:
            cmd.extend(["--aes-key", _abs(path)])

    # Private keys -> -k or -K name:file
    for name, path in ctx["priv_keys"]:
        if name:
            cmd.extend(["-K", f"{name}:{_abs(path)}"])
        else:
            cmd.extend(["-k", _abs(path)])

    # Public keys -> -k or -K name:file
    for name, path in ctx["pub_keys"]:
        if name:
            cmd.extend(["-K", f"{name}:{_abs(path)}"])
        else:
            cmd.extend(["-k", _abs(path)])

    # Public cert keys -> --cert (with name if available via -K)
    for name, path in ctx["pub_cert_keys"]:
        if name:
            cmd.extend(["-K", f"{name}:{_abs(path)}"])
        else:
            cmd.extend(["--cert", _abs(path)])

    # PKCS#12 keys -> --pkcs12 (with name if available via -K)
    for name, path in ctx["pkcs12_keys"]:
        if name:
            cmd.extend(["-K", f"{name}:{_abs(path)}"])
        else:
            cmd.extend(["--pkcs12", _abs(path)])

    # Password (for PKCS#12 and encrypted PEM)
    if ctx["password"]:
        cmd.extend(["--pwd", ctx["password"]])

    # Keys file (xmlsec keys.xml)
    if ctx["keys_file"]:
        cmd.extend(["--keys-file", _abs(ctx["keys_file"])])

    # Trusted certs (for verify and sign)
    if ctx["command"] in ("verify", "sign"):
        for path in ctx["trusted_pem"]:
            cmd.extend(["--trusted", _abs(path)])

    # Untrusted certs (intermediate/entity certs for chain building)
    if ctx["command"] == "verify":
        for path in ctx.get("untrusted_pem", []):
            cmd.extend(["--untrusted", _abs(path)])
    else:
        for path in ctx.get("untrusted_pem", []):
            cmd.extend(["--cert", _abs(path)])

    # URL maps (for verify and sign)
    if ctx["command"] in ("verify", "sign"):
        for url, path in ctx["url_maps"]:
            cmd.extend(["--url-map", f"{url}={_abs(path)}"])

        # Auto-add url-map for tests/ → test-data/ so relative URIs in
        # RetrievalMethod (e.g. "tests/keys/dsa/dsa-1024-cert.der") resolve
        # correctly even when verifying signed output from /tmp.
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        test_data_dir = os.path.join(project_root, "test-data")
        if os.path.isdir(test_data_dir):
            cmd.extend(["--url-map", f"tests/={test_data_dir}"])

    # ID attrs
    for attr in ctx["id_attrs"]:
        cmd.extend(["--id-attr", attr])

    # HMAC minimum output length
    if ctx["hmac_min_out_len"] and ctx["command"] == "verify":
        cmd.extend(["--hmac-min-out-len", ctx["hmac_min_out_len"]])

    # Output
    if ctx["output"]:
        cmd.extend(["-o", _abs(ctx["output"])])

    # Session key (for sign command)
    if ctx["session_key"] and ctx["command"] == "sign":
        cmd.extend(["--session-key", ctx["session_key"]])

    # Verbose
    if ctx["verbose"]:
        cmd.append("-v")

    # Debug (store-references / store-signatures)
    if ctx["debug"] and ctx["command"] in ("verify", "sign"):
        cmd.append("--debug")

    # X.509 validation flags (verify only)
    if ctx["command"] == "verify":
        if ctx["insecure"]:
            cmd.append("--insecure")
        if ctx["verify_keys"]:
            cmd.append("--verify-keys")
        if ctx["verification_gmt_time"]:
            cmd.extend(["--verification-gmt-time", ctx["verification_gmt_time"]])
        if ctx["x509_skip_time_checks"]:
            cmd.append("--x509-skip-time-checks")
        if ctx["enabled_key_data"]:
            cmd.extend(["--enabled-key-data", ctx["enabled_key_data"]])
        for path in ctx["crl_files"]:
            cmd.extend(["--crl", _abs(path)])

    # Decrypt-specific flags
    if ctx["command"] == "decrypt":
        if ctx.get("no_cipher_reference"):
            cmd.append("--no-cipher-reference")

    # Encrypt-specific flags
    if ctx["command"] == "encrypt":
        data_file = ctx["xml_data"] or ctx["binary_data"]
        if data_file:
            cmd.extend(["--data", _abs(data_file)])
        if ctx.get("node_name"):
            cmd.extend(["--node-name", ctx["node_name"]])
        if ctx.get("node_id"):
            cmd.extend(["--node-id", ctx["node_id"]])

    # Input file must be last
    if ctx["input_file"]:
        cmd.append(_abs(ctx["input_file"]))
    else:
        print("xmlsec1-shim: no input file specified", file=sys.stderr)
        return None

    return cmd


def main():
    args = sys.argv[1:]

    if not args:
        print("xmlsec1-shim: no arguments", file=sys.stderr)
        sys.exit(1)

    ctx = parse_xmlsec1_args(args)
    cmd = build_bergshamra_cmd(ctx)

    if cmd is None:
        sys.exit(1)

    if os.environ.get("XMLSEC_SHIM_DEBUG"):
        print(f"xmlsec1-shim: {' '.join(cmd)}", file=sys.stderr)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        # Print bergshamra output
        if result.stdout:
            sys.stdout.write(result.stdout)
        if result.stderr:
            sys.stderr.write(result.stderr)
        sys.exit(result.returncode)
    except FileNotFoundError:
        print(f"xmlsec1-shim: bergshamra not found at {BERGSHAMRA}", file=sys.stderr)
        print(
            "Set BERGSHAMRA env var or build with: cargo build --release",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
