#!/usr/bin/env python3
"""Deterministic XML fixture generator for bergshamra performance scripts.

Produces the SAML-shaped fixture family used by the memory and CLI-timing
harnesses. Output is fully deterministic (no timestamps, no randomness), so
runs are reproducible and byte-identical across machines.

Usage: gen_fixture.py SIZE_CLASS OUT_DIR
    SIZE_CLASS: small | medium | large   (≈ 30 KB / 1 MB / 10 MB)

An unsigned document and a matching enveloped-signature template (RSA-SHA256,
inclusive C14N 1.0 for both SignedInfo and the reference transform,
whole-document reference) are written to OUT_DIR.
"""

import os
import sys

ASSERTION = (
    '<saml:Assertion ID="_assertion{i}" Version="2.0" '
    'IssueInstant="2026-06-29T12:00:00Z">'
    "<saml:Issuer>https://idp.example.org/metadata</saml:Issuer>"
    "<saml:Subject><saml:NameID "
    'Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">'
    "user-{i}@example.org</saml:NameID>"
    '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
    '<saml:SubjectConfirmationData NotOnOrAfter="2026-06-29T12:05:00Z" '
    'Recipient="https://sp.example.org/acs"/></saml:SubjectConfirmation>'
    "</saml:Subject><saml:AttributeStatement>"
    '<saml:Attribute Name="urn:oid:1.2.3.4" '
    'NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">'
    "<saml:AttributeValue>value &amp; {i} &lt; threshold"
    "</saml:AttributeValue></saml:Attribute>"
    "</saml:AttributeStatement></saml:Assertion>"
)

SIGNATURE_TEMPLATE = (
    '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
    "<ds:SignedInfo>"
    '<ds:CanonicalizationMethod Algorithm='
    '"http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>'
    '<ds:SignatureMethod Algorithm='
    '"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>'
    '<ds:Reference URI="">'
    "<ds:Transforms>"
    '<ds:Transform Algorithm='
    '"http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>'
    '<ds:Transform Algorithm='
    '"http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>'
    "</ds:Transforms>"
    '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
    "<ds:DigestValue></ds:DigestValue>"
    "</ds:Reference>"
    "</ds:SignedInfo>"
    "<ds:SignatureValue></ds:SignatureValue>"
    "</ds:Signature>"
)


def document(assertions: int) -> str:
    parts = [
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
        'xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="_response" '
        'Version="2.0" IssueInstant="2026-06-29T12:00:00Z">',
        "<saml:Issuer>https://idp.example.org/metadata</saml:Issuer>",
    ]
    parts.extend(ASSERTION.format(i=i) for i in range(assertions))
    parts.append("</samlp:Response>")
    return "".join(parts)


# Rough assertion size (~720 bytes) used to hit the size classes.
BYTES_PER_ASSERTION = 720
SIZE_CLASSES = {
    "small": 40,        # ≈ 30 KB  — matches the criterion fixture family
    "medium": 1_500,    # ≈ 1 MB
    "large": 15_000,    # ≈ 10 MB  — matches the performance.md memory fixture
}


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    size_class, out_dir = sys.argv[1], sys.argv[2]
    if size_class not in SIZE_CLASSES:
        print(f"unknown size class {size_class!r}; expected one of {sorted(SIZE_CLASSES)}")
        return 2

    os.makedirs(out_dir, exist_ok=True)
    xml = document(SIZE_CLASSES[size_class])

    # Enveloped-signature template: the full document with an empty Signature
    # stub inserted inside the root element, so the CLI signs the whole
    # document (URI="" reference) rather than the stub alone.
    marker = "</samlp:Response>"
    if not xml.endswith(marker):
        raise SystemExit("fixture document must end with the samlp:Response close tag")
    template_xml = xml[: -len(marker)] + SIGNATURE_TEMPLATE + marker

    unsigned = os.path.join(out_dir, f"{size_class}_unsigned.xml")
    template = os.path.join(out_dir, f"{size_class}_template.xml")
    for path, body in ((unsigned, xml), (template, template_xml)):
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)
        print(f"{path}: {len(body)} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
