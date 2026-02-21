#![forbid(unsafe_code)]

//! XML namespace constants used across the library.

/// XML Digital Signature namespace
pub const DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";

/// XML Digital Signature 1.1 namespace
pub const DSIG11: &str = "http://www.w3.org/2009/xmldsig11#";

/// XML Encryption namespace
pub const ENC: &str = "http://www.w3.org/2001/04/xmlenc#";

/// XML Encryption 1.1 namespace
pub const ENC11: &str = "http://www.w3.org/2009/xmlenc11#";

/// Exclusive C14N namespace
pub const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";

/// XPath namespace
pub const XPATH: &str = "http://www.w3.org/TR/1999/REC-xpath-19991116";

/// XPath Filter 2.0 namespace
pub const XPATH2: &str = "http://www.w3.org/2002/06/xmldsig-filter2";

/// XPointer namespace
pub const XPOINTER: &str = "http://www.w3.org/2001/04/xmldsig-more/xptr";

/// XML namespace
pub const XML: &str = "http://www.w3.org/XML/1998/namespace";

/// XMLNS namespace
pub const XMLNS: &str = "http://www.w3.org/2000/xmlns/";

/// xmlsec post-quantum extensions namespace
pub const XMLSEC_PQ: &str = "http://www.aleksey.com/xmlsec/2025/12/xmldsig-more#";

/// OOXML Relationships namespace
pub const RELATIONSHIPS: &str = "http://schemas.openxmlformats.org/package/2006/relationships";

/// OOXML Relationship Reference namespace
pub const RELATIONSHIP_REFERENCE: &str =
    "http://schemas.openxmlformats.org/package/2006/digital-signature";

// ── Element names ────────────────────────────────────────────────────

pub mod node {
    // DSig elements
    pub const SIGNATURE: &str = "Signature";
    pub const SIGNED_INFO: &str = "SignedInfo";
    pub const CANONICALIZATION_METHOD: &str = "CanonicalizationMethod";
    pub const SIGNATURE_METHOD: &str = "SignatureMethod";
    pub const SIGNATURE_VALUE: &str = "SignatureValue";
    pub const DIGEST_METHOD: &str = "DigestMethod";
    pub const DIGEST_VALUE: &str = "DigestValue";
    pub const OBJECT: &str = "Object";
    pub const MANIFEST: &str = "Manifest";
    pub const SIGNATURE_PROPERTIES: &str = "SignatureProperties";
    pub const REFERENCE: &str = "Reference";
    pub const TRANSFORMS: &str = "Transforms";
    pub const TRANSFORM: &str = "Transform";

    // KeyInfo elements
    pub const KEY_INFO: &str = "KeyInfo";
    pub const KEY_NAME: &str = "KeyName";
    pub const KEY_VALUE: &str = "KeyValue";
    pub const RETRIEVAL_METHOD: &str = "RetrievalMethod";
    pub const KEY_INFO_REFERENCE: &str = "KeyInfoReference";
    pub const DER_ENCODED_KEY_VALUE: &str = "DEREncodedKeyValue";

    // RSA elements
    pub const RSA_KEY_VALUE: &str = "RSAKeyValue";
    pub const RSA_MODULUS: &str = "Modulus";
    pub const RSA_EXPONENT: &str = "Exponent";
    pub const RSA_PRIVATE_EXPONENT: &str = "PrivateExponent";
    pub const RSA_OAEP_PARAMS: &str = "OAEPparams";
    pub const RSA_MGF: &str = "MGF";

    // DSA elements
    pub const DSA_KEY_VALUE: &str = "DSAKeyValue";
    pub const DSA_P: &str = "P";
    pub const DSA_Q: &str = "Q";
    pub const DSA_G: &str = "G";
    pub const DSA_J: &str = "J";
    pub const DSA_X: &str = "X";
    pub const DSA_Y: &str = "Y";
    pub const DSA_SEED: &str = "Seed";
    pub const DSA_PGEN_COUNTER: &str = "PgenCounter";

    // EC elements
    pub const EC_KEY_VALUE: &str = "ECKeyValue";
    pub const NAMED_CURVE: &str = "NamedCurve";
    pub const PUBLIC_KEY: &str = "PublicKey";

    // DH elements
    pub const DH_KEY_VALUE: &str = "DHKeyValue";

    // HMAC elements
    pub const HMAC_KEY_VALUE: &str = "HMACKeyValue";
    pub const HMAC_OUTPUT_LENGTH: &str = "HMACOutputLength";

    // X509 elements
    pub const X509_DATA: &str = "X509Data";
    pub const X509_CERTIFICATE: &str = "X509Certificate";
    pub const X509_CRL: &str = "X509CRL";
    pub const X509_SUBJECT_NAME: &str = "X509SubjectName";
    pub const X509_ISSUER_SERIAL: &str = "X509IssuerSerial";
    pub const X509_ISSUER_NAME: &str = "X509IssuerName";
    pub const X509_SERIAL_NUMBER: &str = "X509SerialNumber";
    pub const X509_SKI: &str = "X509SKI";
    pub const X509_DIGEST: &str = "X509Digest";

    // Encryption elements
    pub const ENCRYPTED_DATA: &str = "EncryptedData";
    pub const ENCRYPTION_METHOD: &str = "EncryptionMethod";
    pub const ENCRYPTION_PROPERTIES: &str = "EncryptionProperties";
    pub const ENCRYPTION_PROPERTY: &str = "EncryptionProperty";
    pub const CIPHER_DATA: &str = "CipherData";
    pub const CIPHER_VALUE: &str = "CipherValue";
    pub const CIPHER_REFERENCE: &str = "CipherReference";
    pub const REFERENCE_LIST: &str = "ReferenceList";
    pub const DATA_REFERENCE: &str = "DataReference";
    pub const KEY_REFERENCE: &str = "KeyReference";
    pub const CARRIED_KEY_NAME: &str = "CarriedKeyName";
    pub const ENCRYPTED_KEY: &str = "EncryptedKey";

    // Key derivation elements
    pub const DERIVED_KEY: &str = "DerivedKey";
    pub const KEY_DERIVATION_METHOD: &str = "KeyDerivationMethod";
    pub const DERIVED_KEY_NAME: &str = "DerivedKeyName";
    pub const MASTER_KEY_NAME: &str = "MasterKeyName";

    // Agreement method elements
    pub const AGREEMENT_METHOD: &str = "AgreementMethod";
    pub const ORIGINATOR_KEY_INFO: &str = "OriginatorKeyInfo";
    pub const RECIPIENT_KEY_INFO: &str = "RecipientKeyInfo";

    // PBKDF2 elements
    pub const PBKDF2_PARAMS: &str = "PBKDF2-params";
    pub const PBKDF2_SALT: &str = "Salt";
    pub const PBKDF2_SALT_SPECIFIED: &str = "Specified";
    pub const PBKDF2_ITERATION_COUNT: &str = "IterationCount";
    pub const PBKDF2_KEY_LENGTH: &str = "KeyLength";
    pub const PBKDF2_PRF: &str = "PRF";

    // ConcatKDF elements
    pub const CONCAT_KDF_PARAMS: &str = "ConcatKDFParams";

    // XPath / Exc C14N
    pub const XPATH: &str = "XPath";
    pub const XPOINTER: &str = "XPointer";
    pub const INCLUSIVE_NAMESPACES: &str = "InclusiveNamespaces";

    // PGP/SPKI
    pub const PGP_DATA: &str = "PGPData";
    pub const SPKI_DATA: &str = "SPKIData";

    // AES/DES key value
    pub const AES_KEY_VALUE: &str = "AESKeyValue";
    pub const DES_KEY_VALUE: &str = "DESKeyValue";

    // Post-quantum context string elements
    pub const MLDSA_CONTEXT_STRING: &str = "MLDSAContextString";
    pub const SLHDSA_CONTEXT_STRING: &str = "SLHDSAContextString";
}

// ── Attribute names ──────────────────────────────────────────────────

pub mod attr {
    pub const ID: &str = "Id";
    pub const URI: &str = "URI";
    pub const TYPE: &str = "Type";
    pub const MIME_TYPE: &str = "MimeType";
    pub const ENCODING: &str = "Encoding";
    pub const ALGORITHM: &str = "Algorithm";
    pub const FILTER: &str = "Filter";
    pub const RECIPIENT: &str = "Recipient";
    pub const TARGET: &str = "Target";
    pub const PREFIX_LIST: &str = "PrefixList";
}

// ── Encryption type URIs ─────────────────────────────────────────────

pub const ENC_TYPE_CONTENT: &str = "http://www.w3.org/2001/04/xmlenc#Content";
pub const ENC_TYPE_ELEMENT: &str = "http://www.w3.org/2001/04/xmlenc#Element";

// ── XPath2 filter values ─────────────────────────────────────────────

pub const XPATH2_FILTER_INTERSECT: &str = "intersect";
pub const XPATH2_FILTER_SUBTRACT: &str = "subtract";
pub const XPATH2_FILTER_UNION: &str = "union";
