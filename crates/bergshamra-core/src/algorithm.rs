#![forbid(unsafe_code)]

//! Algorithm URI constants for XML Security.
//!
//! Ported from xmlsec `src/strings.c`. Each constant is the canonical
//! URI string that appears in `Algorithm` attributes.

// ── Canonicalization ─────────────────────────────────────────────────

pub const C14N: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
pub const C14N_WITH_COMMENTS: &str =
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
pub const C14N11: &str = "http://www.w3.org/2006/12/xml-c14n11";
pub const C14N11_WITH_COMMENTS: &str = "http://www.w3.org/2006/12/xml-c14n11#WithComments";
pub const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
pub const EXC_C14N_WITH_COMMENTS: &str = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";

// ── Digest algorithms ────────────────────────────────────────────────

pub const SHA1: &str = "http://www.w3.org/2000/09/xmldsig#sha1";
pub const SHA224: &str = "http://www.w3.org/2001/04/xmldsig-more#sha224";
pub const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
pub const SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#sha384";
pub const SHA512: &str = "http://www.w3.org/2001/04/xmlenc#sha512";
pub const SHA3_224: &str = "http://www.w3.org/2007/05/xmldsig-more#sha3-224";
pub const SHA3_256: &str = "http://www.w3.org/2007/05/xmldsig-more#sha3-256";
pub const SHA3_384: &str = "http://www.w3.org/2007/05/xmldsig-more#sha3-384";
pub const SHA3_512: &str = "http://www.w3.org/2007/05/xmldsig-more#sha3-512";
pub const MD5: &str = "http://www.w3.org/2001/04/xmldsig-more#md5";
pub const RIPEMD160: &str = "http://www.w3.org/2001/04/xmlenc#ripemd160";

// ── RSA signature algorithms ─────────────────────────────────────────

pub const RSA_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
pub const RSA_SHA224: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha224";
pub const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
pub const RSA_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
pub const RSA_SHA512: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
pub const RSA_MD5: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-md5";
pub const RSA_RIPEMD160: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-ripemd160";

// ── RSA-PSS signature algorithms ─────────────────────────────────────

pub const RSA_PSS_SHA1: &str = "http://www.w3.org/2007/05/xmldsig-more#sha1-rsa-MGF1";
pub const RSA_PSS_SHA224: &str = "http://www.w3.org/2007/05/xmldsig-more#sha224-rsa-MGF1";
pub const RSA_PSS_SHA256: &str = "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1";
pub const RSA_PSS_SHA384: &str = "http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1";
pub const RSA_PSS_SHA512: &str = "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1";
pub const RSA_PSS_SHA3_224: &str = "http://www.w3.org/2007/05/xmldsig-more#sha3-224-rsa-MGF1";
pub const RSA_PSS_SHA3_256: &str = "http://www.w3.org/2007/05/xmldsig-more#sha3-256-rsa-MGF1";
pub const RSA_PSS_SHA3_384: &str = "http://www.w3.org/2007/05/xmldsig-more#sha3-384-rsa-MGF1";
pub const RSA_PSS_SHA3_512: &str = "http://www.w3.org/2007/05/xmldsig-more#sha3-512-rsa-MGF1";

// ── DSA signature algorithms ─────────────────────────────────────────

pub const DSA_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#dsa-sha1";
pub const DSA_SHA256: &str = "http://www.w3.org/2009/xmldsig11#dsa-sha256";

// ── ECDSA signature algorithms ───────────────────────────────────────

pub const ECDSA_SHA1: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1";
pub const ECDSA_SHA224: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224";
pub const ECDSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
pub const ECDSA_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
pub const ECDSA_SHA512: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";
pub const ECDSA_RIPEMD160: &str = "http://www.w3.org/2007/05/xmldsig-more#ecdsa-ripemd160";
pub const ECDSA_SHA3_224: &str = "http://www.w3.org/2021/04/xmldsig-more#ecdsa-sha3-224";
pub const ECDSA_SHA3_256: &str = "http://www.w3.org/2021/04/xmldsig-more#ecdsa-sha3-256";
pub const ECDSA_SHA3_384: &str = "http://www.w3.org/2021/04/xmldsig-more#ecdsa-sha3-384";
pub const ECDSA_SHA3_512: &str = "http://www.w3.org/2021/04/xmldsig-more#ecdsa-sha3-512";

// ── HMAC signature algorithms ────────────────────────────────────────

pub const HMAC_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#hmac-sha1";
pub const HMAC_SHA224: &str = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha224";
pub const HMAC_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256";
pub const HMAC_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha384";
pub const HMAC_SHA512: &str = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512";
pub const HMAC_MD5: &str = "http://www.w3.org/2001/04/xmldsig-more#hmac-md5";
pub const HMAC_RIPEMD160: &str = "http://www.w3.org/2001/04/xmldsig-more#hmac-ripemd160";

// ── Block cipher algorithms ──────────────────────────────────────────

pub const AES128_CBC: &str = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
pub const AES192_CBC: &str = "http://www.w3.org/2001/04/xmlenc#aes192-cbc";
pub const AES256_CBC: &str = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
pub const AES128_GCM: &str = "http://www.w3.org/2009/xmlenc11#aes128-gcm";
pub const AES192_GCM: &str = "http://www.w3.org/2009/xmlenc11#aes192-gcm";
pub const AES256_GCM: &str = "http://www.w3.org/2009/xmlenc11#aes256-gcm";
pub const TRIPLEDES_CBC: &str = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc";

// ── Key wrap algorithms ──────────────────────────────────────────────

pub const KW_AES128: &str = "http://www.w3.org/2001/04/xmlenc#kw-aes128";
pub const KW_AES192: &str = "http://www.w3.org/2001/04/xmlenc#kw-aes192";
pub const KW_AES256: &str = "http://www.w3.org/2001/04/xmlenc#kw-aes256";
pub const KW_TRIPLEDES: &str = "http://www.w3.org/2001/04/xmlenc#kw-tripledes";

// ── Key transport algorithms ─────────────────────────────────────────

pub const RSA_PKCS1: &str = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";
pub const RSA_OAEP: &str = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
pub const RSA_OAEP_ENC11: &str = "http://www.w3.org/2009/xmlenc11#rsa-oaep";

// ── MGF algorithms ───────────────────────────────────────────────────

pub const MGF1_SHA1: &str = "http://www.w3.org/2009/xmlenc11#mgf1sha1";
pub const MGF1_SHA224: &str = "http://www.w3.org/2009/xmlenc11#mgf1sha224";
pub const MGF1_SHA256: &str = "http://www.w3.org/2009/xmlenc11#mgf1sha256";
pub const MGF1_SHA384: &str = "http://www.w3.org/2009/xmlenc11#mgf1sha384";
pub const MGF1_SHA512: &str = "http://www.w3.org/2009/xmlenc11#mgf1sha512";

// ── Key agreement algorithms ─────────────────────────────────────────

pub const DH_ES: &str = "http://www.w3.org/2009/xmlenc11#dh-es";
pub const ECDH_ES: &str = "http://www.w3.org/2009/xmlenc11#ECDH-ES";

// ── Key derivation algorithms ────────────────────────────────────────

pub const PBKDF2: &str = "http://www.w3.org/2009/xmlenc11#pbkdf2";
pub const CONCAT_KDF: &str = "http://www.w3.org/2009/xmlenc11#ConcatKDF";

// ── Transform algorithms ─────────────────────────────────────────────

pub const BASE64: &str = "http://www.w3.org/2000/09/xmldsig#base64";
pub const ENVELOPED_SIGNATURE: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
pub const XPATH: &str = "http://www.w3.org/TR/1999/REC-xpath-19991116";
pub const XPATH2: &str = "http://www.w3.org/2002/06/xmldsig-filter2";
pub const XSLT: &str = "http://www.w3.org/TR/1999/REC-xslt-19991116";
pub const XPOINTER: &str = "http://www.w3.org/2001/04/xmldsig-more/xptr";
pub const RELATIONSHIP: &str =
    "http://schemas.openxmlformats.org/package/2006/RelationshipTransform";

// ── KeyValue type URIs ───────────────────────────────────────────────

pub const RSA_KEY_VALUE: &str = "http://www.w3.org/2000/09/xmldsig#RSAKeyValue";
pub const DSA_KEY_VALUE: &str = "http://www.w3.org/2000/09/xmldsig#DSAKeyValue";
pub const EC_KEY_VALUE: &str = "http://www.w3.org/2009/xmldsig11#ECKeyValue";
pub const DH_KEY_VALUE: &str = "http://www.w3.org/2001/04/xmlenc#DHKeyValue";
pub const DER_ENCODED_KEY_VALUE: &str = "http://www.w3.org/2009/xmldsig11#DEREncodedKeyValue";

// ── X509 URIs ────────────────────────────────────────────────────────

pub const X509_DATA: &str = "http://www.w3.org/2000/09/xmldsig#X509Data";
pub const RAW_X509_CERT: &str = "http://www.w3.org/2000/09/xmldsig#rawX509Certificate";

// ── Encrypted key / derived key URIs ─────────────────────────────────

pub const ENCRYPTED_KEY: &str = "http://www.w3.org/2001/04/xmlenc#EncryptedKey";
pub const DERIVED_KEY: &str = "http://www.w3.org/2009/xmlenc11#DerivedKey";
