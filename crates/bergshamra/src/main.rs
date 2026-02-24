#![forbid(unsafe_code)]

//! Bergshamra CLI — XML Security operations (sign, verify, encrypt, decrypt).

use bergshamra_core::Error;
use bergshamra_keys::key::{Key, KeyData, KeyUsage};
use bergshamra_keys::KeysManager;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process;

#[derive(Parser)]
#[command(
    name = "bergshamra",
    about = "Bergshamra — Pure Rust XML Security (XML-DSig, XML-Enc, C14N)",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Verify a signed XML document
    Verify {
        /// Input XML file
        file: PathBuf,

        /// Load private/public key (PEM or DER, auto-detected)
        #[arg(short = 'k', long)]
        key: Option<PathBuf>,

        /// Load key with a name (NAME:FILE)
        #[arg(short = 'K', long = "key-name")]
        key_name: Vec<String>,

        /// Load X.509 certificate (PEM or DER)
        #[arg(long)]
        cert: Vec<PathBuf>,

        /// Load trusted CA certificate(s)
        #[arg(long)]
        trusted: Vec<PathBuf>,

        /// Load PKCS#12 (.p12/.pfx) key file
        #[arg(long)]
        pkcs12: Option<PathBuf>,

        /// Password for PKCS#12 or encrypted PEM keys
        #[arg(long)]
        pwd: Option<String>,

        /// Load raw HMAC key (binary file)
        #[arg(long = "hmac-key")]
        hmac_key: Option<PathBuf>,

        /// Load keys from xmlsec keys.xml file
        #[arg(long = "keys-file")]
        keys_file: Option<PathBuf>,

        /// Map external URI to local file (URL=FILE)
        #[arg(long = "url-map")]
        url_map: Vec<String>,

        /// Register additional ID attribute names
        #[arg(long = "id-attr")]
        id_attr: Vec<String>,

        /// Minimum HMAC output length in bits (default: spec-derived)
        #[arg(long = "hmac-min-out-len")]
        hmac_min_out_len: Option<usize>,

        /// Debug: print pre-digest and pre-signature data to stderr
        #[arg(long)]
        debug: bool,

        /// Verbose output
        #[arg(short, long)]
        verbose: bool,

        /// Skip X.509 certificate validation (insecure mode)
        #[arg(long)]
        insecure: bool,

        /// Verify keys loaded from cert files (validate their certificates)
        #[arg(long = "verify-keys")]
        verify_keys: bool,

        /// Override verification time (format: YYYY-MM-DD+HH:MM:SS)
        #[arg(long = "verification-gmt-time")]
        verification_gmt_time: Option<String>,

        /// Skip X.509 certificate time checks
        #[arg(long = "x509-skip-time-checks")]
        x509_skip_time_checks: bool,

        /// Specify enabled key data types (e.g., x509, key-value, key-name)
        #[arg(long = "enabled-key-data")]
        enabled_key_data: Option<String>,

        /// Strict verification: reject references to nodes that are not ancestors,
        /// siblings, or the document element relative to the Signature (XSW protection)
        #[arg(long)]
        strict: bool,

        /// Only use pre-loaded keys for verification; ignore inline keys in KeyInfo
        /// (KeyValue, X509Certificate, etc.). Essential for SAML and other deployments
        /// where the signing key is known ahead of time.
        #[arg(long = "trusted-keys-only")]
        trusted_keys_only: bool,

        /// Load untrusted intermediate certificate(s)
        #[arg(long)]
        untrusted: Vec<PathBuf>,

        /// Load CRL file (DER or PEM)
        #[arg(long)]
        crl: Vec<PathBuf>,
    },

    /// Sign an XML template
    Sign {
        /// Template XML file (with empty DigestValue/SignatureValue)
        template: PathBuf,

        /// Load private key (PEM or DER)
        #[arg(short = 'k', long)]
        key: Option<PathBuf>,

        /// Load key with a name (NAME:FILE)
        #[arg(short = 'K', long = "key-name")]
        key_name: Vec<String>,

        /// Load X.509 certificate (PEM or DER) for X509Data population
        #[arg(long)]
        cert: Vec<PathBuf>,

        /// Load trusted CA certificate(s)
        #[arg(long)]
        trusted: Vec<PathBuf>,

        /// Load PKCS#12 (.p12/.pfx) key file
        #[arg(long)]
        pkcs12: Option<PathBuf>,

        /// Password for PKCS#12 or encrypted PEM keys
        #[arg(long)]
        pwd: Option<String>,

        /// Load raw HMAC key (binary file)
        #[arg(long = "hmac-key")]
        hmac_key: Option<PathBuf>,

        /// Load keys from xmlsec keys.xml file
        #[arg(long = "keys-file")]
        keys_file: Option<PathBuf>,

        /// Map external URI to local file (URL=FILE)
        #[arg(long = "url-map")]
        url_map: Vec<String>,

        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Register additional ID attribute names
        #[arg(long = "id-attr")]
        id_attr: Vec<String>,

        /// Generate a random session key (e.g. hmac-192, aes-128, des-192)
        #[arg(long = "session-key")]
        session_key: Option<String>,

        /// Debug: print pre-digest and pre-signature data to stderr
        #[arg(long)]
        debug: bool,

        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
    },

    /// Decrypt an encrypted XML document
    Decrypt {
        /// Input encrypted XML file
        file: PathBuf,

        /// Load private key (PEM or DER)
        #[arg(short = 'k', long)]
        key: Option<PathBuf>,

        /// Load key with a name (NAME:FILE)
        #[arg(short = 'K', long = "key-name")]
        key_name: Vec<String>,

        /// Load PKCS#12 (.p12/.pfx) key file
        #[arg(long)]
        pkcs12: Option<PathBuf>,

        /// Password for PKCS#12 or encrypted PEM keys
        #[arg(long)]
        pwd: Option<String>,

        /// Load raw HMAC key (binary file)
        #[arg(long = "hmac-key")]
        hmac_key: Option<PathBuf>,

        /// Load raw AES key (binary file)
        #[arg(long = "aes-key")]
        aes_key: Option<PathBuf>,

        /// Load keys from xmlsec keys.xml file
        #[arg(long = "keys-file")]
        keys_file: Option<PathBuf>,

        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Register additional ID attribute names
        #[arg(long = "id-attr")]
        id_attr: Vec<String>,

        /// Disable CipherReference resolution
        #[arg(long = "no-cipher-reference")]
        no_cipher_reference: bool,

        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
    },

    /// Encrypt XML data using a template
    Encrypt {
        /// Template XML file (with empty CipherValue)
        template: PathBuf,

        /// XML data file to encrypt
        #[arg(long)]
        data: PathBuf,

        /// Load public key or certificate(s) for key transport
        #[arg(long)]
        cert: Vec<PathBuf>,

        /// Load key with a name (NAME:FILE)
        #[arg(short = 'K', long = "key-name")]
        key_name: Vec<String>,

        /// Load PKCS#12 (.p12/.pfx) key file
        #[arg(long)]
        pkcs12: Option<PathBuf>,

        /// Password for PKCS#12 or encrypted PEM keys
        #[arg(long)]
        pwd: Option<String>,

        /// Load raw AES key (binary file)
        #[arg(long = "aes-key")]
        aes_key: Option<PathBuf>,

        /// Load keys from xmlsec keys.xml file
        #[arg(long = "keys-file")]
        keys_file: Option<PathBuf>,

        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Register additional ID attribute names
        #[arg(long = "id-attr")]
        id_attr: Vec<String>,

        /// Select element to encrypt by namespace:localname (e.g. http://example.org:CreditCard)
        #[arg(long = "node-name")]
        node_name: Option<String>,

        /// Select element to encrypt by ID attribute value
        #[arg(long = "node-id")]
        node_id: Option<String>,

        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
    },

    /// List supported algorithms and key types
    Info,
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Verify {
            file,
            key,
            key_name,
            cert,
            trusted,
            pkcs12,
            pwd,
            hmac_key,
            keys_file,
            url_map,
            id_attr,
            hmac_min_out_len,
            debug,
            verbose,
            insecure,
            verify_keys,
            verification_gmt_time,
            x509_skip_time_checks,
            enabled_key_data,
            strict,
            trusted_keys_only,
            untrusted,
            crl,
        } => cmd_verify(
            file,
            key,
            key_name,
            cert,
            trusted,
            pkcs12,
            pwd,
            hmac_key,
            keys_file,
            url_map,
            id_attr,
            hmac_min_out_len,
            debug,
            verbose,
            insecure,
            verify_keys,
            verification_gmt_time,
            x509_skip_time_checks,
            enabled_key_data,
            strict,
            trusted_keys_only,
            untrusted,
            crl,
        ),

        Commands::Sign {
            template,
            key,
            key_name,
            cert,
            trusted,
            pkcs12,
            pwd,
            hmac_key,
            keys_file,
            url_map,
            output,
            id_attr,
            session_key,
            debug,
            verbose,
        } => cmd_sign(
            template,
            key,
            key_name,
            cert,
            trusted,
            pkcs12,
            pwd,
            hmac_key,
            keys_file,
            url_map,
            output,
            id_attr,
            session_key,
            debug,
            verbose,
        ),

        Commands::Decrypt {
            file,
            key,
            key_name,
            pkcs12,
            pwd,
            hmac_key,
            aes_key,
            keys_file,
            output,
            id_attr,
            no_cipher_reference,
            verbose,
        } => cmd_decrypt(
            file,
            key,
            key_name,
            pkcs12,
            pwd,
            hmac_key,
            aes_key,
            keys_file,
            output,
            id_attr,
            no_cipher_reference,
            verbose,
        ),

        Commands::Encrypt {
            template,
            data,
            cert,
            key_name,
            pkcs12,
            pwd,
            aes_key,
            keys_file,
            output,
            id_attr,
            node_name,
            node_id,
            verbose,
        } => cmd_encrypt(
            template, data, cert, key_name, pkcs12, pwd, aes_key, keys_file, output, id_attr,
            node_name, node_id, verbose,
        ),

        Commands::Info => cmd_info(),
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        process::exit(1);
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_verify(
    file: PathBuf,
    key: Option<PathBuf>,
    key_name: Vec<String>,
    certs: Vec<PathBuf>,
    trusted: Vec<PathBuf>,
    pkcs12: Option<PathBuf>,
    pwd: Option<String>,
    hmac_key: Option<PathBuf>,
    keys_file: Option<PathBuf>,
    url_map: Vec<String>,
    id_attr: Vec<String>,
    hmac_min_out_len: Option<usize>,
    debug: bool,
    verbose: bool,
    insecure: bool,
    verify_keys: bool,
    verification_gmt_time: Option<String>,
    x509_skip_time_checks: bool,
    enabled_key_data: Option<String>,
    strict: bool,
    trusted_keys_only: bool,
    untrusted: Vec<PathBuf>,
    crl: Vec<PathBuf>,
) -> Result<(), Error> {
    let xml = read_file(&file)?;
    // Pass untrusted certs as additional cert keys (loaded before trusted certs)
    // so they're available for key resolution by X509Digest, IssuerSerial, etc.
    let mut all_certs = certs;
    all_certs.extend(untrusted.iter().cloned());
    let mut mgr = build_keys_manager(
        key,
        key_name,
        all_certs,
        trusted.clone(),
        pkcs12,
        pwd.as_deref(),
        hmac_key,
        None,
        keys_file,
    )?;

    // Load trusted certs as DER into the manager's trusted cert store
    for path in &trusted {
        let der_certs = load_certs_as_der(path)?;
        for der in der_certs {
            mgr.add_trusted_cert(der);
        }
    }

    // Load untrusted intermediate certs into the cert store for chain building
    for path in &untrusted {
        let der_certs = load_certs_as_der(path)?;
        for der in der_certs {
            mgr.add_untrusted_cert(der);
        }
    }

    // Load CRLs
    for path in &crl {
        let der_crls = load_crl_as_der(path)?;
        for der in der_crls {
            mgr.add_crl(der);
        }
    }

    let mut ctx = bergshamra_dsig::DsigContext::new(mgr);
    for attr in &id_attr {
        ctx.add_id_attr(attr);
    }
    for spec in &url_map {
        if let Some((url, file_path)) = spec.split_once('=') {
            ctx.add_url_map(url, file_path);
        }
    }
    if let Some(min_len) = hmac_min_out_len {
        ctx.hmac_min_out_len = min_len;
    }
    ctx.debug = debug;
    if let Some(parent) = file.parent() {
        ctx.base_dir = Some(parent.to_string_lossy().into_owned());
    }
    ctx.insecure = insecure;
    ctx.verify_keys = verify_keys;
    ctx.verification_time = verification_gmt_time;
    ctx.skip_time_checks = x509_skip_time_checks;
    ctx.enabled_key_data_x509 = enabled_key_data
        .as_deref()
        .map(|s| s.split(',').any(|part| part.trim() == "x509"))
        .unwrap_or(false);
    ctx.strict_verification = strict;
    ctx.trusted_keys_only = trusted_keys_only;

    if verbose {
        eprintln!("Verifying: {}", file.display());
    }

    let result = bergshamra_dsig::verify::verify(&ctx, &xml)?;
    match result {
        bergshamra_dsig::verify::VerifyResult::Valid { .. } => {
            println!("OK");
            Ok(())
        }
        bergshamra_dsig::verify::VerifyResult::Invalid { reason } => {
            eprintln!("INVALID: {reason}");
            process::exit(1);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_sign(
    template: PathBuf,
    key: Option<PathBuf>,
    key_name: Vec<String>,
    certs: Vec<PathBuf>,
    trusted: Vec<PathBuf>,
    pkcs12: Option<PathBuf>,
    pwd: Option<String>,
    hmac_key: Option<PathBuf>,
    keys_file: Option<PathBuf>,
    url_map: Vec<String>,
    output: Option<PathBuf>,
    id_attr: Vec<String>,
    session_key: Option<String>,
    debug: bool,
    verbose: bool,
) -> Result<(), Error> {
    let template_xml = read_file(&template)?;
    let mut mgr = build_keys_manager(
        key,
        key_name,
        certs,
        trusted,
        pkcs12,
        pwd.as_deref(),
        hmac_key,
        None,
        keys_file,
    )?;

    // Generate a random session key if requested (e.g. "hmac-192", "aes-128")
    // Insert it first so it takes priority for signing
    if let Some(ref spec) = session_key {
        let key = generate_session_key(spec)?;
        mgr.insert_key_first(key);
    }

    let mut ctx = bergshamra_dsig::DsigContext::new(mgr);
    for attr in &id_attr {
        ctx.add_id_attr(attr);
    }
    for spec in &url_map {
        if let Some((url, file_path)) = spec.split_once('=') {
            ctx.add_url_map(url, file_path);
        }
    }
    ctx.debug = debug;
    if let Some(parent) = template.parent() {
        ctx.base_dir = Some(parent.to_string_lossy().into_owned());
    }

    if verbose {
        eprintln!("Signing: {}", template.display());
    }

    let signed = bergshamra_dsig::sign::sign(&ctx, &template_xml)?;
    write_output(output, signed.as_bytes())
}

#[allow(clippy::too_many_arguments)]
fn cmd_decrypt(
    file: PathBuf,
    key: Option<PathBuf>,
    key_name: Vec<String>,
    pkcs12: Option<PathBuf>,
    pwd: Option<String>,
    hmac_key: Option<PathBuf>,
    aes_key: Option<PathBuf>,
    keys_file: Option<PathBuf>,
    output: Option<PathBuf>,
    id_attr: Vec<String>,
    no_cipher_reference: bool,
    verbose: bool,
) -> Result<(), Error> {
    let xml = read_file(&file)?;
    let mgr = build_keys_manager(
        key,
        key_name,
        vec![],
        vec![],
        pkcs12,
        pwd.as_deref(),
        hmac_key,
        aes_key,
        keys_file,
    )?;

    let mut ctx = bergshamra_enc::EncContext::new(mgr);
    for attr in &id_attr {
        ctx.add_id_attr(attr);
    }
    ctx.disable_cipher_reference = no_cipher_reference;

    if verbose {
        eprintln!("Decrypting: {}", file.display());
    }

    let decrypted = bergshamra_enc::decrypt::decrypt_to_bytes(&ctx, &xml)?;
    write_output(output, &decrypted)
}

#[allow(clippy::too_many_arguments)]
fn cmd_encrypt(
    template: PathBuf,
    data_file: PathBuf,
    certs: Vec<PathBuf>,
    key_name: Vec<String>,
    pkcs12: Option<PathBuf>,
    pwd: Option<String>,
    aes_key: Option<PathBuf>,
    keys_file: Option<PathBuf>,
    output: Option<PathBuf>,
    id_attr: Vec<String>,
    node_name: Option<String>,
    node_id: Option<String>,
    verbose: bool,
) -> Result<(), Error> {
    let template_xml = read_file(&template)?;
    let data = std::fs::read(&data_file)
        .map_err(|e| Error::Other(format!("{}: {e}", data_file.display())))?;

    // If --node-name or --node-id is specified, and the template wraps EncryptedData
    // inside a document (not standalone), extract just that element from the data.
    // When EncryptedData is the root element, pass the data as-is (including any
    // XML prolog). The decrypt side detects plaintext that starts with <?xml and
    // returns it verbatim, preserving the original encoding attribute and DOCTYPE.
    let data = if template_has_wrapper(&template_xml) {
        extract_node_data(&data, node_name.as_deref(), node_id.as_deref(), &id_attr)?
    } else {
        data
    };

    let mgr = build_keys_manager(
        None,
        key_name,
        certs,
        vec![],
        pkcs12,
        pwd.as_deref(),
        None,
        aes_key,
        keys_file,
    )?;

    let mut ctx = bergshamra_enc::EncContext::new(mgr);
    for attr in &id_attr {
        ctx.add_id_attr(attr);
    }

    if verbose {
        eprintln!("Encrypting: {}", data_file.display());
    }

    let encrypted = bergshamra_enc::encrypt::encrypt(&ctx, &template_xml, &data)?;
    write_output(output, encrypted.as_bytes())
}

/// Check if the template has a wrapper element around EncryptedData.
/// Returns true if EncryptedData is NOT the root element (i.e., it's embedded in a document).
fn template_has_wrapper(template_xml: &str) -> bool {
    if let Ok(doc) = uppsala::parse(template_xml) {
        if let Some(root_id) = doc.document_element() {
            if let Some(elem) = doc.element(root_id) {
                return &*elem.name.local_name != "EncryptedData";
            }
        }
        false
    } else {
        false
    }
}

/// Extract a specific element from XML data based on node-name or node-id.
fn extract_node_data(
    data: &[u8],
    node_name: Option<&str>,
    node_id: Option<&str>,
    id_attrs: &[String],
) -> Result<Vec<u8>, Error> {
    if node_name.is_none() && node_id.is_none() {
        return Ok(data.to_vec());
    }

    let xml_str = std::str::from_utf8(data)
        .map_err(|e| Error::Other(format!("data is not valid UTF-8: {e}")))?;
    let doc = uppsala::parse(xml_str).map_err(|e| Error::XmlParse(e.to_string()))?;

    let target_node_id = if let Some(name) = node_name {
        // Parse namespace:localname format
        let (ns_uri, local_name) = if let Some(colon_pos) = name.rfind(':') {
            (&name[..colon_pos], &name[colon_pos + 1..])
        } else {
            ("", name)
        };
        doc.descendants(doc.root())
            .into_iter()
            .find(|&nid| {
                if let Some(elem) = doc.element(nid) {
                    &*elem.name.local_name == local_name
                        && (ns_uri.is_empty()
                            || elem.name.namespace_uri.as_deref().unwrap_or("") == ns_uri)
                } else {
                    false
                }
            })
            .ok_or_else(|| Error::MissingElement(format!("element matching --node-name {name}")))?
    } else if let Some(id) = node_id {
        let mut id_attr_names: Vec<&str> = vec!["Id", "ID", "id"];
        let extra: Vec<&str> = id_attrs.iter().map(|s| s.as_str()).collect();
        id_attr_names.extend(extra);
        doc.descendants(doc.root())
            .into_iter()
            .find(|&nid| {
                if let Some(elem) = doc.element(nid) {
                    id_attr_names
                        .iter()
                        .any(|attr| elem.get_attribute(attr) == Some(id))
                } else {
                    false
                }
            })
            .ok_or_else(|| Error::MissingElement(format!("element with ID={id}")))?
    } else {
        unreachable!()
    };

    // Extract the element's serialized form from the original XML
    let range = doc
        .node_range(target_node_id)
        .ok_or_else(|| Error::Other("could not determine source range for node".into()))?;
    Ok(xml_str.as_bytes()[range.start..range.end].to_vec())
}

fn cmd_info() -> Result<(), Error> {
    println!("Bergshamra — Pure Rust XML Security Library");
    println!();
    println!("Supported digest algorithms:");
    println!("  SHA-1, SHA-224, SHA-256, SHA-384, SHA-512");
    println!("  SHA3-224, SHA3-256, SHA3-384, SHA3-512");
    println!();
    println!("Supported signature algorithms:");
    println!("  RSA PKCS#1 v1.5 (SHA-1, SHA-224, SHA-256, SHA-384, SHA-512)");
    println!("  RSA-PSS (SHA-1, SHA-224, SHA-256, SHA-384, SHA-512)");
    println!("  ECDSA P-256/P-384 (SHA-1, SHA-256, SHA-384, SHA-512)");
    println!("  HMAC (SHA-1, SHA-256, SHA-384, SHA-512)");
    println!("  EdDSA Ed25519");
    println!();
    println!("Supported encryption algorithms:");
    println!("  AES-128/192/256-CBC, AES-128/256-GCM, 3DES-CBC");
    println!();
    println!("Supported key wrap algorithms:");
    println!("  AES-KW 128/192/256");
    println!();
    println!("Supported key transport algorithms:");
    println!("  RSA PKCS#1 v1.5, RSA-OAEP (SHA-1)");
    println!();
    println!("Supported key agreement algorithms:");
    println!("  ECDH-ES (P-256, P-384, P-521), DH-ES (X9.42), X25519");
    println!();
    println!("Supported key derivation functions:");
    println!("  ConcatKDF, PBKDF2, HKDF (SHA-256/384/512)");
    println!();
    println!("Supported canonicalization:");
    println!("  C14N 1.0 (±comments)");
    println!("  C14N 1.1 (±comments)");
    println!("  Exclusive C14N 1.0 (±comments)");
    println!();
    println!("Supported key formats:");
    println!("  PEM, DER (RSA, EC, Ed25519, X25519), raw binary (HMAC, AES)");
    Ok(())
}

// ── Utility functions ────────────────────────────────────────────────

fn read_file(path: &PathBuf) -> Result<String, Error> {
    std::fs::read_to_string(path).map_err(|e| Error::Other(format!("{}: {e}", path.display())))
}

/// Load certificate(s) from a PEM or DER file and return as DER-encoded bytes.
fn load_certs_as_der(path: &PathBuf) -> Result<Vec<Vec<u8>>, Error> {
    let data = std::fs::read(path).map_err(|e| Error::Other(format!("{}: {e}", path.display())))?;

    // Try PEM first
    if data.starts_with(b"-----") {
        let text = std::str::from_utf8(&data)
            .map_err(|e| Error::Other(format!("{}: invalid UTF-8: {e}", path.display())))?;
        let certs = pem_decode_all(text, "CERTIFICATE")?;
        if certs.is_empty() {
            return Err(Error::Other(format!(
                "{}: no CERTIFICATE found in PEM",
                path.display()
            )));
        }
        Ok(certs)
    } else {
        // Assume DER
        Ok(vec![data])
    }
}

/// Load CRL(s) from a PEM or DER file and return as DER-encoded bytes.
fn load_crl_as_der(path: &PathBuf) -> Result<Vec<Vec<u8>>, Error> {
    let data = std::fs::read(path).map_err(|e| Error::Other(format!("{}: {e}", path.display())))?;

    // Try PEM first
    if data.starts_with(b"-----") {
        let text = std::str::from_utf8(&data)
            .map_err(|e| Error::Other(format!("{}: invalid UTF-8: {e}", path.display())))?;
        let crls = pem_decode_all(text, "X509 CRL")?;
        if crls.is_empty() {
            return Err(Error::Other(format!(
                "{}: no X509 CRL found in PEM",
                path.display()
            )));
        }
        Ok(crls)
    } else {
        // Assume DER
        Ok(vec![data])
    }
}

/// Parse all PEM blocks with the given label from a text string.
fn pem_decode_all(text: &str, label: &str) -> Result<Vec<Vec<u8>>, Error> {
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    let begin_marker = format!("-----BEGIN {}-----", label);
    let end_marker = format!("-----END {}-----", label);

    let mut results = Vec::new();
    let mut remaining = text;

    while let Some(start) = remaining.find(&begin_marker) {
        let after_begin = &remaining[start + begin_marker.len()..];
        if let Some(end) = after_begin.find(&end_marker) {
            let b64_content: String = after_begin[..end]
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            let der = engine
                .decode(&b64_content)
                .map_err(|e| Error::Other(format!("PEM base64 decode error: {e}")))?;
            results.push(der);
            remaining = &after_begin[end + end_marker.len()..];
        } else {
            break;
        }
    }

    Ok(results)
}

fn write_output(path: Option<PathBuf>, data: &[u8]) -> Result<(), Error> {
    match path {
        Some(p) => {
            std::fs::write(&p, data).map_err(|e| Error::Other(format!("{}: {e}", p.display())))
        }
        None => {
            use std::io::Write;
            std::io::stdout()
                .write_all(data)
                .map_err(|e| Error::Other(format!("stdout: {e}")))
        }
    }
}

/// Generate a random session key from a spec like "hmac-192", "aes-128", "des-192".
fn generate_session_key(spec: &str) -> Result<Key, Error> {
    use rand::RngCore;
    let parts: Vec<&str> = spec.splitn(2, '-').collect();
    if parts.len() != 2 {
        return Err(Error::Other(format!(
            "invalid session-key spec: {spec} (expected TYPE-BITS, e.g. hmac-192)"
        )));
    }
    let key_type = parts[0];
    let bits: usize = parts[1]
        .parse()
        .map_err(|_| Error::Other(format!("invalid bit size in session-key spec: {spec}")))?;
    if bits % 8 != 0 || bits == 0 {
        return Err(Error::Other(format!(
            "session-key bit size must be a positive multiple of 8: {bits}"
        )));
    }
    let byte_len = bits / 8;
    let mut key_bytes = vec![0u8; byte_len];
    rand::thread_rng().fill_bytes(&mut key_bytes);

    let key_data = match key_type {
        "hmac" => KeyData::Hmac(key_bytes),
        "aes" => KeyData::Aes(key_bytes),
        "des" | "des3" | "tripledes" => KeyData::Des3(key_bytes),
        _ => {
            return Err(Error::Other(format!(
                "unsupported session-key type: {key_type}"
            )))
        }
    };
    Ok(Key::new(key_data, KeyUsage::Any))
}

#[allow(clippy::too_many_arguments)]
fn build_keys_manager(
    key_path: Option<PathBuf>,
    key_names: Vec<String>,
    cert_paths: Vec<PathBuf>,
    trusted_paths: Vec<PathBuf>,
    pkcs12_path: Option<PathBuf>,
    password: Option<&str>,
    hmac_key_spec: Option<PathBuf>,
    aes_key_path: Option<PathBuf>,
    keys_file_path: Option<PathBuf>,
) -> Result<KeysManager, Error> {
    let mut mgr = KeysManager::new();

    // Load keys from xmlsec keys.xml file
    if let Some(path) = keys_file_path {
        let keys = bergshamra_keys::keysxml::load_keys_file(&path)?;
        for key in keys {
            mgr.add_key(key);
        }
    }

    // Load key file (auto-detect PEM/DER/PKCS#12)
    if let Some(path) = key_path {
        let key = bergshamra_keys::loader::load_key_file_with_password(&path, password)?;
        mgr.add_key(key);
    }

    // Load named keys (NAME:FILE format)
    for spec in &key_names {
        if let Some((name, file_str)) = spec.split_once(':') {
            let path = PathBuf::from(file_str);
            let mut key =
                match bergshamra_keys::loader::load_key_file_with_password(&path, password) {
                    Ok(k) => k,
                    Err(_) => {
                        // Fallback: load as raw symmetric key (for concatkdf/pbkdf2 master keys)
                        let bytes = std::fs::read(&path)
                            .map_err(|e| Error::Other(format!("{}: {e}", path.display())))?;
                        Key::new(KeyData::Aes(bytes), KeyUsage::Any)
                    }
                };
            key.name = Some(name.to_owned());
            mgr.add_key(key);
        } else {
            return Err(Error::Other(format!(
                "invalid key-name format: {spec} (expected NAME:FILE)"
            )));
        }
    }

    // Load PKCS#12 key file
    if let Some(path) = pkcs12_path {
        let data =
            std::fs::read(&path).map_err(|e| Error::Other(format!("{}: {e}", path.display())))?;
        let key = bergshamra_keys::loader::load_pkcs12(&data, password.unwrap_or(""))?;
        mgr.add_key(key);
    }

    // Load certificates
    for path in &cert_paths {
        let key = bergshamra_keys::loader::load_key_file_with_password(path, password)?;
        mgr.add_key(key);
    }

    // Load trusted CA certificates
    for path in &trusted_paths {
        let key = bergshamra_keys::loader::load_key_file_with_password(path, password)?;
        mgr.add_key(key);
    }

    // Load HMAC key (supports NAME:FILE or just FILE)
    if let Some(spec) = hmac_key_spec {
        let spec_str = spec.to_string_lossy();
        let (name, path) = if let Some((n, f)) = spec_str.split_once(':') {
            // Check if it looks like NAME:FILE (name won't contain path separators)
            if !n.contains('/') && !n.contains('\\') && !f.is_empty() {
                (Some(n.to_owned()), PathBuf::from(f))
            } else {
                (None, spec.clone())
            }
        } else {
            (None, spec.clone())
        };
        let bytes =
            std::fs::read(&path).map_err(|e| Error::Other(format!("{}: {e}", path.display())))?;
        let mut key = Key::new(KeyData::Hmac(bytes), KeyUsage::Any);
        key.name = name;
        mgr.add_key(key);
    }

    // Load AES key
    if let Some(path) = aes_key_path {
        let bytes =
            std::fs::read(&path).map_err(|e| Error::Other(format!("{}: {e}", path.display())))?;
        let key = Key::new(KeyData::Aes(bytes), KeyUsage::Any);
        mgr.add_key(key);
    }

    Ok(mgr)
}
