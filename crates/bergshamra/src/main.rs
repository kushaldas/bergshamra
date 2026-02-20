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

        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
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

        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Register additional ID attribute names
        #[arg(long = "id-attr")]
        id_attr: Vec<String>,

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

        /// Load public key or certificate for key transport
        #[arg(long)]
        cert: Option<PathBuf>,

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
            verbose,
        } => cmd_verify(file, key, key_name, cert, trusted, pkcs12, pwd, hmac_key, keys_file, url_map, id_attr, verbose),

        Commands::Sign {
            template,
            key,
            key_name,
            pkcs12,
            pwd,
            hmac_key,
            keys_file,
            output,
            id_attr,
            verbose,
        } => cmd_sign(template, key, key_name, pkcs12, pwd, hmac_key, keys_file, output, id_attr, verbose),

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
            verbose,
        } => cmd_decrypt(file, key, key_name, pkcs12, pwd, hmac_key, aes_key, keys_file, output, id_attr, verbose),

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
            verbose,
        } => cmd_encrypt(template, data, cert, key_name, pkcs12, pwd, aes_key, keys_file, output, id_attr, verbose),

        Commands::Info => cmd_info(),
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        process::exit(1);
    }
}

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
    verbose: bool,
) -> Result<(), Error> {
    let xml = read_file(&file)?;
    let mgr = build_keys_manager(key, key_name, certs, trusted, pkcs12, pwd.as_deref(), hmac_key, None, keys_file)?;

    let mut ctx = bergshamra_dsig::DsigContext::new(mgr);
    for attr in &id_attr {
        ctx.add_id_attr(attr);
    }
    for spec in &url_map {
        if let Some((url, file_path)) = spec.split_once('=') {
            ctx.add_url_map(url, file_path);
        }
    }

    if verbose {
        eprintln!("Verifying: {}", file.display());
    }

    let result = bergshamra_dsig::verify::verify(&ctx, &xml)?;
    match result {
        bergshamra_dsig::verify::VerifyResult::Valid => {
            println!("OK");
            Ok(())
        }
        bergshamra_dsig::verify::VerifyResult::Invalid { reason } => {
            eprintln!("INVALID: {reason}");
            process::exit(1);
        }
    }
}

fn cmd_sign(
    template: PathBuf,
    key: Option<PathBuf>,
    key_name: Vec<String>,
    pkcs12: Option<PathBuf>,
    pwd: Option<String>,
    hmac_key: Option<PathBuf>,
    keys_file: Option<PathBuf>,
    output: Option<PathBuf>,
    id_attr: Vec<String>,
    verbose: bool,
) -> Result<(), Error> {
    let template_xml = read_file(&template)?;
    let mgr = build_keys_manager(key, key_name, vec![], vec![], pkcs12, pwd.as_deref(), hmac_key, None, keys_file)?;

    let mut ctx = bergshamra_dsig::DsigContext::new(mgr);
    for attr in &id_attr {
        ctx.add_id_attr(attr);
    }

    if verbose {
        eprintln!("Signing: {}", template.display());
    }

    let signed = bergshamra_dsig::sign::sign(&ctx, &template_xml)?;
    write_output(output, signed.as_bytes())
}

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
    verbose: bool,
) -> Result<(), Error> {
    let xml = read_file(&file)?;
    let mgr = build_keys_manager(key, key_name, vec![], vec![], pkcs12, pwd.as_deref(), hmac_key, aes_key, keys_file)?;

    let mut ctx = bergshamra_enc::EncContext::new(mgr);
    for attr in &id_attr {
        ctx.add_id_attr(attr);
    }

    if verbose {
        eprintln!("Decrypting: {}", file.display());
    }

    let decrypted = bergshamra_enc::decrypt::decrypt_to_bytes(&ctx, &xml)?;
    write_output(output, &decrypted)
}

fn cmd_encrypt(
    template: PathBuf,
    data_file: PathBuf,
    cert: Option<PathBuf>,
    key_name: Vec<String>,
    pkcs12: Option<PathBuf>,
    pwd: Option<String>,
    aes_key: Option<PathBuf>,
    keys_file: Option<PathBuf>,
    output: Option<PathBuf>,
    id_attr: Vec<String>,
    verbose: bool,
) -> Result<(), Error> {
    let template_xml = read_file(&template)?;
    let data = std::fs::read(&data_file)
        .map_err(|e| Error::Other(format!("{}: {e}", data_file.display())))?;
    let cert_vec = cert.into_iter().collect();
    let mgr = build_keys_manager(None, key_name, cert_vec, vec![], pkcs12, pwd.as_deref(), None, aes_key, keys_file)?;

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
    println!("Supported canonicalization:");
    println!("  C14N 1.0 (±comments)");
    println!("  C14N 1.1 (±comments)");
    println!("  Exclusive C14N 1.0 (±comments)");
    println!();
    println!("Supported key formats:");
    println!("  PEM, DER (RSA, EC), raw binary (HMAC, AES)");
    Ok(())
}

// ── Utility functions ────────────────────────────────────────────────

fn read_file(path: &PathBuf) -> Result<String, Error> {
    std::fs::read_to_string(path)
        .map_err(|e| Error::Other(format!("{}: {e}", path.display())))
}

fn write_output(path: Option<PathBuf>, data: &[u8]) -> Result<(), Error> {
    match path {
        Some(p) => {
            std::fs::write(&p, data)
                .map_err(|e| Error::Other(format!("{}: {e}", p.display())))
        }
        None => {
            use std::io::Write;
            std::io::stdout()
                .write_all(data)
                .map_err(|e| Error::Other(format!("stdout: {e}")))
        }
    }
}

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
            let mut key = bergshamra_keys::loader::load_key_file_with_password(&path, password)?;
            key.name = Some(name.to_owned());
            mgr.add_key(key);
        } else {
            return Err(Error::Other(format!("invalid key-name format: {spec} (expected NAME:FILE)")));
        }
    }

    // Load PKCS#12 key file
    if let Some(path) = pkcs12_path {
        let data = std::fs::read(&path)
            .map_err(|e| Error::Other(format!("{}: {e}", path.display())))?;
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
        let bytes = std::fs::read(&path)
            .map_err(|e| Error::Other(format!("{}: {e}", path.display())))?;
        let mut key = Key::new(KeyData::Hmac(bytes), KeyUsage::Any);
        key.name = name;
        mgr.add_key(key);
    }

    // Load AES key
    if let Some(path) = aes_key_path {
        let bytes = std::fs::read(&path)
            .map_err(|e| Error::Other(format!("{}: {e}", path.display())))?;
        let key = Key::new(KeyData::Aes(bytes), KeyUsage::Any);
        mgr.add_key(key);
    }

    Ok(mgr)
}
