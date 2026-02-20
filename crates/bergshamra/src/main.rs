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
        cert: Option<PathBuf>,

        /// Load trusted CA certificate
        #[arg(long)]
        trusted: Option<PathBuf>,

        /// Load raw HMAC key (binary file)
        #[arg(long = "hmac-key")]
        hmac_key: Option<PathBuf>,

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

        /// Load raw HMAC key (binary file)
        #[arg(long = "hmac-key")]
        hmac_key: Option<PathBuf>,

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

        /// Load raw HMAC key (binary file)
        #[arg(long = "hmac-key")]
        hmac_key: Option<PathBuf>,

        /// Load raw AES key (binary file)
        #[arg(long = "aes-key")]
        aes_key: Option<PathBuf>,

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

        /// Load raw AES key (binary file)
        #[arg(long = "aes-key")]
        aes_key: Option<PathBuf>,

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
            trusted: _,
            hmac_key,
            id_attr,
            verbose,
        } => cmd_verify(file, key, key_name, cert, hmac_key, id_attr, verbose),

        Commands::Sign {
            template,
            key,
            key_name,
            hmac_key,
            output,
            id_attr,
            verbose,
        } => cmd_sign(template, key, key_name, hmac_key, output, id_attr, verbose),

        Commands::Decrypt {
            file,
            key,
            key_name,
            hmac_key,
            aes_key,
            output,
            id_attr,
            verbose,
        } => cmd_decrypt(file, key, key_name, hmac_key, aes_key, output, id_attr, verbose),

        Commands::Encrypt {
            template,
            data,
            cert,
            key_name,
            aes_key,
            output,
            id_attr,
            verbose,
        } => cmd_encrypt(template, data, cert, key_name, aes_key, output, id_attr, verbose),

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
    cert: Option<PathBuf>,
    hmac_key: Option<PathBuf>,
    id_attr: Vec<String>,
    verbose: bool,
) -> Result<(), Error> {
    let xml = read_file(&file)?;
    let mut mgr = build_keys_manager(key, key_name, cert, hmac_key, None)?;
    let _ = &mut mgr; // silence unused mut if needed

    let mut ctx = bergshamra_dsig::DsigContext::new(mgr);
    for attr in &id_attr {
        ctx.add_id_attr(attr);
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
    hmac_key: Option<PathBuf>,
    output: Option<PathBuf>,
    id_attr: Vec<String>,
    verbose: bool,
) -> Result<(), Error> {
    let template_xml = read_file(&template)?;
    let mgr = build_keys_manager(key, key_name, None, hmac_key, None)?;

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
    hmac_key: Option<PathBuf>,
    aes_key: Option<PathBuf>,
    output: Option<PathBuf>,
    id_attr: Vec<String>,
    verbose: bool,
) -> Result<(), Error> {
    let xml = read_file(&file)?;
    let mgr = build_keys_manager(key, key_name, None, hmac_key, aes_key)?;

    let mut ctx = bergshamra_enc::EncContext::new(mgr);
    for attr in &id_attr {
        ctx.add_id_attr(attr);
    }

    if verbose {
        eprintln!("Decrypting: {}", file.display());
    }

    let decrypted = bergshamra_enc::decrypt::decrypt(&ctx, &xml)?;
    write_output(output, decrypted.as_bytes())
}

fn cmd_encrypt(
    template: PathBuf,
    data_file: PathBuf,
    cert: Option<PathBuf>,
    key_name: Vec<String>,
    aes_key: Option<PathBuf>,
    output: Option<PathBuf>,
    id_attr: Vec<String>,
    verbose: bool,
) -> Result<(), Error> {
    let template_xml = read_file(&template)?;
    let data = std::fs::read(&data_file)
        .map_err(|e| Error::Other(format!("{}: {e}", data_file.display())))?;
    let mgr = build_keys_manager(None, key_name, cert, None, aes_key)?;

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
    cert_path: Option<PathBuf>,
    hmac_key_path: Option<PathBuf>,
    aes_key_path: Option<PathBuf>,
) -> Result<KeysManager, Error> {
    let mut mgr = KeysManager::new();

    // Load key file (auto-detect PEM/DER)
    if let Some(path) = key_path {
        let key = bergshamra_keys::loader::load_key_file(&path)?;
        mgr.add_key(key);
    }

    // Load named keys (NAME:FILE format)
    for spec in &key_names {
        if let Some((name, file_str)) = spec.split_once(':') {
            let path = PathBuf::from(file_str);
            let mut key = bergshamra_keys::loader::load_key_file(&path)?;
            key.name = Some(name.to_owned());
            mgr.add_key(key);
        } else {
            return Err(Error::Other(format!("invalid key-name format: {spec} (expected NAME:FILE)")));
        }
    }

    // Load certificate
    if let Some(path) = cert_path {
        let key = bergshamra_keys::loader::load_key_file(&path)?;
        mgr.add_key(key);
    }

    // Load HMAC key
    if let Some(path) = hmac_key_path {
        let bytes = std::fs::read(&path)
            .map_err(|e| Error::Other(format!("{}: {e}", path.display())))?;
        let key = Key::new(KeyData::Hmac(bytes), KeyUsage::Any);
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
