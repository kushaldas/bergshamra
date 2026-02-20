#![forbid(unsafe_code)]

//! Key wrap algorithms (AES-KW per RFC 3394).

use bergshamra_core::{algorithm, Error};
use aes_kw::Kek;

/// Trait for key wrap algorithms.
pub trait KeyWrapAlgorithm: Send {
    fn uri(&self) -> &'static str;
    fn wrap(&self, kek: &[u8], key_data: &[u8]) -> Result<Vec<u8>, Error>;
    fn unwrap(&self, kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, Error>;
    fn kek_size(&self) -> usize;
}

/// Create a key wrap algorithm from its URI.
pub fn from_uri(uri: &str) -> Result<Box<dyn KeyWrapAlgorithm>, Error> {
    match uri {
        algorithm::KW_AES128 => Ok(Box::new(AesKeyWrap { kek_size: 16, uri: algorithm::KW_AES128 })),
        algorithm::KW_AES192 => Ok(Box::new(AesKeyWrap { kek_size: 24, uri: algorithm::KW_AES192 })),
        algorithm::KW_AES256 => Ok(Box::new(AesKeyWrap { kek_size: 32, uri: algorithm::KW_AES256 })),
        algorithm::KW_TRIPLEDES => Ok(Box::new(TripleDesKeyWrap)),
        _ => Err(Error::UnsupportedAlgorithm(format!("key wrap: {uri}"))),
    }
}

struct AesKeyWrap { kek_size: usize, uri: &'static str }

impl KeyWrapAlgorithm for AesKeyWrap {
    fn uri(&self) -> &'static str { self.uri }
    fn kek_size(&self) -> usize { self.kek_size }

    fn wrap(&self, kek_bytes: &[u8], key_data: &[u8]) -> Result<Vec<u8>, Error> {
        if kek_bytes.len() != self.kek_size {
            return Err(Error::Crypto(format!("expected {} byte KEK, got {}", self.kek_size, kek_bytes.len())));
        }
        let mut out = vec![0u8; key_data.len() + 8];
        macro_rules! do_wrap {
            ($aes:ty) => {{
                let kek = Kek::<$aes>::new(kek_bytes.into());
                kek.wrap(key_data, &mut out)
                    .map_err(|e| Error::Crypto(format!("AES-KW wrap: {e}")))?;
            }};
        }
        match self.kek_size {
            16 => do_wrap!(aes::Aes128),
            24 => do_wrap!(aes::Aes192),
            32 => do_wrap!(aes::Aes256),
            _ => return Err(Error::Crypto("unsupported KEK size".into())),
        }
        Ok(out)
    }

    fn unwrap(&self, kek_bytes: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, Error> {
        if kek_bytes.len() != self.kek_size {
            return Err(Error::Crypto(format!("expected {} byte KEK, got {}", self.kek_size, kek_bytes.len())));
        }
        if wrapped.len() < 16 {
            return Err(Error::Crypto("wrapped key too short".into()));
        }
        let mut out = vec![0u8; wrapped.len() - 8];
        macro_rules! do_unwrap {
            ($aes:ty) => {{
                let kek = Kek::<$aes>::new(kek_bytes.into());
                kek.unwrap(wrapped, &mut out)
                    .map_err(|e| Error::Crypto(format!("AES-KW unwrap: {e}")))?;
            }};
        }
        match self.kek_size {
            16 => do_unwrap!(aes::Aes128),
            24 => do_unwrap!(aes::Aes192),
            32 => do_unwrap!(aes::Aes256),
            _ => return Err(Error::Crypto("unsupported KEK size".into())),
        }
        Ok(out)
    }
}

struct TripleDesKeyWrap;

impl KeyWrapAlgorithm for TripleDesKeyWrap {
    fn uri(&self) -> &'static str { algorithm::KW_TRIPLEDES }
    fn kek_size(&self) -> usize { 24 }

    fn wrap(&self, _kek: &[u8], _key_data: &[u8]) -> Result<Vec<u8>, Error> {
        Err(Error::UnsupportedAlgorithm("3DES key wrap not yet implemented".into()))
    }

    fn unwrap(&self, _kek: &[u8], _wrapped: &[u8]) -> Result<Vec<u8>, Error> {
        Err(Error::UnsupportedAlgorithm("3DES key unwrap not yet implemented".into()))
    }
}
