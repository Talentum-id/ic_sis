use std::fmt;
use blake2::{Blake2b, Digest};
use ed25519_dalek::{PublicKey, Signature, Verifier};
use k256::ecdsa::{signature::Verifier as K256Verifier, Signature as K256Signature, VerifyingKey};
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};

pub const SUI_SIGNATURE_SCHEME_FLAG_ED25519: u8 = 0x00;
pub const SUI_SIGNATURE_SCHEME_FLAG_SECP256K1: u8 = 0x01;
pub const SUI_SIGNATURE_SCHEME_FLAG_SECP256R1: u8 = 0x02;
pub const SUI_SIGNATURE_SCHEME_FLAG_MULTISIG: u8 = 0x03;
pub const SUI_SIGNATURE_SCHEME_FLAG_ZKLOGIN: u8 = 0x05;
pub const SUI_SIGNATURE_SCHEME_FLAG_PASSKEY: u8 = 0x06;

pub const INTENT_PREFIX_TRANSACTION: [u8; 3] = [0, 0, 0];

#[derive(Debug)]
pub enum SuiError {
    AddressFormatError(String),
    DecodingError(hex::FromHexError),
    SignatureFormatError(String),
    InvalidSignature(String),
    UnsupportedSignatureScheme(u8),
    InvalidSignatureScheme,
    InvalidPublicKey(String),
    InvalidIntent,
    HashError(String),
}

impl From<hex::FromHexError> for SuiError {
    fn from(err: hex::FromHexError) -> Self {
        SuiError::DecodingError(err)
    }
}

impl fmt::Display for SuiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SuiError::AddressFormatError(e) => write!(f, "Address format error: {}", e),
            SuiError::DecodingError(e) => write!(f, "Decoding error: {}", e),
            SuiError::SignatureFormatError(e) => write!(f, "Signature format error: {}", e),
            SuiError::InvalidSignature(e) => write!(f, "Invalid signature: {}", e),
            SuiError::UnsupportedSignatureScheme(scheme) => write!(f, "Unsupported signature scheme: {}", scheme),
            SuiError::InvalidSignatureScheme => write!(f, "Invalid signature scheme"),
            SuiError::InvalidPublicKey(e) => write!(f, "Invalid public key: {}", e),
            SuiError::InvalidIntent => write!(f, "Invalid intent"),
            SuiError::HashError(e) => write!(f, "Hash error: {}", e),
        }
    }
}

impl From<SuiError> for String {
    fn from(error: SuiError) -> Self {
        error.to_string()
    }
}

#[derive(Debug, Clone)]
pub struct SuiAddress(String);

impl SuiAddress {
    pub fn new(address: &str) -> Result<SuiAddress, SuiError> {
        if !address.starts_with("0x") || address.len() != 66 {
            return Err(SuiError::AddressFormatError(String::from(
                "Must start with '0x' and be 66 characters long",
            )));
        }

        // Validate hex format
        hex::decode(&address[2..]).map_err(SuiError::DecodingError)?;

        Ok(SuiAddress(address.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let address = self.0.strip_prefix("0x").unwrap();
        hex::decode(address).unwrap()
    }

    pub fn as_byte_array(&self) -> [u8; 32] {
        let address = self.0.strip_prefix("0x").unwrap();
        let bytes = hex::decode(address).unwrap();
        let mut array = [0; 32];
        array.copy_from_slice(&bytes);
        array
    }
}

#[derive(Debug)]
pub struct SuiSignature {
    scheme: u8,
    signature: Vec<u8>,
    public_key: Vec<u8>,
}

impl SuiSignature {
    pub fn new(signature_bytes: &[u8]) -> Result<SuiSignature, SuiError> {
        if signature_bytes.is_empty() {
            return Err(SuiError::SignatureFormatError("Empty signature".to_string()));
        }

        let scheme = signature_bytes[0];

        match scheme {
            SUI_SIGNATURE_SCHEME_FLAG_ED25519 => {
                if signature_bytes.len() != 97 {
                    return Err(SuiError::SignatureFormatError(format!(
                        "Ed25519 signature must be 97 bytes, got {}",
                        signature_bytes.len()
                    )));
                }
                let signature = signature_bytes[1..65].to_vec();
                let public_key = signature_bytes[65..].to_vec();
                Ok(SuiSignature {
                    scheme,
                    signature,
                    public_key,
                })
            }
            SUI_SIGNATURE_SCHEME_FLAG_SECP256K1 | SUI_SIGNATURE_SCHEME_FLAG_SECP256R1 => {
                if signature_bytes.len() != 98 {
                    return Err(SuiError::SignatureFormatError(format!(
                        "ECDSA signature must be 98 bytes, got {}",
                        signature_bytes.len()
                    )));
                }
                let signature = signature_bytes[1..65].to_vec();
                let public_key = signature_bytes[65..].to_vec();
                Ok(SuiSignature {
                    scheme,
                    signature,
                    public_key,
                })
            }
            SUI_SIGNATURE_SCHEME_FLAG_MULTISIG | SUI_SIGNATURE_SCHEME_FLAG_ZKLOGIN | SUI_SIGNATURE_SCHEME_FLAG_PASSKEY => {
                Err(SuiError::UnsupportedSignatureScheme(scheme))
            }
            _ => Err(SuiError::InvalidSignatureScheme),
        }
    }

    pub fn from_hex(hex_str: &str) -> Result<SuiSignature, SuiError> {
        if !hex_str.starts_with("0x") {
            return Err(SuiError::SignatureFormatError(
                "Hex signature must start with 0x".to_string(),
            ));
        }
        let bytes = hex::decode(&hex_str[2..]).map_err(SuiError::DecodingError)?;
        Self::new(&bytes)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut result = vec![self.scheme];
        result.extend_from_slice(&self.signature);
        result.extend_from_slice(&self.public_key);
        result
    }

    pub fn as_hex(&self) -> String {
        format!("0x{}", hex::encode(self.as_bytes()))
    }

    pub fn scheme(&self) -> u8 {
        self.scheme
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}

pub fn create_intent_hash(message: &[u8]) -> Result<Vec<u8>, SuiError> {
    let mut intent_message = Vec::with_capacity(INTENT_PREFIX_TRANSACTION.len() + message.len());
    intent_message.extend_from_slice(&INTENT_PREFIX_TRANSACTION);
    intent_message.extend_from_slice(message);

    let mut hasher = Blake2b::new();
    hasher.update(&intent_message);
    let hash = hasher.finalize();

    Ok(hash[..32].to_vec())
}

pub fn verify_sui_signature(
    message: &[u8],
    signature: &SuiSignature,
) -> Result<bool, SuiError> {
    let intent_hash = create_intent_hash(message)?;
    
    match signature.scheme() {
        SUI_SIGNATURE_SCHEME_FLAG_ED25519 => {
            let public_key = PublicKey::from_bytes(signature.public_key())
                .map_err(|e| SuiError::InvalidPublicKey(e.to_string()))?;
            
            let sig = Signature::from_bytes(signature.signature())
                .map_err(|e| SuiError::InvalidSignature(e.to_string()))?;
            
            public_key
                .verify(&intent_hash, &sig)
                .map_err(|e| SuiError::InvalidSignature(e.to_string()))?;
            
            Ok(true)
        }
        SUI_SIGNATURE_SCHEME_FLAG_SECP256K1 => {
            let verifying_key = VerifyingKey::from_sec1_bytes(signature.public_key())
                .map_err(|e| SuiError::InvalidPublicKey(e.to_string()))?;
            
            let sig = K256Signature::from_bytes(signature.signature().into())
                .map_err(|e| SuiError::InvalidSignature(e.to_string()))?;
            
            verifying_key
                .verify(&intent_hash, &sig)
                .map_err(|e| SuiError::InvalidSignature(e.to_string()))?;
            
            Ok(true)
        }
        SUI_SIGNATURE_SCHEME_FLAG_SECP256R1 => {
            let verifying_key = P256VerifyingKey::from_sec1_bytes(signature.public_key())
                .map_err(|e| SuiError::InvalidPublicKey(e.to_string()))?;
            
            let sig = P256Signature::from_bytes(signature.signature().into())
                .map_err(|e| SuiError::InvalidSignature(e.to_string()))?;
            
            verifying_key
                .verify(&intent_hash, &sig)
                .map_err(|e| SuiError::InvalidSignature(e.to_string()))?;
            
            Ok(true)
        }
        _ => Err(SuiError::UnsupportedSignatureScheme(signature.scheme())),
    }
}

pub fn derive_sui_address_from_public_key(scheme: u8, public_key: &[u8]) -> Result<String, SuiError> {
    // Validate scheme
    match scheme {
        SUI_SIGNATURE_SCHEME_FLAG_ED25519 => {
            if public_key.len() != 32 {
                return Err(SuiError::InvalidPublicKey(format!(
                    "Ed25519 public key must be 32 bytes, got {}",
                    public_key.len()
                )));
            }
        }
        SUI_SIGNATURE_SCHEME_FLAG_SECP256K1 | SUI_SIGNATURE_SCHEME_FLAG_SECP256R1 => {
            if public_key.len() != 33 {
                return Err(SuiError::InvalidPublicKey(format!(
                    "ECDSA public key must be 33 bytes, got {}",
                    public_key.len()
                )));
            }
        }
        _ => return Err(SuiError::UnsupportedSignatureScheme(scheme)),
    }

    // Derive address using Blake2b
    let mut hasher = Blake2b::new();
    hasher.update([scheme]); // Prepend scheme identifier
    hasher.update(public_key);
    let hash = hasher.finalize();

    // Take first 32 bytes for the address
    let address_bytes = &hash[..32];
    Ok(format!("0x{}", hex::encode(address_bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_sui_address_creation() {
        // Valid Sui address
        let valid_address = "0x".to_owned() + &"a".repeat(64);
        let address = SuiAddress::new(&valid_address);
        assert!(address.is_ok());
        
        // Invalid prefix
        let invalid_prefix = "1x".to_owned() + &"a".repeat(64);
        let address = SuiAddress::new(&invalid_prefix);
        assert!(address.is_err());
        
        // Invalid length
        let invalid_length = "0x".to_owned() + &"a".repeat(63);
        let address = SuiAddress::new(&invalid_length);
        assert!(address.is_err());
    }
    
    #[test]
    fn test_create_intent_hash() {
        let message = b"Hello, Sui!";
        let result = create_intent_hash(message);
        assert!(result.is_ok());
        let hash = result.unwrap();
        assert_eq!(hash.len(), 32);
    }
}