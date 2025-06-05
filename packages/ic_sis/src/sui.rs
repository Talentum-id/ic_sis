use std::fmt;
use blake2::{Blake2b, Digest};
use ed25519_dalek::{PublicKey, Signature, Verifier};
use k256::ecdsa::{signature::Verifier as K256Verifier, Signature as K256Signature, VerifyingKey};
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use sha2::Sha256;

pub const SUI_SIGNATURE_SCHEME_FLAG_ED25519: u8 = 0x00;
pub const SUI_SIGNATURE_SCHEME_FLAG_SECP256K1: u8 = 0x01;
pub const SUI_SIGNATURE_SCHEME_FLAG_SECP256R1: u8 = 0x02;
pub const SUI_SIGNATURE_SCHEME_FLAG_MULTISIG: u8 = 0x03;
pub const SUI_SIGNATURE_SCHEME_FLAG_ZKLOGIN: u8 = 0x05;
pub const SUI_SIGNATURE_SCHEME_FLAG_PASSKEY: u8 = 0x06;

// Intent scope definitions
pub const INTENT_SCOPE_TRANSACTION: u8 = 0;
pub const INTENT_SCOPE_PERSONAL_MESSAGE: u8 = 3; // For authentication
pub const INTENT_VERSION_V0: u8 = 0;
pub const INTENT_APP_ID_SUI: u8 = 0;

// Intent prefixes
pub const INTENT_PREFIX_TRANSACTION: [u8; 3] = [INTENT_SCOPE_TRANSACTION, INTENT_VERSION_V0, INTENT_APP_ID_SUI];
pub const INTENT_PREFIX_AUTH: [u8; 3] = [INTENT_SCOPE_PERSONAL_MESSAGE, INTENT_VERSION_V0, INTENT_APP_ID_SUI];

// ECDSA curve orders for canonical signature validation
const SECP256K1_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

const SECP256R1_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];

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
            SUI_SIGNATURE_SCHEME_FLAG_SECP256K1 => {
                if signature_bytes.len() != 98 {
                    return Err(SuiError::SignatureFormatError(format!(
                        "ECDSA Secp256k1 signature must be 98 bytes, got {}",
                        signature_bytes.len()
                    )));
                }
                let signature = signature_bytes[1..65].to_vec();
                let public_key = signature_bytes[65..].to_vec();
                
                // Validate canonical signature
                validate_ecdsa_signature(&signature, &SECP256K1_ORDER)?;
                
                Ok(SuiSignature {
                    scheme,
                    signature,
                    public_key,
                })
            }
            SUI_SIGNATURE_SCHEME_FLAG_SECP256R1 => {
                if signature_bytes.len() != 98 {
                    return Err(SuiError::SignatureFormatError(format!(
                        "ECDSA Secp256r1 signature must be 98 bytes, got {}",
                        signature_bytes.len()
                    )));
                }
                let signature = signature_bytes[1..65].to_vec();
                let public_key = signature_bytes[65..].to_vec();
                
                // Validate canonical signature
                validate_ecdsa_signature(&signature, &SECP256R1_ORDER)?;
                
                Ok(SuiSignature {
                    scheme,
                    signature,
                    public_key,
                })
            }
            SUI_SIGNATURE_SCHEME_FLAG_ZKLOGIN => {
                if signature_bytes.len() < 2 {
                    return Err(SuiError::SignatureFormatError(
                        "zkLogin signature too short".to_string()
                    ));
                }
                
                let signature = signature_bytes[1..].to_vec();
                let public_key = vec![]; // zkLogin doesn't have traditional public key
                
                Ok(SuiSignature {
                    scheme,
                    signature,
                    public_key,
                })
            }
            SUI_SIGNATURE_SCHEME_FLAG_MULTISIG | SUI_SIGNATURE_SCHEME_FLAG_PASSKEY => {
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

fn validate_ecdsa_signature(signature: &[u8], curve_order: &[u8; 32]) -> Result<(), SuiError> {
    if signature.len() != 64 {
        return Err(SuiError::SignatureFormatError(
            "ECDSA signature must be 64 bytes".to_string()
        ));
    }
    
    let r_bytes = &signature[0..32];
    let s_bytes = &signature[32..64];
    
    // Check r is in valid range (1 to curve_order - 1)
    if r_bytes.iter().all(|&b| b == 0) {
        return Err(SuiError::InvalidSignature("r value cannot be zero".to_string()));
    }
    
    if r_bytes >= curve_order {
        return Err(SuiError::InvalidSignature("r value too large".to_string()));
    }
    
    // Check s is in lower half of curve order (canonical form)
    let mut half_order = [0u8; 32];
    let mut carry = 0u8;
    for i in (0..32).rev() {
        let sum = curve_order[i] as u16 + carry as u16;
        half_order[i] = (sum >> 1) as u8;
        carry = if sum & 1 == 1 { 0x80 } else { 0 };
    }
    
    if s_bytes > &half_order {
        return Err(SuiError::InvalidSignature(
            "s value not in lower half of curve order (not canonical)".to_string()
        ));
    }
    
    if s_bytes.iter().all(|&b| b == 0) {
        return Err(SuiError::InvalidSignature("s value cannot be zero".to_string()));
    }
    
    Ok(())
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

pub fn create_auth_intent_hash(message: &[u8]) -> Result<Vec<u8>, SuiError> {
    let mut intent_message = Vec::with_capacity(INTENT_PREFIX_AUTH.len() + message.len());
    intent_message.extend_from_slice(&INTENT_PREFIX_AUTH);
    intent_message.extend_from_slice(message);

    let mut hasher = Blake2b::new();
    hasher.update(&intent_message);
    let hash = hasher.finalize();

    Ok(hash[..32].to_vec())
}

pub fn bytes_to_sui_address(bytes: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(bytes))
}

pub fn verify_sui_signature(
    blake2b_hash: &[u8], // This should be the 32-byte Blake2b hash of intent message
    signature: &SuiSignature,
) -> Result<String, SuiError> {
    if blake2b_hash.len() != 32 {
        return Err(SuiError::HashError("Blake2b hash must be 32 bytes".to_string()));
    }
    
    match signature.scheme() {
        SUI_SIGNATURE_SCHEME_FLAG_ED25519 => {
            let public_key = PublicKey::from_bytes(signature.public_key())
                .map_err(|e| SuiError::InvalidPublicKey(e.to_string()))?;
            
            let sig = Signature::from_bytes(signature.signature())
                .map_err(|e| SuiError::InvalidSignature(e.to_string()))?;
            
            // Ed25519 uses SHA-512 internally, but we pass the Blake2b hash directly
            public_key
                .verify(blake2b_hash, &sig)
                .map_err(|e| SuiError::InvalidSignature(e.to_string()))?;
            
            derive_sui_address_from_public_key(SUI_SIGNATURE_SCHEME_FLAG_ED25519, signature.public_key())
        }
        SUI_SIGNATURE_SCHEME_FLAG_SECP256K1 => {
            // ECDSA requires SHA-256 hashing of the Blake2b digest
            let mut sha256_hasher = Sha256::new();
            sha256_hasher.update(blake2b_hash);
            let ecdsa_hash = sha256_hasher.finalize();
            
            let verifying_key = VerifyingKey::from_sec1_bytes(signature.public_key())
                .map_err(|e| SuiError::InvalidPublicKey(e.to_string()))?;
            
            let sig = K256Signature::from_bytes(signature.signature().into())
                .map_err(|e| SuiError::InvalidSignature(e.to_string()))?;
            
            verifying_key
                .verify(&ecdsa_hash, &sig)
                .map_err(|e| SuiError::InvalidSignature(e.to_string()))?;
            
            derive_sui_address_from_public_key(SUI_SIGNATURE_SCHEME_FLAG_SECP256K1, signature.public_key())
        }
        SUI_SIGNATURE_SCHEME_FLAG_SECP256R1 => {
            // ECDSA requires SHA-256 hashing of the Blake2b digest
            let mut sha256_hasher = Sha256::new();
            sha256_hasher.update(blake2b_hash);
            let ecdsa_hash = sha256_hasher.finalize();
            
            let verifying_key = P256VerifyingKey::from_sec1_bytes(signature.public_key())
                .map_err(|e| SuiError::InvalidPublicKey(e.to_string()))?;
            
            let sig = P256Signature::from_bytes(signature.signature().into())
                .map_err(|e| SuiError::InvalidSignature(e.to_string()))?;
            
            verifying_key
                .verify(&ecdsa_hash, &sig)
                .map_err(|e| SuiError::InvalidSignature(e.to_string()))?;
            
            derive_sui_address_from_public_key(SUI_SIGNATURE_SCHEME_FLAG_SECP256R1, signature.public_key())
        }
        SUI_SIGNATURE_SCHEME_FLAG_ZKLOGIN => {
            // TODO: Implement proper zkLogin verification
            // For now, return an error as zkLogin requires complex verification
            Err(SuiError::UnsupportedSignatureScheme(signature.scheme()))
        }
        _ => Err(SuiError::UnsupportedSignatureScheme(signature.scheme())),
    }
}

pub fn derive_sui_address_from_public_key(scheme: u8, public_key: &[u8]) -> Result<String, SuiError> {
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

    let mut hasher = Blake2b::new();
    hasher.update([scheme]); // Prepend scheme identifier
    hasher.update(public_key);
    let hash = hasher.finalize();

    let address_bytes = &hash[..32];
    Ok(format!("0x{}", hex::encode(address_bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_sui_address_creation() {
        let valid_address = "0x".to_owned() + &"a".repeat(64);
        let address = SuiAddress::new(&valid_address);
        assert!(address.is_ok());
        
        let invalid_prefix = "1x".to_owned() + &"a".repeat(64);
        let address = SuiAddress::new(&invalid_prefix);
        assert!(address.is_err());
        
        let invalid_length = "0x".to_owned() + &"a".repeat(63);
        let address = SuiAddress::new(&invalid_length);
        assert!(address.is_err());
    }
    
    #[test]
    fn test_create_auth_intent_hash() {
        let message = b"Hello, Sui Auth!";
        let result = create_auth_intent_hash(message);
        assert!(result.is_ok());
        let hash = result.unwrap();
        assert_eq!(hash.len(), 32);
    }
    
    #[test]
    fn test_intent_prefixes() {
        assert_eq!(INTENT_PREFIX_TRANSACTION, [0, 0, 0]);
        assert_eq!(INTENT_PREFIX_AUTH, [3, 0, 0]);
    }
    
    #[test]
    fn test_ecdsa_signature_validation() {
        let invalid_sig = [1u8; 63];
        let result = validate_ecdsa_signature(&invalid_sig, &SECP256K1_ORDER);
        assert!(result.is_err());
    }
}