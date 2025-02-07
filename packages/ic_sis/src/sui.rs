use std::fmt;
use fastcrypto::{
    ed25519::{Ed25519PublicKey, Ed25519Signature},
    secp256k1::{Secp256k1PublicKey, Secp256k1Signature},
    traits::Authenticator,
};

#[derive(Debug)]
pub enum SuiError {
    AddressFormatError(String),
    DecodingError(String),
    SignatureFormatError(String),
    InvalidSignature,
    PublicKeyRecoveryFailure,
    UnsupportedSignatureScheme,
}

impl fmt::Display for SuiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SuiError::AddressFormatError(e) => write!(f, "Address format error: {}", e),
            SuiError::DecodingError(e) => write!(f, "Decoding error: {}", e),
            SuiError::SignatureFormatError(e) => write!(f, "Signature format error: {}", e),
            SuiError::InvalidSignature => write!(f, "Invalid signature"),
            SuiError::PublicKeyRecoveryFailure => write!(f, "Public key recovery failure"),
            SuiError::UnsupportedSignatureScheme => write!(f, "Unsupported signature scheme"),
        }
    }
}

impl From<SuiError> for String {
    fn from(error: SuiError) -> Self {
        error.to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuiAddress([u8; 32]);

impl SuiAddress {
    pub fn new(address: &str) -> Result<Self, SuiError> {
        if !address.starts_with("0x") {
            return Err(SuiError::AddressFormatError("Must start with '0x'".into()));
        }

        let hex_str = &address[2..];
        if hex_str.len() != 64 {
            return Err(SuiError::AddressFormatError(
                "Address must be 32 bytes (64 hex characters)".into(),
            ));
        }

        let bytes = hex::decode(hex_str)
            .map_err(|e| SuiError::DecodingError(e.to_string()))?;

        let mut addr = [0u8; 32];
        addr.copy_from_slice(&bytes);
        Ok(SuiAddress(addr))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        SuiAddress(bytes)
    }

    pub fn to_string(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub enum SuiSignatureScheme {
    Ed25519,
    Secp256k1,
}

#[derive(Debug)]
pub struct SuiSignature {
    pub bytes: Vec<u8>,
    pub scheme: SuiSignatureScheme,
}

impl SuiSignature {
    pub fn new(signature: &str, scheme: SuiSignatureScheme) -> Result<Self, SuiError> {
        if !signature.starts_with("0x") {
            return Err(SuiError::SignatureFormatError("Must start with '0x'".into()));
        }

        let bytes = hex::decode(&signature[2..])
            .map_err(|e| SuiError::DecodingError(e.to_string()))?;

        Ok(SuiSignature { bytes, scheme })
    }

    pub fn verify(&self, message: &[u8], public_key: &[u8]) -> Result<bool, SuiError> {
        match self.scheme {
            SuiSignatureScheme::Ed25519 => {
                let pk = Ed25519PublicKey::from_bytes(public_key)
                    .map_err(|_| SuiError::PublicKeyRecoveryFailure)?;
                
                let sig = Ed25519Signature::from_bytes(&self.bytes)
                    .map_err(|_| SuiError::InvalidSignature)?;

                Ok(sig.verify(message, &pk))
            }
            SuiSignatureScheme::Secp256k1 => {
                let pk = Secp256k1PublicKey::from_bytes(public_key)
                    .map_err(|_| SuiError::PublicKeyRecoveryFailure)?;
                
                let sig = Secp256k1Signature::from_bytes(&self.bytes)
                    .map_err(|_| SuiError::InvalidSignature)?;

                Ok(sig.verify(message, &pk))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastcrypto::traits::{KeyPair, Signer};
    use rand::rngs::OsRng;

    #[test]
    fn test_sui_address_validation() {
        // Valid Sui address (32 bytes)
        let valid_address = "0x".to_string() + &"a".repeat(64);
        assert!(SuiAddress::new(&valid_address).is_ok());

        // Invalid prefix
        let invalid_prefix = "a".repeat(64);
        assert!(SuiAddress::new(&invalid_prefix).is_err());

        // Invalid length
        let invalid_length = "0x".to_string() + &"a".repeat(63);
        assert!(SuiAddress::new(&invalid_length).is_err());

        // Invalid hex characters
        let invalid_hex = "0x".to_string() + &"g".repeat(64);
        assert!(SuiAddress::new(&invalid_hex).is_err());
    }

    #[test]
    fn test_ed25519_signature_verification() {
        use fastcrypto::ed25519::Ed25519KeyPair;

        // Generate a random Ed25519 keypair
        let kp = Ed25519KeyPair::generate(&mut OsRng);
        
        // Create test message
        let message = b"Test message";
        
        // Sign message
        let signature = kp.sign(message);
        
        // Create SuiSignature
        let sui_sig = SuiSignature {
            bytes: signature.as_ref().to_vec(),
            scheme: SuiSignatureScheme::Ed25519,
        };
        
        // Verify signature
        let result = sui_sig.verify(message, kp.public().as_ref());
        assert!(result.is_ok());
        assert!(result.unwrap());
        
        // Test invalid signature
        let mut invalid_sig = signature.as_ref().to_vec();
        invalid_sig[0] ^= 0xFF; // Flip some bits
        let invalid_sui_sig = SuiSignature {
            bytes: invalid_sig,
            scheme: SuiSignatureScheme::Ed25519,
        };
        
        let result = invalid_sui_sig.verify(message, kp.public().as_ref());
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_secp256k1_signature_verification() {
        use fastcrypto::secp256k1::Secp256k1KeyPair;

        // Generate a random Secp256k1 keypair
        let kp = Secp256k1KeyPair::generate(&mut OsRng);
        
        // Create test message
        let message = b"Test message";
        
        // Sign message
        let signature = kp.sign(message);
        
        // Create SuiSignature
        let sui_sig = SuiSignature {
            bytes: signature.as_ref().to_vec(),
            scheme: SuiSignatureScheme::Secp256k1,
        };
        
        // Verify signature
        let result = sui_sig.verify(message, kp.public().as_ref());
        assert!(result.is_ok());
        assert!(result.unwrap());
        
        // Test invalid signature
        let mut invalid_sig = signature.as_ref().to_vec();
        invalid_sig[0] ^= 0xFF; // Flip some bits
        let invalid_sui_sig = SuiSignature {
            bytes: invalid_sig,
            scheme: SuiSignatureScheme::Secp256k1,
        };
        
        let result = invalid_sui_sig.verify(message, kp.public().as_ref());
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }
}