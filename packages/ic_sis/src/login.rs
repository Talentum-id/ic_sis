use std::fmt;

use candid::{CandidType, Principal};
use serde::Deserialize;
use serde_bytes::ByteBuf;
use simple_asn1::ASN1EncodeErr;

use crate::{
    delegation::{
        create_delegation, create_delegation_hash, create_user_canister_pubkey, generate_seed,
        DelegationError,
    },
    sui::{SuiAddress, SuiError, SuiSignature},
    hash,
    rand::generate_nonce,
    settings::Settings,
    signature_map::SignatureMap,
    sis::{SisMessage, SisMessageError},
    time::get_current_time,
    with_settings, SIS_MESSAGES,
};

const MAX_SIGS_TO_PRUNE: usize = 10;

pub fn prepare_login(address: &SuiAddress) -> Result<(SisMessage, String), SuiError> {
    let nonce = generate_nonce();
    let message = SisMessage::new(address, &nonce);

    // Save the SIS message for use in the login call
    SIS_MESSAGES.with_borrow_mut(|sis_messages| {
        sis_messages.insert(message.clone(), address, &nonce);
    });

    Ok((message, nonce))
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct LoginDetails {
    pub expiration: u64,
    pub user_canister_pubkey: ByteBuf,
}

pub enum LoginError {
    SuiError(SuiError),
    SisMessageError(SisMessageError),
    AddressMismatch,
    DelegationError(DelegationError),
    ASN1EncodeErr(ASN1EncodeErr),
}

impl From<SuiError> for LoginError {
    fn from(err: SuiError) -> Self {
        LoginError::SuiError(err)
    }
}

impl From<SisMessageError> for LoginError {
    fn from(err: SisMessageError) -> Self {
        LoginError::SisMessageError(err)
    }
}

impl From<DelegationError> for LoginError {
    fn from(err: DelegationError) -> Self {
        LoginError::DelegationError(err)
    }
}

impl From<ASN1EncodeErr> for LoginError {
    fn from(err: ASN1EncodeErr) -> Self {
        LoginError::ASN1EncodeErr(err)
    }
}

impl fmt::Display for LoginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoginError::SuiError(e) => write!(f, "{}", e),
            LoginError::SisMessageError(e) => write!(f, "{}", e),
            LoginError::AddressMismatch => write!(f, "Recovered address does not match"),
            LoginError::DelegationError(e) => write!(f, "{}", e),
            LoginError::ASN1EncodeErr(e) => write!(f, "{}", e),
        }
    }
}

pub fn login(
    signature: &SuiSignature,
    address: &SuiAddress,
    public_key: &[u8],
    session_key: ByteBuf,
    signature_map: &mut SignatureMap,
    canister_id: &Principal,
    nonce: &str,
) -> Result<LoginDetails, LoginError> {
    SIS_MESSAGES.with_borrow_mut(|sis_messages| {
        sis_messages.prune_expired();

        let message = sis_messages.get(address, nonce)?;
        let signing_message = message.get_signing_message();

        // Verify Sui signature
        if !signature.verify(&signing_message, public_key)? {
            return Err(LoginError::SuiError(SuiError::InvalidSignature));
        }

        sis_messages.remove(address, nonce);

        let expiration = with_settings!(|settings: &Settings| {
            message
                .issued_at
                .saturating_add(settings.session_expires_in)
        });

        let seed = generate_seed(address);
        signature_map.prune_expired(get_current_time(), MAX_SIGS_TO_PRUNE);

        let delegation = create_delegation(session_key, expiration)?;
        let delegation_hash = create_delegation_hash(&delegation);
        signature_map.put(hash::hash_bytes(seed), delegation_hash);

        let user_canister_pubkey = create_user_canister_pubkey(canister_id, seed.to_vec())?;

        Ok(LoginDetails {
            expiration,
            user_canister_pubkey: ByteBuf::from(user_canister_pubkey),
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastcrypto::{
        ed25519::Ed25519KeyPair,
        traits::{KeyPair, Signer},
    };
    use rand::rngs::OsRng;

    #[test]
    fn test_login_flow() {
        // Create a test address
        let address = SuiAddress::new(
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        ).unwrap();

        // Prepare login
        let (message, nonce) = prepare_login(&address).unwrap();
        
        // Generate test keypair
        let kp = Ed25519KeyPair::generate(&mut OsRng);
        
        // Get signing message and create signature
        let signing_message = message.get_signing_message();
        let sig = kp.sign(&signing_message);
        
        let sui_sig = SuiSignature {
            bytes: sig.as_ref().to_vec(),
            scheme: crate::sui::SuiSignatureScheme::Ed25519,
        };

        // Create test session key
        let session_key = ByteBuf::from(vec![1, 2, 3, 4]);
        let mut signature_map = SignatureMap::default();
        let canister_id = Principal::from_text("aaaaa-aa").unwrap();

        // Initialize settings
        use crate::settings::SettingsBuilder;
        use crate::SETTINGS;
        
        let settings = SettingsBuilder::new("example.com", "http://example.com", "test_salt")
            .build()
            .unwrap();
        SETTINGS.set(Some(settings));

        // Perform login
        let result = login(
            &sui_sig,
            &address,
            kp.public().as_ref(),
            session_key,
            &mut signature_map,
            &canister_id,
            &nonce,
        );

        assert!(result.is_ok());
        let login_details = result.unwrap();
        assert!(login_details.expiration > get_current_time());
        assert!(!login_details.user_canister_pubkey.is_empty());
    }

    #[test]
    fn test_login_invalid_signature() {
        let address = SuiAddress::new(
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        ).unwrap();

        let (message, nonce) = prepare_login(&address).unwrap();
        
        let kp = Ed25519KeyPair::generate(&mut OsRng);
        let signing_message = message.get_signing_message();
        let mut sig = kp.sign(&signing_message).as_ref().to_vec();
        
        // Corrupt the signature
        sig[0] ^= 0xFF;
        
        let sui_sig = SuiSignature {
            bytes: sig,
            scheme: crate::sui::SuiSignatureScheme::Ed25519,
        };

        let session_key = ByteBuf::from(vec![1, 2, 3, 4]);
        let mut signature_map = SignatureMap::default();
        let canister_id = Principal::from_text("aaaaa-aa").unwrap();

        // Initialize settings
        use crate::settings::SettingsBuilder;
        use crate::SETTINGS;
        
        let settings = SettingsBuilder::new("example.com", "http://example.com", "test_salt")
            .build()
            .unwrap();
        SETTINGS.set(Some(settings));

        let result = login(
            &sui_sig,
            &address,
            kp.public().as_ref(),
            session_key,
            &mut signature_map,
            &canister_id,
            &nonce,
        );

        assert!(result.is_err());
        match result {
            Err(LoginError::SuiError(SuiError::InvalidSignature)) => (),
            _ => panic!("Expected InvalidSignature error"),
        }
    }

    #[test]
    fn test_login_expired_message() {
        let address = SuiAddress::new(
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        ).unwrap();

        let (message, nonce) = prepare_login(&address).unwrap();
        
        // Wait for message to expire
        std::thread::sleep(std::time::Duration::from_secs(1));

        let kp = Ed25519KeyPair::generate(&mut OsRng);
        let signing_message = message.get_signing_message();
        let sig = kp.sign(&signing_message);
        
        let sui_sig = SuiSignature {
            bytes: sig.as_ref().to_vec(),
            scheme: crate::sui::SuiSignatureScheme::Ed25519,
        };

        let session_key = ByteBuf::from(vec![1, 2, 3, 4]);
        let mut signature_map = SignatureMap::default();
        let canister_id = Principal::from_text("aaaaa-aa").unwrap();

        // Initialize settings
        use crate::settings::SettingsBuilder;
        use crate::SETTINGS;
        
        let settings = SettingsBuilder::new("example.com", "http://example.com", "test_salt")
            .build()
            .unwrap();
        SETTINGS.set(Some(settings));

        let result = login(
            &sui_sig,
            &address,
            kp.public().as_ref(),
            session_key,
            &mut signature_map,
            &canister_id,
            &nonce,
        );

        assert!(result.is_err());
        match result {
            Err(LoginError::SisMessageError(SisMessageError::MessageExpired)) => (),
            _ => panic!("Expected MessageExpired error"),
        }
    }
}