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
    sui::{SuiAddress, SuiError, SuiSignature, verify_sui_signature},
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
    SignatureVerificationFailed,
    MessageCreationFailed,
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
            LoginError::SignatureVerificationFailed => write!(f, "Signature verification failed"),
            LoginError::MessageCreationFailed => write!(f, "Failed to create message for verification"),
        }
    }
}

pub fn login(
    signature: &SuiSignature,
    address: &SuiAddress,
    session_key: ByteBuf,
    signature_map: &mut SignatureMap,
    canister_id: &Principal,
    nonce: &str,
) -> Result<LoginDetails, LoginError> {
    SIS_MESSAGES.with_borrow_mut(|sis_messages| {
        sis_messages.prune_expired();
        let message = sis_messages.get(address, nonce)?;
        
        let message_bytes = message.to_sign_bytes();

        match verify_sui_signature(&message_bytes, signature) {
            Ok(derived_address) => {
                if derived_address != address.as_str() {
                    return Err(LoginError::AddressMismatch);
                }
            },
            Err(e) => return Err(LoginError::SuiError(e)),
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

pub fn prune_all(signature_map: &mut SignatureMap) -> (usize, usize) {
    let current_time = get_current_time();
    let signatures_pruned = signature_map.prune_expired(current_time, usize::MAX);
    let mut messages_count = 0;

    SIS_MESSAGES.with_borrow_mut(|sis_messages| {
        messages_count = sis_messages.count();
        sis_messages.prune_expired();
    });
    
    (signatures_pruned, messages_count)
}

pub fn clear_all(signature_map: &mut SignatureMap) -> (usize, usize) {
    let signatures_count = signature_map.clear();
    
    let mut messages_count = 0;
    SIS_MESSAGES.with_borrow_mut(|sis_messages| {
        messages_count = sis_messages.count();
        sis_messages.clear();
    });
    
    (signatures_count, messages_count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::SettingsBuilder;
    use crate::SETTINGS;

    #[test]
    fn test_prepare_login() {
        let builder = SettingsBuilder::new("example.com", "http://example.com", "some_salt")
            .network("mainnet");
        let settings = builder.build().unwrap();
        SETTINGS.with(|s| s.borrow_mut().replace(settings));
        let sui_address = "0x".to_owned() + &"a".repeat(64).as_str();

        let address = SuiAddress::new(&sui_address).unwrap();
        
        let result = prepare_login(&address);
        assert!(result.is_ok());
        
        let (message, nonce) = result.unwrap();
        assert_eq!(message.address, address.as_str());
        assert!(!nonce.is_empty());
    }
}