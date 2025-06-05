use candid::Principal;
use ic_cdk::update;
use ic_sis::{
    login::LoginDetails,
    sui::{SuiAddress, SuiSignature},
};
use ic_stable_structures::storable::Blob;
use serde_bytes::ByteBuf;

use crate::{update_root_hash, ADDRESS_PRINCIPAL, PRINCIPAL_ADDRESS, SETTINGS, STATE};

#[update]
fn sis_login(
    signature: String,
    address: String,
    session_key: ByteBuf,
    nonce: String,
) -> Result<LoginDetails, String> {
    STATE.with(|state| {
        let signature_map = &mut *state.signature_map.borrow_mut();

        let address =
            SuiAddress::new(&address).map_err(|e| format!("Invalid Sui address: {}", e))?;

        let signature = SuiSignature::from_hex(&signature)
            .map_err(|e| format!("Invalid signature format: {}", e))?;

        let login_response = ic_sis::login::login(
            &signature,
            &address,
            session_key,
            signature_map,
            &ic_cdk::api::id(),
            &nonce,
        )
        .map_err(|e| match e.to_string().as_str() {
            msg if msg.contains("Message not found") => {
                "Authentication session expired or invalid nonce. Please try signing in again."
                    .to_string()
            }
            msg if msg.contains("Address mismatch") => {
                "Signature verification failed: recovered address does not match provided address."
                    .to_string()
            }
            msg if msg.contains("Signature verification failed") => {
                "Invalid signature: signature verification failed.".to_string()
            }
            _ => format!("Authentication failed: {}", e),
        })?;

        update_root_hash(&state.asset_hashes.borrow(), signature_map);

        let principal: Blob<29> =
            Principal::self_authenticating(&login_response.user_canister_pubkey).as_slice()[..29]
                .try_into()
                .map_err(|_| {
                    "Failed to create principal from user canister public key".to_string()
                })?;

        manage_principal_address_mappings(&principal, &address);

        Ok(login_response)
    })
}

fn manage_principal_address_mappings(principal: &Blob<29>, address: &SuiAddress) {
    SETTINGS.with(|s| {
        let settings = s.borrow();
        if !settings.disable_principal_to_sui_mapping {
            PRINCIPAL_ADDRESS.with(|pa| {
                pa.borrow_mut().insert(*principal, address.as_byte_array());
            });
        }
        if !settings.disable_sui_to_principal_mapping {
            ADDRESS_PRINCIPAL.with(|ap| {
                ap.borrow_mut().insert(address.as_byte_array(), *principal);
            });
        }
    });
}
