use candid::Principal;
use ic_cdk::update;
use ic_sis::{
    sui::{SuiAddress, SuiSignature},
    login::LoginDetails,
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

        let address = SuiAddress::new(&address)?;

        let signature = SuiSignature::from_hex(&signature)?;

        let login_response = ic_sis::login::login(
            &signature,
            &address,
            session_key,
            signature_map,
            &ic_cdk::api::id(),
            &nonce,
        )
        .map_err(|e| e.to_string())?;

        update_root_hash(&state.asset_hashes.borrow(), signature_map);

        let principal: Blob<29> =
            Principal::self_authenticating(&login_response.user_canister_pubkey).as_slice()[..29]
                .try_into()
                .map_err(|_| format!("Invalid principal: {:?}", login_response))?;

        manage_principal_address_mappings(&principal, &address);

        Ok(login_response)
    })
}

fn manage_principal_address_mappings(principal: &Blob<29>, address: &SuiAddress) {
    SETTINGS.with(|s| {
        if !s.borrow().disable_principal_to_sui_mapping {
            PRINCIPAL_ADDRESS.with(|pa| {
                pa.borrow_mut().insert(*principal, address.as_byte_array());
            });
        }
        if !s.borrow().disable_sui_to_principal_mapping {
            ADDRESS_PRINCIPAL.with(|ap| {
                ap.borrow_mut().insert(address.as_byte_array(), *principal);
            });
        }
    });
}