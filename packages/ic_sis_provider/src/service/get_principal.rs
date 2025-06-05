use ic_cdk::query;
use ic_sis::sui::SuiAddress;
use serde_bytes::ByteBuf;

use crate::{ADDRESS_PRINCIPAL, SETTINGS};

#[query]
fn get_principal(address: String) -> Result<ByteBuf, String> {
    SETTINGS.with_borrow(|s| {
        if s.disable_sui_to_principal_mapping {
            return Err("Sui address to principal mapping is disabled".to_string());
        }
        Ok(())
    })?;

    // Create a SuiAddress from the string. This validates the address.
    let address = SuiAddress::new(&address)?;

    ADDRESS_PRINCIPAL.with(|ap| {
        ap.borrow().get(&address.as_byte_array()).map_or(
            Err("No principal found for the given address".to_string()),
            |p| Ok(ByteBuf::from(p.as_ref().to_vec())),
        )
    })
}
