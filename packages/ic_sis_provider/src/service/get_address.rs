use ic_cdk::query;
use ic_sis::sui::bytes_to_sui_address;
use ic_stable_structures::storable::Blob;
use serde_bytes::ByteBuf;

use crate::{PRINCIPAL_ADDRESS, SETTINGS};

#[query]
pub(crate) fn get_address(principal: ByteBuf) -> Result<String, String> {
    SETTINGS.with_borrow(|s| {
        if s.disable_principal_to_sui_mapping {
            return Err("Principal to Sui address mapping is disabled".to_string());
        }
        Ok(())
    })?;

    let principal: Blob<29> = principal
        .as_ref()
        .try_into()
        .map_err(|_| "Failed to convert ByteBuf to Blob<29>")?;

    let address = PRINCIPAL_ADDRESS.with(|pa| {
        pa.borrow().get(&principal).map_or(
            Err("No address found for the given principal".to_string()),
            |a| Ok(bytes_to_sui_address(&a)),
        )
    })?;

    Ok(address)
}