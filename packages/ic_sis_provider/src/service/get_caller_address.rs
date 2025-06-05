use ic_cdk::query;
use serde_bytes::ByteBuf;

use crate::SETTINGS;

use super::get_address::get_address;

#[query]
fn get_caller_address() -> Result<String, String> {
    SETTINGS.with_borrow(|s| {
        if s.disable_principal_to_sui_mapping {
            return Err("Principal to Sui address mapping is disabled".to_string());
        }
        Ok(())
    })?;

    let principal = ic_cdk::caller();
    get_address(ByteBuf::from(principal.as_slice().to_vec()))
}
