use candid::CandidType;
use ic_cdk::update;
use ic_sis::sui::SuiAddress;

#[derive(CandidType)]
struct PrepareLoginOkResponse {
    sis_message: String,
    nonce: String,
}

#[update]
fn sis_prepare_login(address: String) -> Result<PrepareLoginOkResponse, String> {
    // Create a SuiAddress from the string. This validates the address.
    let address = SuiAddress::new(&address)?;

    match ic_sis::login::prepare_login(&address) {
        Ok(m) => Ok(PrepareLoginOkResponse {
            sis_message: m.0.into(),
            nonce: m.1,
        }),
        Err(e) => Err(e.into()),
    }
}