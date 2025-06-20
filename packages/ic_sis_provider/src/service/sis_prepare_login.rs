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
    let address = SuiAddress::new(&address)?;

    match ic_sis::login::prepare_login(&address) {
        Ok((message, nonce)) => {
            Ok(PrepareLoginOkResponse {
                sis_message: message.to_human_readable(),
                nonce,
            })
        }
        Err(e) => Err(e.into()),
    }
}
