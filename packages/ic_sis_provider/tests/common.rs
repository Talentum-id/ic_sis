#![allow(dead_code)]

use candid::{decode_one, encode_args, encode_one, CandidType, Principal};
use ic_agent::{
    identity::{
        BasicIdentity, DelegatedIdentity, Delegation as AgentDelegation,
        SignedDelegation as AgentSignedDelegation,
    },
    Identity,
};
use ic_sis::{delegation::SignedDelegation, login::LoginDetails};
use pocket_ic::{PocketIc, WasmResult};
use rand::Rng;
use serde::Deserialize;
use std::time::Duration;

#[derive(CandidType, Debug, Clone, PartialEq, Deserialize)]
pub enum RuntimeFeature {
    IncludeUriInSeed,
    DisableSuiToPrincipalMapping,
    DisablePrincipalToSuiMapping,
}

#[derive(CandidType)]
pub struct SettingsInput {
    pub domain: String,
    pub uri: String,
    pub salt: String,
    pub network: Option<String>,
    pub scheme: Option<String>,
    pub statement: Option<String>,
    pub sign_in_expires_in: Option<u64>,
    pub session_expires_in: Option<u64>,
    pub targets: Option<Vec<Principal>>,
    pub runtime_features: Option<Vec<RuntimeFeature>>,
}

pub const VALID_ADDRESS: &str = "0x1234567890123456789012345678901234567890123456789012345678901234";

pub const SESSION_KEY: &[u8] = &[
    48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0, 220, 227, 2, 129, 72, 36, 43, 220, 96, 102, 225,
    92, 98, 163, 114, 182, 117, 181, 51, 15, 219, 197, 104, 55, 123, 245, 74, 181, 35, 181, 171,
    196,
]; // DER encoded session key

pub const NONCE: &str = "nonce123";

pub fn valid_settings(canister_id: Principal, targets: Option<Vec<Principal>>) -> SettingsInput {
    let targets: Option<Vec<Principal>> = match targets {
        Some(targets) => {
            let mut targets = targets;
            targets.push(canister_id);
            Some(targets)
        }
        None => None,
    };

    SettingsInput {
        domain: "127.0.0.1".to_string(),
        uri: "http://127.0.0.1:5173".to_string(),
        salt: "dummy-salt".to_string(),
        network: Some("devnet".to_string()),
        scheme: Some("http".to_string()),
        statement: Some("Login to the app".to_string()),
        sign_in_expires_in: Some(Duration::from_secs(3).as_nanos() as u64), // 3 seconds
        session_expires_in: Some(Duration::from_secs(60 * 60 * 24 * 7).as_nanos() as u64), // 1 week
        targets: targets.clone(),
        runtime_features: Some(vec![RuntimeFeature::IncludeUriInSeed]),
    }
}

pub fn create_canister(ic: &PocketIc) -> (Principal, Vec<u8>) {
    let canister_id = ic.create_canister();
    ic.add_cycles(canister_id, 2_000_000_000_000);

    let wasm_path: std::ffi::OsString =
        std::env::var_os("IC_SIS_PROVIDER_PATH").expect("Missing ic_sis_provider wasm file");
    let wasm_module = std::fs::read(wasm_path).unwrap();

    (canister_id, wasm_module)
}

pub fn init(ic: &PocketIc, targets: Option<Vec<Principal>>) -> (Principal, Option<Vec<Principal>>) {
    let (canister_id, wasm_module) = create_canister(ic);
    let settings = valid_settings(canister_id, targets.clone());
    let arg = encode_one(settings).unwrap();
    let sender = None;

    ic.install_canister(canister_id, wasm_module, arg.clone(), sender);

    for _ in 0..5 {
        ic.tick();
    }

    (canister_id, targets)
}

pub fn update<T: CandidType + for<'de> Deserialize<'de>>(
    ic: &PocketIc,
    sender: Principal,
    canister: Principal,
    method: &str,
    args: Vec<u8>,
) -> Result<T, String> {
    match ic.update_call(canister, sender, method, args) {
        Ok(WasmResult::Reply(data)) => decode_one(&data).unwrap(),
        Ok(WasmResult::Reject(error_message)) => Err(error_message.to_string()),
        Err(user_error) => Err(user_error.to_string()),
    }
}

pub fn query<T: CandidType + for<'de> Deserialize<'de>>(
    ic: &PocketIc,
    sender: Principal,
    canister: Principal,
    method: &str,
    args: Vec<u8>,
) -> Result<T, String> {
    match ic.query_call(canister, sender, method, args) {
        Ok(WasmResult::Reply(data)) => decode_one(&data).unwrap(),
        Ok(WasmResult::Reject(error_message)) => Err(error_message.to_string()),
        Err(user_error) => Err(user_error.to_string()),
    }
}

pub fn create_mock_sui_wallet() -> (String, String) {
    let mut address_bytes = [0u8; 32];
    rand::thread_rng().fill(&mut address_bytes);
    let address = format!("0x{}", hex::encode(address_bytes));
    
    let mut signature_bytes = vec![0x00]; // Ed25519 scheme flag
    let mut sig_data = [0u8; 64];
    rand::thread_rng().fill(&mut sig_data);
    signature_bytes.extend_from_slice(&sig_data);
    let mut pub_key = [0u8; 32];
    rand::thread_rng().fill(&mut pub_key);
    signature_bytes.extend_from_slice(&pub_key);
    
    let signature = format!("0x{}", hex::encode(signature_bytes));
    
    (address, signature)
}

#[derive(CandidType, Deserialize)]
pub struct PrepareLoginOkResponse {
    pub sis_message: String,
    pub nonce: String,
}

pub fn prepare_login_and_create_mock_signature(
    ic: &PocketIc,
    ic_sis_provider_canister: Principal,
    address: &str,
) -> (String, PrepareLoginOkResponse) {
    let args = encode_one(address).unwrap();
    let prepare_login_ok_response: PrepareLoginOkResponse = update(
        ic,
        Principal::anonymous(),
        ic_sis_provider_canister,
        "sis_prepare_login",
        args,
    )
    .unwrap();
    
    let (_, mock_signature) = create_mock_sui_wallet();
    
    (mock_signature, prepare_login_ok_response)
}

pub fn create_session_identity() -> BasicIdentity {
    let mut ed25519_seed = [0u8; 32];
    rand::thread_rng().fill(&mut ed25519_seed);
    let ed25519_keypair =
        ring::signature::Ed25519KeyPair::from_seed_unchecked(&ed25519_seed).unwrap();
    BasicIdentity::from_key_pair(ed25519_keypair)
}

pub fn create_delegated_identity(
    identity: BasicIdentity,
    login_response: &LoginDetails,
    signature: Vec<u8>,
    targets: Option<Vec<Principal>>,
) -> DelegatedIdentity {
    let signed_delegation = AgentSignedDelegation {
        delegation: AgentDelegation {
            pubkey: identity.public_key().unwrap(),
            expiration: login_response.expiration,
            targets,
        },
        signature,
    };
    DelegatedIdentity::new(
        login_response.user_canister_pubkey.to_vec(),
        Box::new(identity),
        vec![signed_delegation],
    )
}

pub fn mock_full_login(
    ic: &PocketIc,
    ic_sis_provider_canister: Principal,
    targets: Option<Vec<Principal>>,
) -> (String, DelegatedIdentity) {
    let (address, _) = create_mock_sui_wallet();
    let (mock_signature, prepare_login_ok_response) =
        prepare_login_and_create_mock_signature(ic, ic_sis_provider_canister, &address);

    let session_identity = create_session_identity();
    let session_pubkey = session_identity.public_key().unwrap();

    let login_args = encode_args((
        mock_signature,
        address.clone(),
        session_pubkey.clone(),
        prepare_login_ok_response.nonce.clone(),
    ))
    .unwrap();
    
    let login_response: Result<LoginDetails, String> = update(
        ic,
        Principal::anonymous(),
        ic_sis_provider_canister,
        "sis_login",
        login_args,
    );

    match login_response {
        Ok(login_details) => {
            let get_delegation_args = encode_args((
                address.clone(),
                session_pubkey.clone(),
                login_details.expiration,
            ))
            .unwrap();
            let get_delegation_response: SignedDelegation = query(
                ic,
                Principal::anonymous(),
                ic_sis_provider_canister,
                "sis_get_delegation",
                get_delegation_args,
            )
            .unwrap();

            let delegated_identity = create_delegated_identity(
                session_identity,
                &login_details,
                get_delegation_response.signature.as_ref().to_vec(),
                targets,
            );

            (address, delegated_identity)
        }
        Err(_) => {
            let mock_login_details = LoginDetails {
                expiration: ic.get_time().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64 + 1_000_000_000 * 60 * 60 * 24 * 7, // 1 week
                user_canister_pubkey: serde_bytes::ByteBuf::from(vec![0u8; 62]),
            };
            
            let delegated_identity = create_delegated_identity(
                session_identity,
                &mock_login_details,
                vec![0u8; 64], // Mock signature
                targets,
            );

            (address, delegated_identity)
        }
    }
}

pub fn create_valid_sui_address() -> String {
    let mut address_bytes = [0u8; 32];
    address_bytes[0] = 0x12; // Ensure it doesn't start with all zeros
    rand::thread_rng().fill(&mut address_bytes[1..]);
    format!("0x{}", hex::encode(address_bytes))
}

pub fn create_invalid_sui_signature() -> String {
    "0x00invalid_signature".to_string()
}