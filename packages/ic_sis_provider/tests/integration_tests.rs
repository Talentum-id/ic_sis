mod common;

use candid::{encode_args, encode_one, Principal};
use common::{
    create_canister, create_session_identity, create_mock_sui_wallet, mock_full_login, init, query, update,
    valid_settings, PrepareLoginOkResponse, RuntimeFeature, NONCE, SESSION_KEY, VALID_ADDRESS,
    create_valid_sui_address, create_invalid_sui_signature, prepare_login_and_create_mock_signature,
};
use ic_agent::Identity;
use ic_sis::login::LoginDetails;
use pocket_ic::PocketIc;
use serde_bytes::ByteBuf;
use std::time::{Duration};

use crate::common::SettingsInput;

fn create_pocket_ic() -> PocketIc {
    PocketIc::new()
}

#[test]
#[should_panic]
fn test_init_with_no_settings() {
    let ic = create_pocket_ic();
    let (canister_id, wasm_module) = common::create_canister(&ic);
    ic.install_canister(canister_id, wasm_module, encode_one(()).unwrap(), None);
}

#[test]
fn test_init_with_valid_settings() {
    let ic = create_pocket_ic();
    let (canister_id, wasm_module) = common::create_canister(&ic);
    let settings = valid_settings(canister_id, None);
    let arg = encode_one(settings).unwrap();
    ic.install_canister(canister_id, wasm_module, arg, None);
}

#[test]
#[should_panic]
fn test_init_with_invalid_settings() {
    let ic = create_pocket_ic();
    let (canister_id, wasm_module) = common::create_canister(&ic);
    let mut settings = valid_settings(canister_id, None);
    settings.domain = "invalid domain".to_string(); // Invalid domain, should cause a panic
    let arg = encode_one(settings).unwrap();
    ic.install_canister(canister_id, wasm_module, arg, None);
}

#[test]
fn test_upgrade_with_changed_arguments() {
    let ic = create_pocket_ic();

    let (ic_sis_provider_canister, _) = init(&ic, None);

    let wasm_path: std::ffi::OsString =
        std::env::var_os("IC_SIS_PROVIDER_PATH").expect("Missing ic_sis_provider wasm file");
    let wasm_module = std::fs::read(wasm_path).unwrap();
    let targets: Option<Vec<Principal>> = Some(vec![ic_sis_provider_canister]);
    let settings = SettingsInput {
        domain: "192.168.0.1".to_string(),
        uri: "http://192.168.0.1:666".to_string(),
        salt: "another-salt".to_string(),
        network: Some("testnet".to_string()),
        scheme: Some("https".to_string()),
        statement: Some("Some login statement".to_string()),
        sign_in_expires_in: Some(Duration::from_secs(300).as_nanos() as u64), // 5 minutes
        session_expires_in: Some(Duration::from_secs(60 * 60 * 24 * 14).as_nanos() as u64), // 2 weeks
        targets: targets.clone(),
        runtime_features: None,
    };
    let arg = encode_one(settings).unwrap();
    let upgrade_result =
        ic.upgrade_canister(ic_sis_provider_canister, wasm_module, arg.clone(), None);
    assert!(upgrade_result.is_ok());

    for _ in 0..10 {
        ic.tick();
    }

    let address = encode_one(VALID_ADDRESS).unwrap();
    let response: Result<PrepareLoginOkResponse, String> = update(
        &ic,
        Principal::anonymous(),
        ic_sis_provider_canister,
        "sis_prepare_login",
        address,
    );
    assert!(response.is_ok());
    let prepare_login_ok_response: PrepareLoginOkResponse = response.unwrap();
    
    let sis_message = &prepare_login_ok_response.sis_message;
    
    assert!(sis_message.contains("192.168.0.1"));
    assert!(sis_message.contains("http://192.168.0.1:666"));
    assert!(sis_message.contains("testnet"));
    assert!(sis_message.contains("Some login statement"));
    assert!(sis_message.contains(VALID_ADDRESS));
}

#[test]
fn test_upgrade_with_no_settings() {
    let ic = create_pocket_ic();
    let (ic_sis_provider_canister, _) = init(&ic, None);
    let wasm_path: std::ffi::OsString =
        std::env::var_os("IC_SIS_PROVIDER_PATH").expect("Missing ic_sis_provider wasm file");
    let wasm_module = std::fs::read(wasm_path).unwrap();
    let result = ic.upgrade_canister(
        ic_sis_provider_canister,
        wasm_module,
        encode_one(()).unwrap(),
        None,
    );
    assert!(result.is_err());
}

#[test]
fn test_sis_prepare_login_invalid_address() {
    let ic = create_pocket_ic();
    let (ic_sis_provider_canister, _) = init(&ic, None);
    let address = encode_one("invalid address").unwrap();
    let response: Result<String, String> = update(
        &ic,
        Principal::anonymous(),
        ic_sis_provider_canister,
        "sis_prepare_login",
        address,
    );
    assert_eq!(
        response.unwrap_err(),
        "Address format error: Must start with '0x' and be 66 characters long"
    );
}

#[test]
fn test_sis_prepare_login_too_short_address() {
    let ic = create_pocket_ic();
    let (ic_sis_provider_canister, _) = init(&ic, None);
    let address = encode_one("0x1234567890123456789012345678901234567890123456789012345678901").unwrap(); // 63 chars instead of 64
    let response: Result<String, String> = update(
        &ic,
        Principal::anonymous(),
        ic_sis_provider_canister,
        "sis_prepare_login",
        address,
    );
    assert_eq!(
        response.unwrap_err(),
        "Address format error: Must start with '0x' and be 66 characters long"
    );
}

#[test]
fn test_sis_prepare_login_ok() {
    let ic = create_pocket_ic();
    let (ic_sis_provider_canister, _) = init(&ic, None);
    let address = encode_one(VALID_ADDRESS).unwrap();
    let response: Result<PrepareLoginOkResponse, String> = update(
        &ic,
        Principal::anonymous(),
        ic_sis_provider_canister,
        "sis_prepare_login",
        address,
    );
    assert!(response.is_ok());
    let prepare_login_ok_response: PrepareLoginOkResponse = response.unwrap();
    
    let sis_message = &prepare_login_ok_response.sis_message;
    assert!(sis_message.contains(VALID_ADDRESS));
    assert!(sis_message.contains("127.0.0.1"));
    assert!(sis_message.contains("devnet"));
    assert!(!prepare_login_ok_response.nonce.is_empty());
}

#[test]
fn test_login_signature_too_short() {
    let ic = create_pocket_ic();
    let (ic_sis_provider_canister, _) = init(&ic, None);
    let signature = "0xTOO-SHORT";
    let args = encode_args((signature, VALID_ADDRESS, SESSION_KEY, NONCE)).unwrap();
    let response: Result<LoginDetails, String> = update(
        &ic,
        Principal::anonymous(),
        ic_sis_provider_canister,
        "sis_login",
        args,
    );
    assert!(response.is_err());
    assert!(response.unwrap_err().contains("Signature"));
}

#[test]
fn test_login_signature_invalid_format() {
    let ic = create_pocket_ic();
    let (ic_sis_provider_canister, _) = init(&ic, None);
    let signature = create_invalid_sui_signature();
    let args = encode_args((signature, VALID_ADDRESS, SESSION_KEY, NONCE)).unwrap();
    let response: Result<LoginDetails, String> = update(
        &ic,
        Principal::anonymous(),
        ic_sis_provider_canister,
        "sis_login",
        args,
    );
    assert!(response.is_err());
    match response {
        Ok(_) => panic!("Expected an error but got success"),
        Err(error_msg) => {
            assert!(
                error_msg.contains("Decoding error") || 
                error_msg.contains("Signature") ||
                error_msg.contains("Hash error") || // New in v0.2.0
                error_msg.contains("Invalid signature format"), // Enhanced error messages
                "Unexpected error message: {}",
                error_msg
            );
        }
    }
}

#[test]
fn test_sign_in_message_expired() {
    let ic = create_pocket_ic();
    let (ic_sis_provider_canister, _) = init(&ic, None);
    let (address, _) = create_mock_sui_wallet();
    let (mock_signature, _) =
        prepare_login_and_create_mock_signature(&ic, ic_sis_provider_canister, &address);

    ic.advance_time(Duration::from_secs(10));

    let args = encode_args((mock_signature, address, SESSION_KEY, NONCE)).unwrap();
    let response: Result<LoginDetails, String> = update(
        &ic,
        Principal::anonymous(),
        ic_sis_provider_canister,
        "sis_login",
        args,
    );
    let error_msg = response.unwrap_err();
    assert!(
        error_msg.contains("Message not found") || 
        error_msg.contains("Authentication session expired"),
        "Unexpected error message: {}",
        error_msg
    );
}

#[test]
fn test_prepare_login_structure() {
    let ic = create_pocket_ic();
    let (ic_sis_provider_canister, _) = init(&ic, None);
    let address = create_valid_sui_address();
    let args = encode_one(address.clone()).unwrap();
    let response: Result<PrepareLoginOkResponse, String> = update(
        &ic,
        Principal::anonymous(),
        ic_sis_provider_canister,
        "sis_prepare_login",
        args,
    );
    
    assert!(response.is_ok());
    let prepare_response = response.unwrap();
    
    assert!(!prepare_response.sis_message.is_empty());
    assert!(!prepare_response.nonce.is_empty());
    
    let sis_message = &prepare_response.sis_message;
    assert!(sis_message.contains(&address));
    assert!(sis_message.contains("Version: 1"));
    assert!(sis_message.contains("127.0.0.1"));
    assert!(sis_message.contains("devnet"));
    assert!(sis_message.contains("Login to the app"));
}

#[test]
fn test_bcs_serialization_integration() {
    let ic = create_pocket_ic();
    let (ic_sis_provider_canister, _) = init(&ic, None);
    let address = create_valid_sui_address();
    let args = encode_one(address.clone()).unwrap();
    let response: Result<PrepareLoginOkResponse, String> = update(
        &ic,
        Principal::anonymous(),
        ic_sis_provider_canister,
        "sis_prepare_login",
        args,
    );
    
    assert!(response.is_ok());
    let prepare_response = response.unwrap();
    
    let sis_message = &prepare_response.sis_message;
    
    assert!(sis_message.contains("Sign in with your Sui account"));
    assert!(sis_message.contains(&address));
    assert!(sis_message.contains("URI:"));
    assert!(sis_message.contains("Version:"));
    assert!(sis_message.contains("Network:"));
    assert!(sis_message.contains("Nonce:"));
    assert!(sis_message.contains("Issued At:"));
    assert!(sis_message.contains("Expiration Time:"));
}