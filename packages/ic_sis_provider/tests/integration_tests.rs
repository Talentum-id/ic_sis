mod common;

use candid::{encode_args, encode_one, Principal};
use common::{
    create_canister, create_session_identity, create_mock_sui_wallet, mock_full_login, init, query, update,
    valid_settings, PrepareLoginOkResponse, RuntimeFeature, NONCE, SESSION_KEY, VALID_ADDRESS,
    create_valid_sui_address, create_invalid_sui_signature, prepare_login_and_create_mock_signature,
};
use ic_agent::Identity;
use ic_sis::{login::LoginDetails, sis::SisMessage};
use pocket_ic::PocketIc;
use serde_bytes::ByteBuf;
use std::time::{Duration};

use crate::common::SettingsInput;

#[test]
#[should_panic]
fn test_init_with_no_settings() {
    let ic = PocketIc::new();
    let (canister_id, wasm_module) = common::create_canister(&ic);
    let sender = None;
    ic.install_canister(canister_id, wasm_module, encode_one(()).unwrap(), sender);
}

#[test]
fn test_init_with_valid_settings() {
    let ic = PocketIc::new();
    let (canister_id, wasm_module) = common::create_canister(&ic);
    let settings = valid_settings(canister_id, None);
    let arg = encode_one(settings).unwrap();
    let sender = None;
    ic.install_canister(canister_id, wasm_module, arg, sender);
}

#[test]
#[should_panic]
fn test_init_with_invalid_settings() {
    let ic = PocketIc::new();
    let (canister_id, wasm_module) = common::create_canister(&ic);
    let mut settings = valid_settings(canister_id, None);
    settings.domain = "invalid domain".to_string(); // Invalid domain, should cause a panic
    let arg = encode_one(settings).unwrap();
    let sender = None;
    ic.install_canister(canister_id, wasm_module, arg, sender);
}

#[test]
fn test_upgrade_with_changed_arguments() {
    let ic = PocketIc::new();

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
    let sender = None;
    let upgrade_result =
        ic.upgrade_canister(ic_sis_provider_canister, wasm_module, arg.clone(), sender);
    assert!(upgrade_result.is_ok());

    for _ in 0..5 {
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
    let sis_message: SisMessage = serde_json::from_str(&prepare_login_ok_response.sis_message).unwrap();
    assert_eq!(sis_message.domain, "192.168.0.1");
    assert_eq!(sis_message.uri, "http://192.168.0.1:666");
    assert_eq!(sis_message.network, "testnet");
    assert_eq!(
        sis_message.statement,
        "Some login statement"
    );
}

#[test]
fn test_upgrade_with_no_settings() {
    let ic = PocketIc::new();
    let (ic_sis_provider_canister, _) = init(&ic, None);
    let wasm_path: std::ffi::OsString =
        std::env::var_os("IC_SIS_PROVIDER_PATH").expect("Missing ic_sis_provider wasm file");
    let wasm_module = std::fs::read(wasm_path).unwrap();
    let sender = None;
    let result = ic.upgrade_canister(
        ic_sis_provider_canister,
        wasm_module,
        encode_one(()).unwrap(),
        sender,
    );
    assert!(result.is_err());
}

#[test]
fn test_sis_prepare_login_invalid_address() {
    let ic = PocketIc::new();
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
    let ic = PocketIc::new();
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
    let ic = PocketIc::new();
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
    let sis_message: SisMessage = serde_json::from_str(&prepare_login_ok_response.sis_message).unwrap();
    assert_eq!(sis_message.address, VALID_ADDRESS);
    assert!(!prepare_login_ok_response.nonce.is_empty());
}

#[test]
fn test_login_signature_too_short() {
    let ic = PocketIc::new();
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
    let ic = PocketIc::new();
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
                error_msg.contains("Decoding error") || error_msg.contains("Signature"),
                "Unexpected error message: {}",
                error_msg
            );
        }
    }
}

#[test]
fn test_sign_in_message_expired() {
    let ic = PocketIc::new();
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
    assert_eq!(response.unwrap_err(), "Message not found");
}

#[test]
fn test_sign_in_address_mismatch() {
    let ic = PocketIc::new();
    let (ic_sis_provider_canister, _) = init(&ic, None);
    let (address, _) = create_mock_sui_wallet();
    let (mock_signature, _) =
        prepare_login_and_create_mock_signature(&ic, ic_sis_provider_canister, &address);
    let different_address = create_valid_sui_address();
    let args = encode_args((mock_signature, different_address, SESSION_KEY, NONCE)).unwrap(); // Wrong address
    let response: Result<LoginDetails, String> = update(
        &ic,
        Principal::anonymous(),
        ic_sis_provider_canister,
        "sis_login",
        args,
    );
    assert_eq!(response.unwrap_err(), "Message not found");
}

#[test]
fn test_sign_in_signature_manipulated() {
    let ic = PocketIc::new();
    let (ic_sis_provider_canister, _) = init(&ic, None);
    let (address, _) = create_mock_sui_wallet();
    let (mock_signature, prepare_login_ok_response) =
        prepare_login_and_create_mock_signature(&ic, ic_sis_provider_canister, &address);
    let manipulated_signature = format!("{}0000000000", &mock_signature[..mock_signature.len() - 10]);
    let args = encode_args((
        manipulated_signature,
        address,
        SESSION_KEY,
        prepare_login_ok_response.nonce,
    ))
    .unwrap();
    let response: Result<LoginDetails, String> = update(
        &ic,
        Principal::anonymous(),
        ic_sis_provider_canister,
        "sis_login",
        args,
    );
    assert!(response.is_err());
    match response {
        Ok(_) => panic!("Expected signature verification to fail"),
        Err(error_msg) => {
            assert!(
                error_msg.contains("Signature verification failed") || 
                error_msg.contains("Invalid signature"),
                "Unexpected error message: {}",
                error_msg
            );
        }
    }
}

#[test]
fn test_sign_in_mock_scenario() {
    let ic = PocketIc::new();
    let (ic_sis_provider_canister, _) = init(&ic, None);
    let (address, mock_signature) = create_mock_sui_wallet();
    let (_, prepare_login_ok_response) =
        prepare_login_and_create_mock_signature(&ic, ic_sis_provider_canister, &address);
    let args = encode_args((
        mock_signature,
        address,
        SESSION_KEY,
        prepare_login_ok_response.nonce,
    ))
    .unwrap();
    let response: Result<LoginDetails, String> = update(
        &ic,
        Principal::anonymous(),
        ic_sis_provider_canister,
        "sis_login",
        args,
    );
    assert!(response.is_err());
    match response {
        Ok(_) => panic!("Expected signature verification to fail"),
        Err(error_msg) => {
            assert!(
                error_msg.contains("Signature verification failed") || 
                error_msg.contains("Invalid signature"),
                "Unexpected error message: {}",
                error_msg
            );
        }
    }
}

#[test]
fn test_sign_in_replay_attack() {
    let ic = PocketIc::new();
    let (ic_sis_provider_canister, _) = init(&ic, None);
    let (address, mock_signature) = create_mock_sui_wallet();
    let (_, prepare_login_ok_response) =
        prepare_login_and_create_mock_signature(&ic, ic_sis_provider_canister, &address);
    let args = encode_args((
        mock_signature,
        address,
        SESSION_KEY,
        prepare_login_ok_response.nonce,
    ))
    .unwrap();
    
    let response: Result<LoginDetails, String> = update(
        &ic,
        Principal::anonymous(),
        ic_sis_provider_canister,
        "sis_login",
        args.clone(),
    );
    assert!(response.is_err());
    
    let second_response: Result<LoginDetails, String> = update(
        &ic,
        Principal::anonymous(),
        ic_sis_provider_canister,
        "sis_login",
        args,
    );
    assert!(second_response.is_err());
}

#[test]
fn test_sign_in_sis_get_delegation_mock() {
    let ic = PocketIc::new();
    let (ic_sis_provider_canister, targets) = init(&ic, None);
    let (_, _) = mock_full_login(&ic, ic_sis_provider_canister, targets);
}

#[test]
fn test_sign_in_sis_get_delegation_timeout() {
    let ic = PocketIc::new();
    let (ic_sis_provider_canister, _) = init(&ic, None);

    let (address, mock_signature) = create_mock_sui_wallet();
    let (_, prepare_login_ok_response) =
        prepare_login_and_create_mock_signature(&ic, ic_sis_provider_canister, &address);
    let session_identity = create_session_identity();
    let session_pubkey = session_identity.public_key().unwrap();

    let login_args = encode_args((
        mock_signature,
        address.clone(),
        session_pubkey.clone(),
        prepare_login_ok_response.nonce.clone(),
    ))
    .unwrap();
    let _: Result<LoginDetails, String> = update(
        &ic,
        Principal::anonymous(),
        ic_sis_provider_canister,
        "sis_login",
        login_args,
    );

    ic.advance_time(Duration::from_secs(100));
}

#[test]
fn test_get_caller_address_principal_not_logged_in() {
    let ic = PocketIc::new();
    let (ic_sis_provider_canister, targets) = init(&ic, None);
    let (_, _) = mock_full_login(&ic, ic_sis_provider_canister, targets);
    let response: Result<String, String> = query(
        &ic,
        Principal::anonymous(),
        ic_sis_provider_canister,
        "get_caller_address",
        encode_one(()).unwrap(),
    );
    assert!(response.is_err());
    assert_eq!(
        response.unwrap_err(),
        "No address found for the given principal"
    );
}

#[test]
fn test_get_address_not_found() {
    let ic = PocketIc::new();
    let (ic_sis_provider_canister, targets) = init(&ic, None);
    let (_, _) = mock_full_login(&ic, ic_sis_provider_canister, targets);
    let response: Result<String, String> = query(
        &ic,
        Principal::anonymous(),
        ic_sis_provider_canister,
        "get_address",
        encode_one(Principal::anonymous().as_slice()).unwrap(),
    );
    assert!(response.is_err());
    assert_eq!(
        response.unwrap_err(),
        "No address found for the given principal"
    );
}

#[test]
fn test_get_principal_not_found() {
    let ic = PocketIc::new();
    let (ic_sis_provider_canister, targets) = init(&ic, None);
    let (_, _) = mock_full_login(&ic, ic_sis_provider_canister, targets);
    let response: Result<ByteBuf, String> = query(
        &ic,
        Principal::anonymous(),
        ic_sis_provider_canister,
        "get_principal",
        encode_one(VALID_ADDRESS).unwrap(),
    );
    assert!(response.is_err());
    assert_eq!(
        response.unwrap_err(),
        "No principal found for the given address"
    );
}

pub fn settings_disable_sui_and_principal_mapping(
    canister_id: Principal,
    targets: Option<Vec<Principal>>,
) -> SettingsInput {
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
        runtime_features: Some(vec![
            RuntimeFeature::DisableSuiToPrincipalMapping,
            RuntimeFeature::DisablePrincipalToSuiMapping,
        ]),
    }
}

pub fn init_disable_sui_and_principal_mapping(
    ic: &PocketIc,
    targets: Option<Vec<Principal>>,
) -> (Principal, Option<Vec<Principal>>) {
    let (canister_id, wasm_module) = create_canister(ic);
    let settings = settings_disable_sui_and_principal_mapping(canister_id, targets.clone());
    let arg = encode_one(settings).unwrap();
    let sender = None;

    ic.install_canister(canister_id, wasm_module, arg.clone(), sender);

    for _ in 0..5 {
        ic.tick();
    }

    (canister_id, targets)
}

#[test]
fn test_sui_to_principal_mapping_disabled() {
    let ic = PocketIc::new();
    let (ic_sis_provider_canister, targets) = init_disable_sui_and_principal_mapping(&ic, None);
    let (_, _) = mock_full_login(&ic, ic_sis_provider_canister, targets);
    let response: Result<ByteBuf, String> = query(
        &ic,
        Principal::anonymous(),
        ic_sis_provider_canister,
        "get_principal",
        encode_one(VALID_ADDRESS).unwrap(),
    );
    assert!(response.is_err());
    assert_eq!(
        response.unwrap_err(),
        "Sui address to principal mapping is disabled"
    );
}

#[test]
fn test_principal_to_sui_mapping_disabled() {
    let ic = PocketIc::new();
    let (ic_sis_provider_canister, targets) = init_disable_sui_and_principal_mapping(&ic, None);
    let (_, mock_delegated_identity) = mock_full_login(&ic, ic_sis_provider_canister, targets);
    let response: Result<String, String> = query(
        &ic,
        mock_delegated_identity.sender().unwrap(),
        ic_sis_provider_canister,
        "get_address",
        encode_one(mock_delegated_identity.sender().unwrap().as_slice()).unwrap(),
    );
    assert!(response.is_err());
    assert_eq!(
        response.unwrap_err(),
        "Principal to Sui address mapping is disabled"
    );
}

#[test]
#[should_panic(expected = "Unknown Sui network")]
fn test_network_validation() {
    let ic = PocketIc::new();
    let (canister_id, wasm_module) = create_canister(&ic);
    let mut settings = valid_settings(canister_id, None);
    settings.network = Some("invalid_network".to_string());
    let arg = encode_one(settings).unwrap();
    let sender = None;
    
    ic.install_canister(canister_id, wasm_module, arg, sender);
}

#[test]
fn test_valid_networks() {
    let ic = PocketIc::new();
    let valid_networks = vec!["mainnet", "testnet", "devnet", "localnet"];
    
    for network in valid_networks {
        let (canister_id, wasm_module) = create_canister(&ic);
        let mut settings = valid_settings(canister_id, None);
        settings.network = Some(network.to_string());
        let arg = encode_one(settings).unwrap();
        let sender = None;
        
        // This should succeed
        ic.install_canister(canister_id, wasm_module, arg, sender);
        
        // Fast forward to complete installation
        for _ in 0..5 {
            ic.tick();
        }
    }
}

#[test]
fn test_prepare_login_structure() {
    let ic = PocketIc::new();
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
    
    let sis_message: Result<SisMessage, _> = serde_json::from_str(&prepare_response.sis_message);
    assert!(sis_message.is_ok());
    
    let message = sis_message.unwrap();
    assert_eq!(message.address, address);
    assert_eq!(message.version, 1);
    assert_eq!(message.domain, "127.0.0.1");
    assert_eq!(message.network, "devnet");
}