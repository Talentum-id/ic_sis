use ic_sis::{
    settings::SettingsBuilder,
    sui::{SuiAddress, derive_sui_address_from_public_key, SUI_SIGNATURE_SCHEME_FLAG_ED25519, 
         create_auth_intent_hash, INTENT_PREFIX_AUTH},
};

fn create_test_sis_message(address: &ic_sis::sui::SuiAddress, nonce: &str) -> ic_sis::sis::SisMessage {
    use ic_sis::sis::SisMessage;
    
    SisMessage {
        scheme: "https".to_string(),
        domain: "example.com".to_string(),
        address: address.as_str().to_string(),
        statement: "Sign in with Sui".to_string(),
        uri: "http://example.com".to_string(),
        version: 1,
        network: "mainnet".to_string(),
        nonce: nonce.to_string(),
        issued_at: 1000000000, // Mock timestamp
        expiration_time: 1000000000 + (5 * 60 * 1_000_000_000), // Mock expiration
    }
}

#[test]
fn test_settings_creation() {
    let builder = SettingsBuilder::new(
        "example.com", 
        "http://example.com", 
        "test_salt"
    ).network("mainnet");
    
    let settings = builder.build();
    assert!(settings.is_ok());
    
    let settings = settings.unwrap();
    assert_eq!(settings.domain, "example.com");
    assert_eq!(settings.network, "mainnet");
}

#[test]
fn test_sui_address_validation() {
    let valid_address = "0x".to_owned() + &"a".repeat(64);
    let address = SuiAddress::new(&valid_address);
    assert!(address.is_ok());
    
    let invalid_address = "0x".to_owned() + &"a".repeat(63);
    let address = SuiAddress::new(&invalid_address);
    assert!(address.is_err());
}

#[test]
fn test_derive_address() {
    let pub_key = [1u8; 32];
    let result = derive_sui_address_from_public_key(
        SUI_SIGNATURE_SCHEME_FLAG_ED25519, 
        &pub_key
    );
    assert!(result.is_ok());
    let address = result.unwrap();
    assert!(address.starts_with("0x"));
    assert_eq!(address.len(), 66); // "0x" + 64 hex chars
}

#[test]
fn test_intent_prefix_constants() {
    assert_eq!(INTENT_PREFIX_AUTH, [3, 0, 0]);
}

#[test]
fn test_create_auth_intent_hash() {
    let message = b"test authentication message";
    let result = create_auth_intent_hash(message);
    assert!(result.is_ok());
    
    let hash = result.unwrap();
    assert_eq!(hash.len(), 32); // Should be 32 bytes
}

#[test]
fn test_bcs_serialization() {
    let address_str = "0x".to_owned() + &"a".repeat(64);
    let address = SuiAddress::new(&address_str).unwrap();
    let nonce = "test_nonce";
    
    let message = create_test_sis_message(&address, nonce);
    
    let bcs_bytes = message.to_sign_bytes();
    assert!(!bcs_bytes.is_empty());
    
    let validation_result = message.validate_bcs_serialization();
    assert!(validation_result.is_ok(), "BCS serialization validation failed: {:?}", validation_result);
    
    println!("BCS serialized message length: {} bytes", bcs_bytes.len());
    println!("BCS hex: {}", hex::encode(&bcs_bytes[..std::cmp::min(32, bcs_bytes.len())]));
}

#[test]
fn test_bcs_deterministic() {
    let address_str = "0x".to_owned() + &"a".repeat(64);
    let address = SuiAddress::new(&address_str).unwrap();
    let nonce = "test_nonce";
    
    let message = create_test_sis_message(&address, nonce);
    
    let bytes1 = message.to_sign_bytes();
    let bytes2 = message.to_sign_bytes();
    assert_eq!(bytes1, bytes2, "BCS serialization should be deterministic");
}

#[test]
fn test_sis_message_intent_creation() {
    let address_str = "0x".to_owned() + &"a".repeat(64);
    let address = SuiAddress::new(&address_str).unwrap();
    let nonce = "test_nonce";
    
    let message = create_test_sis_message(&address, nonce);
    let intent_hash = message.create_intent_message();
    
    assert_eq!(intent_hash.len(), 32);
    
    let intent_hash2 = message.create_intent_message();
    assert_eq!(intent_hash, intent_hash2);
    
    println!("Intent hash: {}", hex::encode(&intent_hash));
}

#[test]
fn test_human_readable_message() {
    let address_str = "0x".to_owned() + &"a".repeat(64);
    let address = SuiAddress::new(&address_str).unwrap();
    let nonce = "test_nonce_123";
    
    let message = create_test_sis_message(&address, nonce);
    let human_readable = message.to_human_readable();
    
    assert!(human_readable.contains("example.com"));
    assert!(human_readable.contains(&address_str));
    assert!(human_readable.contains("Sign in with Sui"));
    assert!(human_readable.contains("mainnet"));
    assert!(human_readable.contains(nonce));
    assert!(human_readable.contains("URI: http://example.com"));
    assert!(human_readable.contains("Version: 1"));
}

#[test]
fn test_bcs_vs_json_comparison() {
    let address_str = "0x".to_owned() + &"a".repeat(64);
    let address = SuiAddress::new(&address_str).unwrap();
    let nonce = "test_nonce";
    
    let message = create_test_sis_message(&address, nonce);
    
    let bcs_bytes = message.to_sign_bytes();
    
    let json_result = message.to_json_bytes();
    assert!(json_result.is_ok(), "JSON serialization should work");
    let json_bytes = json_result.unwrap();
    
    assert!(!bcs_bytes.is_empty(), "BCS bytes should not be empty");
    assert!(!json_bytes.is_empty(), "JSON bytes should not be empty");
    
    assert!(bcs_bytes.len() < json_bytes.len(), "BCS should be more compact than JSON");
    
    println!("BCS size: {} bytes", bcs_bytes.len());
    println!("JSON size: {} bytes", json_bytes.len());
    println!("Compression ratio: {:.2}%", (bcs_bytes.len() as f64 / json_bytes.len() as f64) * 100.0);
}

#[test]
fn test_intent_message_with_bcs() {
    let address_str = "0x".to_owned() + &"a".repeat(64);
    let address = SuiAddress::new(&address_str).unwrap();
    let nonce = "test_nonce";
    
    let message = create_test_sis_message(&address, nonce);
    
    let intent_hash1 = message.create_intent_message();
    
    let message2 = create_test_sis_message(&address, nonce);
    let intent_hash2 = message2.create_intent_message();
    
    assert_eq!(intent_hash1, intent_hash2, "Intent hashes should be deterministic");
    
    // Should be exactly 32 bytes
    assert_eq!(intent_hash1.len(), 32, "Intent hash should be 32 bytes");
}