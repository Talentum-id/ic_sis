use ic_sis::{
    settings::SettingsBuilder,
    sui::{SuiAddress, derive_sui_address_from_public_key, SUI_SIGNATURE_SCHEME_FLAG_ED25519},
};

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
    // Create a sample Ed25519 public key (32 bytes)
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