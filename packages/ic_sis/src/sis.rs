use crate::sui::SuiAddress;
use crate::settings::Settings;
use crate::time::get_current_time;
use crate::{hash, with_settings};
use candid::{CandidType, Deserialize};
use ic_certified_map::Hash;
use serde::Serialize;
use std::collections::HashMap;
use std::fmt;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use blake2::{Blake2b, Digest};

#[derive(Debug)]
pub enum SisMessageError {
    MessageNotFound,
    MessageCreationError(String),
    SerializationError(String),
}

impl fmt::Display for SisMessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SisMessageError::MessageNotFound => write!(f, "Message not found"),
            SisMessageError::MessageCreationError(e) => write!(f, "Message creation error: {}", e),
            SisMessageError::SerializationError(e) => write!(f, "Serialization error: {}", e),
        }
    }
}

impl From<SisMessageError> for String {
    fn from(error: SisMessageError) -> Self {
        error.to_string()
    }
}

#[derive(CandidType, Deserialize, Serialize, Clone, Debug)]
pub struct SisMessage {
    pub scheme: String,
    pub domain: String,
    pub address: String,
    pub statement: String,
    pub uri: String,
    pub version: u8,
    pub network: String,
    pub nonce: String,
    pub issued_at: u64,
    pub expiration_time: u64,
}

/// BCS-compatible version of SisMessage for serialization
/// This ensures proper ordering and formatting for SUI compatibility
#[derive(Serialize, Clone, Debug)]
struct BcsSisMessage {
    address: String,
    domain: String,
    expiration_time: u64,
    issued_at: u64,
    network: String,
    nonce: String,
    scheme: String,
    statement: String,
    uri: String,
    version: u8,
}

impl From<&SisMessage> for BcsSisMessage {
    fn from(msg: &SisMessage) -> Self {
        BcsSisMessage {
            address: msg.address.clone(),
            domain: msg.domain.clone(),
            expiration_time: msg.expiration_time,
            issued_at: msg.issued_at,
            network: msg.network.clone(),
            nonce: msg.nonce.clone(),
            scheme: msg.scheme.clone(),
            statement: msg.statement.clone(),
            uri: msg.uri.clone(),
            version: msg.version,
        }
    }
}

impl SisMessage {
    pub fn new(address: &SuiAddress, nonce: &str) -> SisMessage {
        let current_time = get_current_time();
        with_settings!(|settings: &Settings| {
            SisMessage {
                scheme: settings.scheme.clone(),
                domain: settings.domain.clone(),
                address: address.as_str().to_string(),
                statement: settings.statement.clone(),
                uri: settings.uri.clone(),
                version: 1,
                network: settings.network.clone(),
                nonce: nonce.to_string(),
                issued_at: current_time,
                expiration_time: current_time.saturating_add(settings.sign_in_expires_in),
            }
        })
    }

    pub fn is_expired(&self) -> bool {
        let current_time = get_current_time();
        self.issued_at > current_time || current_time > self.expiration_time
    }

    pub fn to_sign_bytes(&self) -> Vec<u8> {
        let bcs_message = BcsSisMessage::from(self);
        match bcs::to_bytes(&bcs_message) {
            Ok(bytes) => bytes,
            Err(e) => {
                // Fallback to JSON if BCS fails (for debugging/development)
                eprintln!("BCS serialization failed: {}, falling back to JSON", e);
                serde_json::to_vec(self).unwrap_or_default()
            }
        }
    }

    pub fn to_json_bytes(&self) -> Result<Vec<u8>, SisMessageError> {
        serde_json::to_vec(self)
            .map_err(|e| SisMessageError::SerializationError(e.to_string()))
    }

    pub fn validate_bcs_serialization(&self) -> Result<(), SisMessageError> {
        let bcs_message = BcsSisMessage::from(self);
        bcs::to_bytes(&bcs_message)
            .map_err(|e| SisMessageError::SerializationError(format!("BCS serialization failed: {}", e)))
            .map(|_| ())
    }
    
    pub fn create_intent_message(&self) -> Vec<u8> {
        let message_bytes = self.to_human_readable().into_bytes();
        let intent_prefix = crate::sui::INTENT_PREFIX_AUTH;
        
        let mut intent_message = Vec::with_capacity(intent_prefix.len() + message_bytes.len());
        intent_message.extend_from_slice(&intent_prefix);
        intent_message.extend_from_slice(&message_bytes);
        
        let mut hasher = Blake2b::new();
        hasher.update(&intent_message);
        let hash = hasher.finalize();
        
        hash[..32].to_vec()
    }

    pub fn to_human_readable(&self) -> String {
        let issued_at_datetime =
            OffsetDateTime::from_unix_timestamp_nanos(self.issued_at as i128)
                .unwrap_or_else(|_| OffsetDateTime::now_utc());
        let issued_at_iso_8601 = issued_at_datetime.format(&Rfc3339)
            .unwrap_or_else(|_| "Invalid timestamp".to_string());

        let expiration_datetime =
            OffsetDateTime::from_unix_timestamp_nanos(self.expiration_time as i128)
                .unwrap_or_else(|_| OffsetDateTime::now_utc());
        let expiration_iso_8601 = expiration_datetime.format(&Rfc3339)
            .unwrap_or_else(|_| "Invalid timestamp".to_string());

        format!(
            "{domain} wants you to sign in with your Sui account:\n\
            {address}\n\n\
            {statement}\n\n\
            URI: {uri}\n\
            Version: {version}\n\
            Network: {network}\n\
            Nonce: {nonce}\n\
            Issued At: {issued_at_iso_8601}\n\
            Expiration Time: {expiration_iso_8601}",
            domain = self.domain,
            address = self.address,
            statement = self.statement,
            uri = self.uri,
            version = self.version,
            network = self.network,
            nonce = self.nonce,
        )
    }

    /// Compare BCS vs JSON serialization for debugging
    #[cfg(test)]
    pub fn compare_serializations(&self) -> (Vec<u8>, Vec<u8>) {
        let bcs_bytes = self.to_sign_bytes();
        let json_bytes = self.to_json_bytes().unwrap_or_default();
        (bcs_bytes, json_bytes)
    }
}

impl fmt::Display for SisMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_human_readable())
    }
}

impl From<SisMessage> for String {
    fn from(val: SisMessage) -> Self {
        val.to_human_readable()
    }
}

pub fn sis_message_map_hash(address: &SuiAddress, nonce: &str) -> Hash {
    let mut bytes: Vec<u8> = vec![];

    let address_bytes = address.as_str().as_bytes();
    bytes.push(address_bytes.len() as u8);
    bytes.extend(address_bytes);

    let nonce_bytes = nonce.as_bytes();
    bytes.push(nonce_bytes.len() as u8);
    bytes.extend(nonce_bytes);

    hash::hash_bytes(bytes)
}

pub struct SisMessageMap {
    map: HashMap<[u8; 32], SisMessage>,
}

impl SisMessageMap {
    pub fn new() -> SisMessageMap {
        SisMessageMap {
            map: HashMap::new(),
        }
    }

    pub fn prune_expired(&mut self) {
        let current_time = get_current_time();
        self.map
            .retain(|_, message| message.expiration_time > current_time);
    }

    pub fn insert(&mut self, message: SisMessage, address: &SuiAddress, nonce: &str) {
        let hash = sis_message_map_hash(address, nonce);
        self.map.insert(hash, message);
    }

    pub fn get(&self, address: &SuiAddress, nonce: &str) -> Result<SisMessage, SisMessageError> {
        let hash = sis_message_map_hash(address, nonce);
        self.map
            .get(&hash)
            .cloned()
            .ok_or(SisMessageError::MessageNotFound)
    }

    pub fn remove(&mut self, address: &SuiAddress, nonce: &str) {
        let hash = sis_message_map_hash(address, nonce);
        self.map.remove(&hash);
    }

    pub fn count(&self) -> usize {
        self.map.len()
    }

    pub fn clear(&mut self) -> usize {
        let count = self.map.len();
        self.map.clear();
        count
    }
}

impl Default for SisMessageMap {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::SettingsBuilder;
    use crate::SETTINGS;

    fn setup() -> SuiAddress {
        let builder = SettingsBuilder::new("example.com", "http://example.com", "test_salt")
            .network("mainnet");
        let settings = builder.build().unwrap();
        SETTINGS.with(|s| s.borrow_mut().replace(settings));

        let address = "0x".to_owned() + &"a".repeat(64).as_str();
        
        SuiAddress::new(&address).unwrap()
    }

    fn create_test_message(address: &SuiAddress, nonce: &str) -> SisMessage {
        SisMessage {
            scheme: "https".to_string(),
            domain: "example.com".to_string(),
            address: address.as_str().to_string(),
            statement: "Sign in with Sui".to_string(),
            uri: "http://example.com".to_string(),
            version: 1,
            network: "mainnet".to_string(),
            nonce: nonce.to_string(),
            issued_at: 1000000000,
            expiration_time: 1000000000 + (5 * 60 * 1_000_000_000),
        }
    }

    #[test]
    fn test_bcs_serialization() {
        let address = setup();
        let nonce = "test_nonce";
        
        let message = create_test_message(&address, nonce);
        
        let bcs_bytes = message.to_sign_bytes();
        assert!(!bcs_bytes.is_empty());
        
        let validation_result = message.validate_bcs_serialization();
        assert!(validation_result.is_ok());
    }

    #[test]
    fn test_bcs_vs_json_serialization() {
        let address = setup();
        let nonce = "test_nonce";
        
        let message = create_test_message(&address, nonce);
        let (bcs_bytes, json_bytes) = message.compare_serializations();
        
        assert!(!bcs_bytes.is_empty());
        assert!(!json_bytes.is_empty());
        
        assert!(bcs_bytes.len() < json_bytes.len());
        
        println!("BCS size: {} bytes", bcs_bytes.len());
        println!("JSON size: {} bytes", json_bytes.len());
        println!("BCS hex: {}", hex::encode(&bcs_bytes));
    }

    #[test]
    fn test_bcs_deterministic() {
        let address = setup();
        let nonce = "test_nonce";
        
        let message = create_test_message(&address, nonce);
        
        let bytes1 = message.to_sign_bytes();
        let bytes2 = message.to_sign_bytes();
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn test_create_intent_message_with_bcs() {
        let address = setup();
        let nonce = "test_nonce";
        
        let message = create_test_message(&address, nonce);
        let intent_hash = message.create_intent_message();

        assert_eq!(intent_hash.len(), 32);
        
        let intent_hash2 = message.create_intent_message();
        assert_eq!(intent_hash, intent_hash2);
    }

    #[test]
    fn test_bcs_message_field_order() {
        let address = setup();
        let nonce = "test_nonce";
        
        let message = create_test_message(&address, nonce);
        let bcs_message = BcsSisMessage::from(&message);
        
        assert_eq!(bcs_message.address, message.address);
        assert_eq!(bcs_message.domain, message.domain);
        assert_eq!(bcs_message.nonce, message.nonce);
        assert_eq!(bcs_message.version, message.version);
    }

    #[test]
    fn test_sis_message_map() {
        let address = setup();
        let nonce = "test_nonce";
        let message = create_test_message(&address, nonce);
        
        let mut map = SisMessageMap::new();
        map.insert(message.clone(), &address, nonce);
        
        let retrieved = map.get(&address, nonce);
        assert!(retrieved.is_ok());
        assert_eq!(retrieved.unwrap().nonce, nonce);
        
        map.remove(&address, nonce);
        let retrieved = map.get(&address, nonce);
        assert!(retrieved.is_err());
    }
}