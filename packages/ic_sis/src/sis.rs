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
}

impl fmt::Display for SisMessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SisMessageError::MessageNotFound => write!(f, "Message not found"),
            SisMessageError::MessageCreationError(e) => write!(f, "Message creation error: {}", e),
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
                issued_at: get_current_time(),
                expiration_time: current_time.saturating_add(settings.sign_in_expires_in),
            }
        })
    }

    pub fn is_expired(&self) -> bool {
        let current_time = get_current_time();
        self.issued_at > current_time || current_time > self.expiration_time
    }

    pub fn to_sign_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }
    
    pub fn create_intent_message(&self) -> Vec<u8> {
        let message_bytes = self.to_sign_bytes();
        
        let intent_prefix: [u8; 3] = [0, 0, 0]; // This would be the actual intent prefix
        
        let mut intent_message = Vec::with_capacity(intent_prefix.len() + message_bytes.len());
        intent_message.extend_from_slice(&intent_prefix);
        intent_message.extend_from_slice(&message_bytes);
        
        let mut hasher = Blake2b::new();
        hasher.update(&intent_message);
        let hash = hasher.finalize();
        
        hash[..32].to_vec()
    }
}

impl fmt::Display for SisMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let json = serde_json::to_string(self).map_err(|_| fmt::Error)?;
        write!(f, "{}", json)
    }
}

impl From<SisMessage> for String {
    fn from(val: SisMessage) -> Self {
        let issued_at_datetime =
            OffsetDateTime::from_unix_timestamp_nanos(val.issued_at as i128).unwrap();
        let issued_at_iso_8601 = issued_at_datetime.format(&Rfc3339).unwrap();

        let expiration_datetime =
            OffsetDateTime::from_unix_timestamp_nanos(val.expiration_time as i128).unwrap();
        let expiration_iso_8601 = expiration_datetime.format(&Rfc3339).unwrap();

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
            domain = val.domain,
            address = val.address,
            statement = val.statement,
            uri = val.uri,
            version = val.version,
            network = val.network,
            nonce = val.nonce,
        )
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

    #[test]
    fn test_sis_message_creation() {
        let address = setup();
        let nonce = "test_nonce";
        
        let message = SisMessage::new(&address, nonce);
        
        assert_eq!(message.domain, "example.com");
        assert_eq!(message.address, address.as_str());
        assert_eq!(message.nonce, nonce);
        assert_eq!(message.network, "mainnet");
        assert_eq!(message.version, 1);
    }

    #[test]
    fn test_create_intent_message() {
        let address = setup();
        let nonce = "test_nonce";
        
        let message = SisMessage::new(&address, nonce);
        let intent_message = message.create_intent_message();

        assert_eq!(intent_message.len(), 32);
    }
}