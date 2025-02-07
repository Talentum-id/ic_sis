use crate::hash;
use crate::sui::SuiAddress;
use crate::settings::Settings;
use crate::time::get_current_time;
use crate::with_settings;
use candid::CandidType;
use ic_certified_map::Hash;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

const PERSONAL_MESSAGE_PREFIX: &[u8] = b"\x19Sui Signed Message:\n";

#[derive(Debug)]
pub enum SisMessageError {
    MessageNotFound,
    MessageExpired,
}

impl fmt::Display for SisMessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SisMessageError::MessageNotFound => write!(f, "Message not found"),
            SisMessageError::MessageExpired => write!(f, "Message has expired"),
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
    pub nonce: String,
    pub issued_at: u64,
    pub expiration_time: u64,
    pub chain: String,
}

impl SisMessage {
    pub fn new(address: &SuiAddress, nonce: &str) -> SisMessage {
        let current_time = get_current_time();
        with_settings!(|settings: &Settings| {
            SisMessage {
                scheme: settings.scheme.clone(),
                domain: settings.domain.clone(),
                address: address.to_string(),
                statement: settings.statement.clone(),
                uri: settings.uri.clone(),
                version: 1,
                nonce: nonce.to_string(),
                issued_at: current_time,
                expiration_time: current_time.saturating_add(settings.sign_in_expires_in),
                chain: "sui".to_string(),
            }
        })
    }

    pub fn is_expired(&self) -> bool {
        let current_time = get_current_time();
        self.issued_at < current_time || current_time > self.expiration_time
    }

    pub fn get_signing_message(&self) -> Vec<u8> {
        let message = self.to_string();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(PERSONAL_MESSAGE_PREFIX);
        bytes.extend_from_slice(message.len().to_string().as_bytes());
        bytes.extend_from_slice(message.as_bytes());
        bytes
    }
}

impl ToString for SisMessage {
    fn to_string(&self) -> String {
        let issued_at_datetime =
            OffsetDateTime::from_unix_timestamp_nanos(self.issued_at as i128).unwrap();
        let issued_at_iso_8601 = issued_at_datetime.format(&Rfc3339).unwrap();

        let expiration_datetime =
            OffsetDateTime::from_unix_timestamp_nanos(self.expiration_time as i128).unwrap();
        let expiration_iso_8601 = expiration_datetime.format(&Rfc3339).unwrap();

        format!(
            "{domain} wants you to sign in with your Sui account:\n\
            {address}\n\n\
            {statement}\n\n\
            URI: {uri}\n\
            Version: {version}\n\
            Chain: {chain}\n\
            Nonce: {nonce}\n\
            Issued At: {issued_at_iso_8601}\n\
            Expiration Time: {expiration_iso_8601}",
            domain = self.domain,
            address = self.address,
            statement = self.statement,
            uri = self.uri,
            version = self.version,
            chain = self.chain,
            nonce = self.nonce,
        )
    }
}

pub fn sis_message_map_hash(address: &SuiAddress, nonce: &str) -> Hash {
    let mut bytes: Vec<u8> = vec![];

    let address_bytes = address.as_bytes();
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
        self.map.retain(|_, message| !message.is_expired());
    }

    pub fn insert(&mut self, message: SisMessage, address: &SuiAddress, nonce: &str) {
        let hash = sis_message_map_hash(address, nonce);
        self.map.insert(hash.into(), message);
    }

    pub fn get(&self, address: &SuiAddress, nonce: &str) -> Result<SisMessage, SisMessageError> {
        let hash = sis_message_map_hash(address, nonce);
        let message = self.map
            .get(&hash.into())
            .cloned()
            .ok_or(SisMessageError::MessageNotFound)?;

        if message.is_expired() {
            return Err(SisMessageError::MessageExpired);
        }

        Ok(message)
    }

    pub fn remove(&mut self, address: &SuiAddress, nonce: &str) {
        let hash = sis_message_map_hash(address, nonce);
        self.map.remove(&hash.into());
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
    use std::thread::sleep;
    use std::time::Duration;

    #[test]
    fn test_sis_message_creation() {
        let address = SuiAddress::new(
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        ).unwrap();
        let nonce = "test_nonce";
        let message = SisMessage::new(&address, nonce);

        assert_eq!(message.nonce, nonce);
        assert_eq!(message.address, address.to_string());
        assert_eq!(message.chain, "sui");
        assert_eq!(message.version, 1);
    }

    #[test]
    fn test_message_expiration() {
        let address = SuiAddress::new(
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        ).unwrap();
        let nonce = "test_nonce";
        let mut map = SisMessageMap::new();
        let message = SisMessage::new(&address, nonce);

        map.insert(message, &address, nonce);
        assert!(map.get(&address, nonce).is_ok());

        // Wait for message to expire
        sleep(Duration::from_secs(1));

        map.prune_expired();
        let result = map.get(&address, nonce);
        assert!(result.is_err());
        match result {
            Err(SisMessageError::MessageExpired) => (),
            _ => panic!("Expected MessageExpired error"),
        }
    }

    #[test]
    fn test_signing_message_format() {
        let address = SuiAddress::new(
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        ).unwrap();
        let nonce = "test_nonce";
        let message = SisMessage::new(&address, nonce);

        let signing_message = message.get_signing_message();
        assert!(signing_message.starts_with(PERSONAL_MESSAGE_PREFIX));

        let message_string = String::from_utf8(signing_message[PERSONAL_MESSAGE_PREFIX.len()..].to_vec()).unwrap();
        assert!(message_string.contains(&address.to_string()));
        assert!(message_string.contains(nonce));
    }
}