use ic_certified_map::Hash;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::convert::AsRef;

#[derive(Clone, Serialize, Deserialize)]
pub enum Value<'a> {
    Bytes(#[serde(with = "serde_bytes")] &'a [u8]),
    String(&'a str),
    U64(u64),
    Array(Vec<Value<'a>>),
}

pub(crate) fn hash_of_map<S: AsRef<str>>(map: HashMap<S, Value>) -> Hash {
    let mut hashes = map
        .into_iter()
        .map(|(key, val)| hash_key_value(key.as_ref(), val))
        .collect::<Vec<_>>();

    hashes.sort_unstable();
    let mut hasher = Sha256::new();
    for hash in hashes {
        hasher.update(&hash);
    }

    hasher.finalize().into()
}

pub(crate) fn hash_with_domain(sep: &[u8], bytes: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([sep.len() as u8]);
    hasher.update(sep);
    hasher.update(bytes);
    hasher.finalize().into()
}

fn hash_key_value(key: &str, val: Value<'_>) -> Vec<u8> {
    let mut key_hash = hash_string(key).to_vec();
    let val_hash = hash_value(val);
    key_hash.extend_from_slice(&val_hash[..]);
    key_hash
}

pub(crate) fn hash_string(value: &str) -> Hash {
    hash_bytes(value.as_bytes())
}

pub(crate) fn hash_bytes(value: impl AsRef<[u8]>) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(value.as_ref());
    hasher.finalize().into()
}

fn hash_u64(value: u64) -> Hash {
    let mut buf = [0u8; 10];
    let mut n = value;
    let mut i = 0;

    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        buf[i] = byte | if n != 0 { 0x80 } else { 0 };

        if n == 0 {
            break;
        }
        i += 1;
    }

    hash_bytes(&buf[..=i])
}

fn hash_array(elements: Vec<Value<'_>>) -> Hash {
    let mut hasher = Sha256::new();
    for element in elements {
        hasher.update(&hash_value(element)[..]);
    }
    hasher.finalize().into()
}

fn hash_value(val: Value<'_>) -> Hash {
    match val {
        Value::String(s) => hash_string(s),
        Value::Bytes(b) => hash_bytes(b),
        Value::U64(n) => hash_u64(n),
        Value::Array(a) => hash_array(a),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use std::collections::HashMap;

    #[test]
    fn test_hash_string() {
        let result = hash_string("test");
        assert_eq!(
            result.as_ref(),
            hex!("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
        );
    }

    #[test]
    fn test_hash_bytes() {
        let result = hash_bytes(b"test");
        assert_eq!(
            result.as_ref(),
            hex!("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
        );
    }

    #[test]
    fn test_hash_u64() {
        assert_eq!(
            hash_u64(0),
            hex!("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d").into()
        );
        assert_eq!(
            hash_u64(1234),
            hex!("8b37fd3ebbe6396a89ed8563dd0cc55927ac90138950460c77cffeb55cf63810").into()
        );
    }

    #[test]
    fn test_hash_array() {
        let arr = vec![Value::String("test")];
        let result = hash_array(arr);
        assert_ne!(result, Hash::default());
    }

    #[test]
    fn test_hash_of_map() {
        let mut map = HashMap::new();
        map.insert("key", Value::String("value"));
        let result = hash_of_map(map);
        assert_ne!(result, Hash::default());
    }

    #[test]
    fn test_hash_with_domain() {
        let result = hash_with_domain(b"domain", b"value");
        assert_ne!(result, Hash::default());
    }
}