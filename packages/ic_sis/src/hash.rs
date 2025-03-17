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

    #[test]
    fn message_id_string_reference_1() {
        assert_eq!(
            hash_string("request_type"),
            hex!("769e6f87bdda39c859642b74ce9763cdd37cb1cd672733e8c54efaa33ab78af9"),
        );
    }

    #[test]
    fn message_id_string_reference_2() {
        assert_eq!(
            hash_string("call"),
            hex!("7edb360f06acaef2cc80dba16cf563f199d347db4443da04da0c8173e3f9e4ed"),
        );
    }

    #[test]
    fn message_id_bytes_reference() {
        assert_eq!(
            hash_bytes(&[68, 73, 68, 76, 0, 253, 42][..]),
            hex!("6c0b2ae49718f6995c02ac5700c9c789d7b7862a0d53e6d40a73f1fcd2f70189")
        );
    }
}