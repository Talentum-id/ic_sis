#[cfg(not(test))]
pub(crate) fn generate_nonce() -> String {
    use crate::RNG;
    use rand_chacha::rand_core::RngCore;

    let mut buf = [0u8; 10];
    RNG.with_borrow_mut(|rng| rng.as_mut().unwrap().fill_bytes(&mut buf));

    hex::encode(buf)
}

#[cfg(test)]
pub(crate) fn generate_nonce() -> String {
    use rand::{thread_rng, Rng};

    let mut rng = thread_rng();
    let mut nonce = [0u8; 10];
    rng.fill(&mut nonce);
    hex::encode(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_nonce() {
        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();

        // Test length
        assert_eq!(nonce1.len(), 20); // 10 bytes = 20 hex chars
        assert_eq!(nonce2.len(), 20);

        // Test uniqueness
        assert_ne!(nonce1, nonce2);

        // Test hex format
        assert!(hex::decode(&nonce1).is_ok());
        assert!(hex::decode(&nonce2).is_ok());
    }
}