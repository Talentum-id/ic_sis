#[cfg(any(test, feature = "test-mode"))]
pub(crate) fn generate_nonce() -> String {
    use rand::{thread_rng, Rng};

    let mut rng = thread_rng();
    let mut nonce = [0u8; 10];
    rng.fill(&mut nonce);
    hex::encode(nonce)
}

#[cfg(not(any(test, feature = "test-mode")))]
pub(crate) fn generate_nonce() -> String {
    use crate::RNG;
    use rand_chacha::rand_core::RngCore;

    let mut buf = [0u8; 10];
    RNG.with_borrow_mut(|rng| rng.as_mut().unwrap().fill_bytes(&mut buf));

    hex::encode(buf)
}