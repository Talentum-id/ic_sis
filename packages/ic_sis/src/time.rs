#[cfg(any(test, feature = "test-mode"))]
pub(crate) fn get_current_time() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    let start = SystemTime::now();
    start.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64
}

#[cfg(not(any(test, feature = "test-mode")))]
pub(crate) fn get_current_time() -> u64 {
    ic_cdk::api::time()
}