use crate::{settings::Settings, SETTINGS};

pub fn init(settings: Settings) -> Result<(), String> {
    SETTINGS.set(Some(settings));
    init_rng();
    Ok(())
}

fn init_rng() {
    use crate::RNG;
    use candid::Principal;
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
    use std::time::Duration;
    
    ic_cdk_timers::set_timer(Duration::ZERO, || {
        ic_cdk::spawn(async {
            let (seed,): ([u8; 32],) = ic_cdk::call(
                Principal::management_canister(), 
                "raw_rand", 
                ()
            ).await.unwrap();
            RNG.with_borrow_mut(|rng| *rng = Some(ChaCha20Rng::from_seed(seed)));
        })
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::SettingsBuilder;

    #[test]
    fn test_init() {
        let settings = SettingsBuilder::new("example.com", "http://example.com", "test_salt")
            .build()
            .unwrap();
        
        let result = init(settings.clone());
        assert!(result.is_ok());

        SETTINGS.with_borrow(|s| {
            assert_eq!(s.as_ref().unwrap().domain, settings.domain);
            assert_eq!(s.as_ref().unwrap().uri, settings.uri);
            assert_eq!(s.as_ref().unwrap().salt, settings.salt);
        });
    }
}