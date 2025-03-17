#![doc = include_str!("../CHANGELOG.md")]
pub mod delegation;
pub mod sui;
pub(crate) mod hash;
pub(crate) mod init;
pub mod login;
mod macros;
pub(crate) mod rand;
pub mod settings;
pub mod signature_map;
pub mod sis;
pub(crate) mod time;

pub use init::init;

use settings::Settings;
use sis::SisMessageMap;
use std::cell::RefCell;

use rand_chacha::ChaCha20Rng;

thread_local! {
    static RNG: RefCell<Option<ChaCha20Rng>> = const { RefCell::new(None) };
    static SETTINGS: RefCell<Option<Settings>> = const { RefCell::new(None) };
    static SIS_MESSAGES: RefCell<SisMessageMap> = RefCell::new(SisMessageMap::new());
}