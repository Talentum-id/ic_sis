use ic_cdk::api::set_certified_data;
use ic_certified_map::{fork_hash, labeled_hash, AsHashTree, Hash, RbTree};
use ic_sis::signature_map::SignatureMap;
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    storable::Blob,
    DefaultMemoryImpl, StableBTreeMap,
};
use std::cell::RefCell;

pub mod service;

pub const LABEL_ASSETS: &[u8] = b"http_assets";
pub const LABEL_SIG: &[u8] = b"sig";

pub(crate) type AssetHashes = RbTree<&'static str, Hash>;

pub(crate) struct State {
    pub signature_map: RefCell<SignatureMap>,
    pub asset_hashes: RefCell<AssetHashes>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            signature_map: RefCell::new(SignatureMap::default()),
            asset_hashes: RefCell::new(AssetHashes::default()),
        }
    }
}

#[derive(Default, Debug, Clone)]
pub(crate) struct Settings {
    pub disable_sui_to_principal_mapping: bool,
    pub disable_principal_to_sui_mapping: bool,
}

thread_local! {
    static STATE: State = State::default();

    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    static SETTINGS: RefCell<Settings> = const { RefCell::new(Settings {
        disable_sui_to_principal_mapping: false,
        disable_principal_to_sui_mapping: false,
    }) };

    // For Sui, addresses are 32 bytes (instead of Ethereum's 20 bytes)
    static PRINCIPAL_ADDRESS: RefCell<StableBTreeMap<Blob<29>, [u8;32], VirtualMemory<DefaultMemoryImpl>>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))),
        )
    );

    static ADDRESS_PRINCIPAL: RefCell<StableBTreeMap<[u8;32], Blob<29>, VirtualMemory<DefaultMemoryImpl>>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1))),
        )
    );
}

pub(crate) fn update_root_hash(asset_hashes: &AssetHashes, signature_map: &SignatureMap) {
    let prefixed_root_hash = fork_hash(
        &labeled_hash(LABEL_ASSETS, &asset_hashes.root_hash()),
        &labeled_hash(LABEL_SIG, &signature_map.root_hash()),
    );
    set_certified_data(&prefixed_root_hash[..]);
}