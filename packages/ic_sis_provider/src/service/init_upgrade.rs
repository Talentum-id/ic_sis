use candid::{CandidType, Principal};
use ic_cdk::{init, post_upgrade};
use ic_sis::settings::SettingsBuilder;
use serde::Deserialize;

use crate::SETTINGS;

#[derive(CandidType, Debug, Clone, PartialEq, Deserialize)]
pub enum RuntimeFeature {
    IncludeUriInSeed,

    DisableSuiToPrincipalMapping,

    DisablePrincipalToSuiMapping,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct SettingsInput {
    pub domain: String,

    pub uri: String,

    pub salt: String,

    pub network: Option<String>,

    pub scheme: Option<String>,

    pub statement: Option<String>,

    pub sign_in_expires_in: Option<u64>,

    pub session_expires_in: Option<u64>,

    pub targets: Option<Vec<String>>,

    pub runtime_features: Option<Vec<RuntimeFeature>>,
}

fn sis_init(settings_input: SettingsInput) {
    let mut ic_sis_settings = SettingsBuilder::new(
        &settings_input.domain,
        &settings_input.uri,
        &settings_input.salt,
    );

    if let Some(network) = settings_input.network.as_deref() {
        ic_sis_settings = ic_sis_settings.network(network);
    }
    if let Some(scheme) = settings_input.scheme.as_deref() {
        ic_sis_settings = ic_sis_settings.scheme(scheme);
    }
    if let Some(statement) = settings_input.statement.as_deref() {
        ic_sis_settings = ic_sis_settings.statement(statement);
    }
    if let Some(expire_in) = settings_input.sign_in_expires_in {
        ic_sis_settings = ic_sis_settings.sign_in_expires_in(expire_in);
    }
    if let Some(session_expire_in) = settings_input.session_expires_in {
        ic_sis_settings = ic_sis_settings.session_expires_in(session_expire_in);
    }
    if let Some(targets) = settings_input.targets {
        let targets: Vec<Principal> = targets
            .into_iter()
            .map(|t| Principal::from_text(t).unwrap())
            .collect();
        let canister_id = ic_cdk::id();
        if !targets.contains(&canister_id) {
            panic!(
                "ic_sis_provider canister id {} not in the list of targets",
                canister_id
            );
        }
        ic_sis_settings = ic_sis_settings.targets(targets);
    }

    SETTINGS.with_borrow_mut(|provider_settings| {
        if let Some(runtime_features) = settings_input.runtime_features {
            for feature in runtime_features {
                match feature {
                    RuntimeFeature::IncludeUriInSeed => {
                        ic_sis_settings = ic_sis_settings.runtime_features(vec![
                            ic_sis::settings::RuntimeFeature::IncludeUriInSeed,
                        ]);
                    }
                    RuntimeFeature::DisableSuiToPrincipalMapping => {
                        provider_settings.disable_sui_to_principal_mapping = true;
                    }
                    RuntimeFeature::DisablePrincipalToSuiMapping => {
                        provider_settings.disable_principal_to_sui_mapping = true;
                    }
                }
            }
        }

        ic_sis::init(ic_sis_settings.build().unwrap()).unwrap();
    });
}

#[init]
fn init(settings: SettingsInput) {
    sis_init(settings);
}

#[post_upgrade]
fn upgrade(settings: SettingsInput) {
    sis_init(settings);
}