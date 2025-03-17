use candid::Principal;
use url::Url;

const DEFAULT_SCHEME: &str = "https";
const DEFAULT_STATEMENT: &str = "Sign in with Sui";
const DEFAULT_NETWORK: &str = "mainnet"; // Sui mainnet
const DEFAULT_SIGN_IN_EXPIRES_IN: u64 = 60 * 5 * 1_000_000_000; // 5 minutes
const DEFAULT_SESSION_EXPIRES_IN: u64 = 30 * 60 * 1_000_000_000; // 30 minutes

#[derive(Debug, Clone, PartialEq)]
pub enum RuntimeFeature {
    IncludeUriInSeed,
}

#[derive(Default, Debug, Clone)]
pub struct Settings {
    pub domain: String,

    pub uri: String,

    pub salt: String,

    pub network: String,

    pub scheme: String,

    pub statement: String,

    pub sign_in_expires_in: u64,

    pub session_expires_in: u64,

    pub targets: Option<Vec<Principal>>,

    pub runtime_features: Option<Vec<RuntimeFeature>>,
}

pub struct SettingsBuilder {
    settings: Settings,
}

impl SettingsBuilder {
    pub fn new<S: Into<String>, T: Into<String>, U: Into<String>>(
        domain: S,
        uri: T,
        salt: U,
    ) -> Self {
        SettingsBuilder {
            settings: Settings {
                domain: domain.into(),
                uri: uri.into(),
                salt: salt.into(),
                network: DEFAULT_NETWORK.to_string(),
                scheme: DEFAULT_SCHEME.to_string(),
                statement: DEFAULT_STATEMENT.to_string(),
                sign_in_expires_in: DEFAULT_SIGN_IN_EXPIRES_IN,
                session_expires_in: DEFAULT_SESSION_EXPIRES_IN,
                targets: None,
                runtime_features: None,
            },
        }
    }

    pub fn network<S: Into<String>>(mut self, network: S) -> Self {
        self.settings.network = network.into();
        self
    }

    pub fn scheme<S: Into<String>>(mut self, scheme: S) -> Self {
        self.settings.scheme = scheme.into();
        self
    }

    pub fn statement<S: Into<String>>(mut self, statement: S) -> Self {
        self.settings.statement = statement.into();
        self
    }

    pub fn sign_in_expires_in(mut self, expires_in: u64) -> Self {
        self.settings.sign_in_expires_in = expires_in;
        self
    }

    pub fn session_expires_in(mut self, expires_in: u64) -> Self {
        self.settings.session_expires_in = expires_in;
        self
    }

    pub fn targets(mut self, targets: Vec<Principal>) -> Self {
        self.settings.targets = Some(targets);
        self
    }

    pub fn runtime_features(mut self, features: Vec<RuntimeFeature>) -> Self {
        self.settings.runtime_features = Some(features);
        self
    }

    pub fn build(self) -> Result<Settings, String> {
        validate_domain(&self.settings.scheme, &self.settings.domain)?;
        validate_uri(&self.settings.uri)?;
        validate_salt(&self.settings.salt)?;
        validate_network(&self.settings.network)?;
        validate_scheme(&self.settings.scheme)?;
        validate_statement(&self.settings.statement)?;
        validate_sign_in_expires_in(self.settings.sign_in_expires_in)?;
        validate_session_expires_in(self.settings.session_expires_in)?;
        validate_targets(&self.settings.targets)?;

        Ok(self.settings)
    }
}

fn validate_domain(scheme: &str, domain: &str) -> Result<String, String> {
    let url_str = format!("{}://{}", scheme, domain);
    let parsed_url = Url::parse(&url_str).map_err(|_| String::from("Invalid domain"))?;
    if !parsed_url.has_authority() {
        Err(String::from("Invalid domain"))
    } else {
        Ok(parsed_url.host_str().unwrap().to_string())
    }
}

fn validate_uri(uri: &str) -> Result<String, String> {
    let parsed_uri = Url::parse(uri).map_err(|_| String::from("Invalid URI"))?;
    if !parsed_uri.has_host() {
        Err(String::from("Invalid URI"))
    } else {
        Ok(uri.to_string())
    }
}

fn validate_salt(salt: &str) -> Result<String, String> {
    if salt.is_empty() {
        return Err(String::from("Salt cannot be empty"));
    }
    if salt.chars().any(|c| !c.is_ascii() || !c.is_ascii_graphic()) {
        return Err(String::from("Invalid salt"));
    }
    Ok(salt.to_string())
}

fn validate_network(network: &str) -> Result<String, String> {
    if network.is_empty() {
        return Err(String::from("Network cannot be empty"));
    }
    
    // Validate the network is one of the known Sui networks
    match network {
        "mainnet" | "testnet" | "devnet" | "localnet" => Ok(network.to_string()),
        _ => Err(String::from("Unknown Sui network. Use 'mainnet', 'testnet', 'devnet', or 'localnet'")),
    }
}

fn validate_scheme(scheme: &str) -> Result<String, String> {
    if scheme == "http" || scheme == "https" {
        return Ok(scheme.to_string());
    }
    Err(String::from("Invalid scheme"))
}

fn validate_statement(statement: &str) -> Result<String, String> {
    if statement.contains('\n') {
        return Err(String::from("Invalid statement"));
    }
    Ok(statement.to_string())
}

fn validate_sign_in_expires_in(expires_in: u64) -> Result<u64, String> {
    if expires_in == 0 {
        return Err(String::from("Sign in expires in must be greater than 0"));
    }
    Ok(expires_in)
}

fn validate_session_expires_in(expires_in: u64) -> Result<u64, String> {
    if expires_in == 0 {
        return Err(String::from("Session expires in must be greater than 0"));
    }
    Ok(expires_in)
}

fn validate_targets(targets: &Option<Vec<Principal>>) -> Result<Option<Vec<Principal>>, String> {
    if let Some(targets) = targets {
        if targets.is_empty() {
            return Err(String::from("Targets cannot be empty"));
        }

        if targets.len() > 1000 {
            return Err(String::from("Too many targets"));
        }

        let mut targets_clone = targets.clone();
        targets_clone.sort();
        targets_clone.dedup();
        if targets_clone.len() != targets.len() {
            return Err(String::from("Duplicate targets are not allowed"));
        }
    }
    Ok(targets.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use candid::Principal;

    #[test]
    fn test_successful_settings_creation_defaults() {
        let builder = SettingsBuilder::new("example.com", "http://example.com", "some_salt");
        let settings = builder
            .build()
            .expect("Failed to create settings with defaults");
        assert_eq!(settings.domain, "example.com");
        assert_eq!(settings.uri, "http://example.com");
        assert_eq!(settings.salt, "some_salt");
        assert_eq!(settings.network, DEFAULT_NETWORK);
        assert_eq!(settings.scheme, DEFAULT_SCHEME);
        assert_eq!(settings.statement, DEFAULT_STATEMENT);
        assert_eq!(settings.sign_in_expires_in, DEFAULT_SIGN_IN_EXPIRES_IN);
        assert_eq!(settings.session_expires_in, DEFAULT_SESSION_EXPIRES_IN);
        assert!(settings.targets.is_none());
    }

    #[test]
    fn test_successful_settings_creation_custom() {
        let targets = vec![Principal::anonymous()];
        let builder = SettingsBuilder::new("example.com", "http://example.com", "some_salt")
            .network("testnet")
            .scheme("http")
            .statement("Custom statement")
            .sign_in_expires_in(10_000_000_000)
            .session_expires_in(20_000_000_000)
            .targets(targets.clone());
        let settings = builder
            .build()
            .expect("Failed to create settings with custom values");
        assert_eq!(settings.network, "testnet");
        assert_eq!(settings.scheme, "http");
        assert_eq!(settings.statement, "Custom statement");
        assert_eq!(settings.sign_in_expires_in, 10_000_000_000);
        assert_eq!(settings.session_expires_in, 20_000_000_000);
        assert_eq!(settings.targets, Some(targets));
    }

    #[test]
    fn test_invalid_network() {
        let builder = SettingsBuilder::new("example.com", "http://example.com", "some_salt")
            .network("invalid_network");
        assert!(builder.build().is_err());
    }

    #[test]
    fn test_empty_salt() {
        let builder = SettingsBuilder::new("example.com", "http://example.com", "");
        assert!(builder.build().is_err());
    }

    #[test]
    fn test_invalid_scheme() {
        let builder =
            SettingsBuilder::new("example.com", "http://example.com", "some_salt").scheme("ftp");
        assert!(builder.build().is_err());
    }
}