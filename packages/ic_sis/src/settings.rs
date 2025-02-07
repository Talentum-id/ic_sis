use candid::Principal;
use url::Url;

const DEFAULT_SCHEME: &str = "https";
const DEFAULT_STATEMENT: &str = "SIS Fields:";
const DEFAULT_SIGN_IN_EXPIRES_IN: u64 = 60 * 5 * 1_000_000_000; // 5 minutes
const DEFAULT_SESSION_EXPIRES_IN: u64 = 30 * 60 * 1_000_000_000; // 30 minutes

#[derive(Default, Debug, Clone)]
pub struct Settings {
    pub domain: String,
    pub uri: String,
    pub salt: String,
    pub scheme: String,
    pub statement: String,
    pub sign_in_expires_in: u64,
    pub session_expires_in: u64,
    pub targets: Option<Vec<Principal>>,
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
                scheme: DEFAULT_SCHEME.to_string(),
                statement: DEFAULT_STATEMENT.to_string(),
                sign_in_expires_in: DEFAULT_SIGN_IN_EXPIRES_IN,
                session_expires_in: DEFAULT_SESSION_EXPIRES_IN,
                targets: None,
            },
        }
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

    pub fn build(self) -> Result<Settings, String> {
        validate_domain(&self.settings.scheme, &self.settings.domain)?;
        validate_uri(&self.settings.uri)?;
        validate_salt(&self.settings.salt)?;
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

    #[test]
    fn test_settings_builder_defaults() {
        let settings = SettingsBuilder::new("example.com", "http://example.com", "test_salt")
            .build()
            .unwrap();
        
        assert_eq!(settings.scheme, DEFAULT_SCHEME);
        assert_eq!(settings.statement, DEFAULT_STATEMENT);
        assert_eq!(settings.sign_in_expires_in, DEFAULT_SIGN_IN_EXPIRES_IN);
        assert_eq!(settings.session_expires_in, DEFAULT_SESSION_EXPIRES_IN);
        assert!(settings.targets.is_none());
    }

    #[test]
    fn test_settings_builder_custom_values() {
        let settings = SettingsBuilder::new("example.com", "http://example.com", "test_salt")
            .scheme("http")
            .statement("Custom statement")
            .sign_in_expires_in(60000)
            .session_expires_in(120000)
            .targets(vec![Principal::from_text("aaaaa-aa").unwrap()])
            .build()
            .unwrap();
        
        assert_eq!(settings.scheme, "http");
        assert_eq!(settings.statement, "Custom statement");
        assert_eq!(settings.sign_in_expires_in, 60000);
        assert_eq!(settings.session_expires_in, 120000);
        assert!(settings.targets.is_some());
    }

    #[test]
    fn test_invalid_settings() {
        // Test invalid domain
        assert!(SettingsBuilder::new("", "http://example.com", "test_salt")
            .build()
            .is_err());

        // Test invalid URI
        assert!(SettingsBuilder::new("example.com", "", "test_salt")
            .build()
            .is_err());

        // Test invalid salt
        assert!(SettingsBuilder::new("example.com", "http://example.com", "")
            .build()
            .is_err());

        // Test invalid scheme
        assert!(SettingsBuilder::new("example.com", "http://example.com", "test_salt")
            .scheme("ftp")
            .build()
            .is_err());

        // Test invalid statement
        assert!(SettingsBuilder::new("example.com", "http://example.com", "test_salt")
            .statement("Invalid\nstatement")
            .build()
            .is_err());

        // Test invalid expiration times
        assert!(SettingsBuilder::new("example.com", "http://example.com", "test_salt")
            .sign_in_expires_in(0)
            .build()
            .is_err());

        assert!(SettingsBuilder::new("example.com", "http://example.com", "test_salt")
            .session_expires_in(0)
            .build()
            .is_err());

        // Test invalid targets
        assert!(SettingsBuilder::new("example.com", "http://example.com", "test_salt")
            .targets(vec![])
            .build()
            .is_err());
    }
}