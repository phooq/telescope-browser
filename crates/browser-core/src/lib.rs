use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroize;

pub type Result<T> = std::result::Result<T, TelescopeError>;
pub type CredentialId = String;
pub type SessionId = String;

#[derive(Debug, Error)]
pub enum TelescopeError {
    #[error("invalid URL or origin: {0}")]
    InvalidOrigin(String),
    #[error("credential not found: {0}")]
    CredentialNotFound(String),
    #[error("agent session not found: {0}")]
    SessionNotFound(String),
    #[error("policy denied: {0}")]
    PolicyDenied(String),
    #[error("secret store error: {0}")]
    SecretStore(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[cfg(feature = "os-keyring")]
    #[error("keyring error: {0}")]
    Keyring(#[from] keyring::Error),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct WebOrigin {
    pub scheme: String,
    pub host: String,
    pub port: u16,
}

impl WebOrigin {
    pub fn parse(input: &str) -> Result<Self> {
        let url = if input.contains("://") {
            Url::parse(input)
        } else {
            Url::parse(&format!("https://{input}"))
        }
        .map_err(|err| TelescopeError::InvalidOrigin(format!("{input}: {err}")))?;

        Self::from_url(&url)
    }

    pub fn from_url(url: &Url) -> Result<Self> {
        let scheme = url.scheme();
        if scheme != "http" && scheme != "https" {
            return Err(TelescopeError::InvalidOrigin(format!(
                "unsupported scheme `{scheme}`"
            )));
        }

        let host = url
            .host_str()
            .ok_or_else(|| TelescopeError::InvalidOrigin("missing host".to_string()))?
            .to_ascii_lowercase();
        let port = url
            .port_or_known_default()
            .ok_or_else(|| TelescopeError::InvalidOrigin("missing port".to_string()))?;

        Ok(Self {
            scheme: scheme.to_string(),
            host,
            port,
        })
    }

    pub fn from_url_str(url: &str) -> Result<Self> {
        let parsed = Url::parse(url)
            .map_err(|err| TelescopeError::InvalidOrigin(format!("{url}: {err}")))?;
        Self::from_url(&parsed)
    }

    pub fn matches_url(&self, url: &str) -> Result<bool> {
        Ok(Self::from_url_str(url)? == *self)
    }

    pub fn display_url(&self) -> String {
        match (self.scheme.as_str(), self.port) {
            ("http", 80) | ("https", 443) => format!("{}://{}", self.scheme, self.host),
            _ => format!("{}://{}:{}", self.scheme, self.host, self.port),
        }
    }

    pub fn key(&self) -> String {
        format!("{}://{}:{}", self.scheme, self.host, self.port)
    }
}

impl std::fmt::Display for WebOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.display_url())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialRecord {
    pub id: CredentialId,
    pub origin: WebOrigin,
    pub username: String,
    pub login_url: Option<String>,
    pub label: Option<String>,
    pub created_at_unix: u64,
    pub updated_at_unix: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialInput {
    pub origin: String,
    pub username: String,
    pub password: String,
    pub login_url: Option<String>,
    pub label: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserCredentialMaterial {
    pub credential_id: CredentialId,
    pub origin: WebOrigin,
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct CredentialIndex {
    records: BTreeMap<CredentialId, CredentialRecord>,
}

pub trait SecretStore: Send + Sync {
    fn set_secret(&self, key: &str, secret: &str) -> Result<()>;
    fn get_secret(&self, key: &str) -> Result<String>;
    fn delete_secret(&self, key: &str) -> Result<()>;
}

#[derive(Clone, Default)]
pub struct MemorySecretStore {
    inner: Arc<RwLock<BTreeMap<String, String>>>,
}

impl MemorySecretStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SecretStore for MemorySecretStore {
    fn set_secret(&self, key: &str, secret: &str) -> Result<()> {
        self.inner
            .write()
            .map_err(|_| TelescopeError::SecretStore("memory store lock poisoned".to_string()))?
            .insert(key.to_string(), secret.to_string());
        Ok(())
    }

    fn get_secret(&self, key: &str) -> Result<String> {
        self.inner
            .read()
            .map_err(|_| TelescopeError::SecretStore("memory store lock poisoned".to_string()))?
            .get(key)
            .cloned()
            .ok_or_else(|| TelescopeError::SecretStore(format!("secret not found: {key}")))
    }

    fn delete_secret(&self, key: &str) -> Result<()> {
        self.inner
            .write()
            .map_err(|_| TelescopeError::SecretStore("memory store lock poisoned".to_string()))?
            .remove(key);
        Ok(())
    }
}

#[cfg(feature = "os-keyring")]
#[derive(Clone, Debug)]
pub struct OsKeyringStore {
    service: String,
}

#[cfg(feature = "os-keyring")]
impl OsKeyringStore {
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }
}

#[cfg(feature = "os-keyring")]
impl Default for OsKeyringStore {
    fn default() -> Self {
        Self::new("dev.telescope.browser")
    }
}

#[cfg(feature = "os-keyring")]
impl SecretStore for OsKeyringStore {
    fn set_secret(&self, key: &str, secret: &str) -> Result<()> {
        keyring::Entry::new(&self.service, key)?.set_password(secret)?;
        Ok(())
    }

    fn get_secret(&self, key: &str) -> Result<String> {
        Ok(keyring::Entry::new(&self.service, key)?.get_password()?)
    }

    fn delete_secret(&self, key: &str) -> Result<()> {
        keyring::Entry::new(&self.service, key)?.delete_credential()?;
        Ok(())
    }
}

pub struct CredentialVault {
    profile_id: String,
    index_path: Option<PathBuf>,
    secret_store: Arc<dyn SecretStore>,
    records: BTreeMap<CredentialId, CredentialRecord>,
}

impl CredentialVault {
    pub fn ephemeral(profile_id: impl Into<String>, secret_store: Arc<dyn SecretStore>) -> Self {
        Self {
            profile_id: profile_id.into(),
            index_path: None,
            secret_store,
            records: BTreeMap::new(),
        }
    }

    pub fn open(
        profile_id: impl Into<String>,
        index_path: impl AsRef<Path>,
        secret_store: Arc<dyn SecretStore>,
    ) -> Result<Self> {
        let index_path = index_path.as_ref().to_path_buf();
        let records = if index_path.exists() {
            let data = fs::read_to_string(&index_path)?;
            serde_json::from_str::<CredentialIndex>(&data)?.records
        } else {
            BTreeMap::new()
        };

        Ok(Self {
            profile_id: profile_id.into(),
            index_path: Some(index_path),
            secret_store,
            records,
        })
    }

    pub fn put(&mut self, mut input: CredentialInput) -> Result<CredentialRecord> {
        let origin = WebOrigin::parse(&input.origin)?;
        if let Some(login_url) = &input.login_url {
            if !origin.matches_url(login_url)? {
                return Err(TelescopeError::PolicyDenied(format!(
                    "login URL `{login_url}` is outside credential origin `{origin}`"
                )));
            }
        }

        let now = now_unix();
        let existing_id = self.records.iter().find_map(|(id, record)| {
            (record.origin == origin && record.username == input.username).then(|| id.clone())
        });
        let id = existing_id.unwrap_or_else(|| Uuid::new_v4().to_string());
        let existing = self.records.get(&id);
        let record = CredentialRecord {
            id: id.clone(),
            origin,
            username: input.username,
            login_url: input.login_url.or_else(|| {
                existing
                    .and_then(|record| record.login_url.as_ref())
                    .cloned()
            }),
            label: input
                .label
                .or_else(|| existing.and_then(|record| record.label.as_ref()).cloned()),
            created_at_unix: existing.map(|record| record.created_at_unix).unwrap_or(now),
            updated_at_unix: now,
        };

        self.secret_store
            .set_secret(&self.secret_key(&id), input.password.as_str())?;
        input.password.zeroize();
        self.records.insert(id, record.clone());
        self.persist()?;
        Ok(record)
    }

    pub fn list(&self) -> Vec<CredentialRecord> {
        self.records.values().cloned().collect()
    }

    pub fn list_for_url(&self, url: &str) -> Result<Vec<CredentialRecord>> {
        let origin = WebOrigin::from_url_str(url)?;
        Ok(self
            .records
            .values()
            .filter(|record| record.origin == origin)
            .cloned()
            .collect())
    }

    pub fn get_record(&self, credential_id: &str) -> Result<CredentialRecord> {
        self.records
            .get(credential_id)
            .cloned()
            .ok_or_else(|| TelescopeError::CredentialNotFound(credential_id.to_string()))
    }

    pub fn material_for_browser(&self, credential_id: &str) -> Result<BrowserCredentialMaterial> {
        let record = self.get_record(credential_id)?;
        let password = self
            .secret_store
            .get_secret(&self.secret_key(credential_id))?;
        Ok(BrowserCredentialMaterial {
            credential_id: credential_id.to_string(),
            origin: record.origin,
            username: record.username,
            password,
        })
    }

    pub fn delete(&mut self, credential_id: &str) -> Result<()> {
        if self.records.remove(credential_id).is_none() {
            return Err(TelescopeError::CredentialNotFound(
                credential_id.to_string(),
            ));
        }
        let _ = self
            .secret_store
            .delete_secret(&self.secret_key(credential_id));
        self.persist()
    }

    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    fn secret_key(&self, credential_id: &str) -> String {
        format!("{}:credential:{credential_id}", self.profile_id)
    }

    fn persist(&self) -> Result<()> {
        let Some(index_path) = &self.index_path else {
            return Ok(());
        };

        if let Some(parent) = index_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let index = CredentialIndex {
            records: self.records.clone(),
        };
        let tmp_path = index_path.with_extension("json.tmp");
        write_private_file(&tmp_path, &serde_json::to_vec_pretty(&index)?)?;
        fs::rename(tmp_path, index_path)?;
        set_private_file_permissions(index_path)?;
        Ok(())
    }
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        set_private_file_permissions(path)?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        fs::write(path, bytes)?;
        Ok(())
    }
}

fn set_private_file_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }

    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentPolicy {
    pub allowed_origins: Vec<WebOrigin>,
    pub allow_credentials: bool,
    pub allow_interactions: bool,
    pub allow_scripts: bool,
    pub expires_at_unix: Option<u64>,
}

impl AgentPolicy {
    pub fn new(allowed_origins: Vec<WebOrigin>) -> Self {
        Self {
            allowed_origins,
            allow_credentials: false,
            allow_interactions: false,
            allow_scripts: false,
            expires_at_unix: None,
        }
    }

    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.expires_at_unix = Some(now_unix() + ttl.as_secs());
        self
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentSession {
    pub id: SessionId,
    pub policy: AgentPolicy,
    pub created_at_unix: u64,
}

impl AgentSession {
    pub fn new(policy: AgentPolicy) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            policy,
            created_at_unix: now_unix(),
        }
    }

    pub fn assert_active(&self) -> Result<()> {
        if let Some(expires_at) = self.policy.expires_at_unix {
            if now_unix() >= expires_at {
                return Err(TelescopeError::PolicyDenied(format!(
                    "session `{}` is expired",
                    self.id
                )));
            }
        }
        Ok(())
    }

    pub fn assert_allows_url(&self, url: &str) -> Result<WebOrigin> {
        self.assert_active()?;
        let origin = WebOrigin::from_url_str(url)?;
        if self
            .policy
            .allowed_origins
            .iter()
            .any(|item| item == &origin)
        {
            Ok(origin)
        } else {
            Err(TelescopeError::PolicyDenied(format!(
                "session `{}` is not allowed to access `{origin}`",
                self.id
            )))
        }
    }

    pub fn assert_can_fill_credential(
        &self,
        credential: &CredentialRecord,
        target_url: &str,
    ) -> Result<()> {
        let target_origin = self.assert_allows_url(target_url)?;
        if !self.policy.allow_credentials {
            return Err(TelescopeError::PolicyDenied(format!(
                "session `{}` cannot use credentials",
                self.id
            )));
        }
        if credential.origin != target_origin {
            return Err(TelescopeError::PolicyDenied(format!(
                "credential `{}` belongs to `{}`, not `{target_origin}`",
                credential.id, credential.origin
            )));
        }
        Ok(())
    }

    pub fn assert_can_interact(&self) -> Result<()> {
        self.assert_active()?;
        if self.policy.allow_interactions {
            Ok(())
        } else {
            Err(TelescopeError::PolicyDenied(format!(
                "session `{}` cannot interact with pages",
                self.id
            )))
        }
    }
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn memory_vault() -> CredentialVault {
        CredentialVault::ephemeral("test", Arc::new(MemorySecretStore::new()))
    }

    #[test]
    fn origin_normalizes_default_ports() {
        let explicit = WebOrigin::parse("https://EXAMPLE.com:443/login").unwrap();
        let implicit = WebOrigin::parse("https://example.com/").unwrap();
        assert_eq!(explicit, implicit);
        assert_eq!(implicit.display_url(), "https://example.com");
    }

    #[test]
    fn vault_stores_metadata_and_keeps_secret_fetch_browser_only() {
        let mut vault = memory_vault();
        let record = vault
            .put(CredentialInput {
                origin: "https://example.com".to_string(),
                username: "me@example.com".to_string(),
                password: "correct horse battery staple".to_string(),
                login_url: Some("https://example.com/login".to_string()),
                label: Some("primary".to_string()),
            })
            .unwrap();

        let listed = vault.list_for_url("https://example.com/account").unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].username, "me@example.com");

        let material = vault.material_for_browser(&record.id).unwrap();
        assert_eq!(material.password, "correct horse battery staple");
    }

    #[test]
    fn vault_updates_existing_origin_username_credential() {
        let mut vault = memory_vault();
        let first = vault
            .put(CredentialInput {
                origin: "https://example.com".to_string(),
                username: "me@example.com".to_string(),
                password: "old secret".to_string(),
                login_url: Some("https://example.com/login".to_string()),
                label: Some("Primary".to_string()),
            })
            .unwrap();
        let updated = vault
            .put(CredentialInput {
                origin: "https://example.com/account".to_string(),
                username: "me@example.com".to_string(),
                password: "new secret".to_string(),
                login_url: Some("https://example.com/settings".to_string()),
                label: None,
            })
            .unwrap();

        assert_eq!(updated.id, first.id);
        assert_eq!(updated.created_at_unix, first.created_at_unix);
        assert!(updated.updated_at_unix >= first.updated_at_unix);
        assert_eq!(
            updated.login_url.as_deref(),
            Some("https://example.com/settings")
        );
        assert_eq!(updated.label.as_deref(), Some("Primary"));
        assert_eq!(vault.list_for_url("https://example.com/").unwrap().len(), 1);
        let material = vault.material_for_browser(&updated.id).unwrap();
        assert_eq!(material.password, "new secret");
    }

    #[cfg(unix)]
    #[test]
    fn vault_persists_index_with_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let mut dir = std::env::temp_dir();
        dir.push(format!("telescope-vault-{}", Uuid::new_v4()));
        let index_path = dir.join("profile").join("credentials.json");
        let mut vault = CredentialVault::open(
            "secure-profile",
            &index_path,
            Arc::new(MemorySecretStore::new()),
        )
        .unwrap();
        vault
            .put(CredentialInput {
                origin: "https://example.com".to_string(),
                username: "me@example.com".to_string(),
                password: "persisted secret".to_string(),
                login_url: None,
                label: None,
            })
            .unwrap();

        let mode = fs::metadata(&index_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let index_json = fs::read_to_string(&index_path).unwrap();
        assert!(index_json.contains("me@example.com"));
        assert!(!index_json.contains("persisted secret"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn agent_policy_denies_cross_origin_credentials() {
        let mut vault = memory_vault();
        let record = vault
            .put(CredentialInput {
                origin: "https://example.com".to_string(),
                username: "me".to_string(),
                password: "secret".to_string(),
                login_url: None,
                label: None,
            })
            .unwrap();
        let mut policy = AgentPolicy::new(vec![WebOrigin::parse("https://example.com").unwrap()]);
        policy.allow_credentials = true;
        let session = AgentSession::new(policy);

        session
            .assert_can_fill_credential(&record, "https://example.com/login")
            .unwrap();
        let denied = session
            .assert_can_fill_credential(&record, "https://evil.example/login")
            .unwrap_err();
        assert!(matches!(denied, TelescopeError::PolicyDenied(_)));
    }

    #[test]
    fn zero_ttl_session_is_immediately_expired() {
        let policy = AgentPolicy::new(vec![WebOrigin::parse("https://example.com").unwrap()])
            .with_ttl(Duration::from_secs(0));
        let session = AgentSession::new(policy);

        let denied = session.assert_active().unwrap_err();
        assert!(matches!(denied, TelescopeError::PolicyDenied(_)));
    }
}
