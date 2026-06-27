use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, Write};
use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use thiserror::Error;
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};
use uuid::Uuid;

use telescope_core::{
    now_unix, AgentSession, BrowserCredentialMaterial, CredentialInput, CredentialRecord,
    CredentialVault, Result as CoreResult, SessionId, TelescopeError,
};
pub use telescope_core::{AgentPolicy, WebOrigin};

#[derive(Debug, Error)]
pub enum ControlError {
    #[error("{0}")]
    Core(#[from] TelescopeError),
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("not found: {0}")]
    NotFound(String),
    #[error("server error: {0}")]
    Server(String),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, ControlError>;

#[derive(Clone)]
pub struct ControlPlane {
    inner: Arc<Mutex<InnerState>>,
    vault: Arc<Mutex<CredentialVault>>,
    audit_path: Option<PathBuf>,
    bookmark_path: Option<PathBuf>,
}

#[derive(Default)]
struct InnerState {
    sessions: BTreeMap<SessionId, AgentSession>,
    tabs: BTreeMap<String, TabState>,
    active_tab_id: Option<String>,
    agent_panes: BTreeMap<String, AgentPaneState>,
    agent_pane_connections: BTreeMap<String, AgentPaneConnection>,
    agent_grants: BTreeMap<String, AgentGrant>,
    page_contexts: BTreeMap<String, PageContextSnapshot>,
    element_refs: BTreeMap<String, ElementReference>,
    commands: VecDeque<BrowserCommand>,
    command_scopes: BTreeMap<String, CommandScope>,
    command_results: VecDeque<CommandExecutionReport>,
    audit_events: VecDeque<AuditEvent>,
    bookmarks: BTreeMap<String, BookmarkRecord>,
}

impl ControlPlane {
    pub fn new(vault: CredentialVault) -> Self {
        Self {
            inner: Arc::new(Mutex::new(InnerState::default())),
            vault: Arc::new(Mutex::new(vault)),
            audit_path: None,
            bookmark_path: None,
        }
    }

    pub fn with_audit_log(vault: CredentialVault, audit_path: impl AsRef<Path>) -> Result<Self> {
        Self::with_optional_storage(vault, Some(audit_path.as_ref().to_path_buf()), None)
    }

    pub fn with_profile_storage(
        vault: CredentialVault,
        audit_path: impl AsRef<Path>,
        bookmark_path: impl AsRef<Path>,
    ) -> Result<Self> {
        Self::with_optional_storage(
            vault,
            Some(audit_path.as_ref().to_path_buf()),
            Some(bookmark_path.as_ref().to_path_buf()),
        )
    }

    fn with_optional_storage(
        vault: CredentialVault,
        audit_path: Option<PathBuf>,
        bookmark_path: Option<PathBuf>,
    ) -> Result<Self> {
        let audit_events = match &audit_path {
            Some(audit_path) => load_audit_events(audit_path)?,
            None => VecDeque::new(),
        };
        let bookmarks = match &bookmark_path {
            Some(bookmark_path) => load_bookmarks(bookmark_path)?,
            None => BTreeMap::new(),
        };
        Ok(Self {
            inner: Arc::new(Mutex::new(InnerState {
                audit_events,
                bookmarks,
                ..InnerState::default()
            })),
            vault: Arc::new(Mutex::new(vault)),
            audit_path,
            bookmark_path,
        })
    }

    pub fn create_session(&self, request: CreateSessionRequest) -> Result<AgentSession> {
        let origins = request
            .allowed_origins
            .iter()
            .map(|origin| WebOrigin::parse(origin))
            .collect::<CoreResult<Vec<_>>>()?;
        if origins.is_empty() {
            return Err(ControlError::BadRequest(
                "at least one allowed origin is required".to_string(),
            ));
        }

        let mut policy = AgentPolicy::new(origins);
        policy.allow_credentials = request.allow_credentials;
        policy.allow_interactions = request.allow_interactions;
        policy.allow_scripts = request.allow_scripts;
        if let Some(ttl_seconds) = request.ttl_seconds {
            policy.expires_at_unix = Some(now_unix() + ttl_seconds);
        }

        let session = AgentSession::new(policy);
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| ControlError::Server("control state lock poisoned".to_string()))?;
        inner.sessions.insert(session.id.clone(), session.clone());
        self.record_audit_locked(
            &mut inner,
            AuditEventKind::SessionCreated {
                session_id: session.id.clone(),
                allowed_origins: session.policy.allowed_origins.clone(),
                allow_credentials: session.policy.allow_credentials,
                allow_interactions: session.policy.allow_interactions,
                allow_scripts: session.policy.allow_scripts,
                expires_at_unix: session.policy.expires_at_unix,
            },
        )?;
        Ok(session)
    }

    pub fn list_sessions(&self) -> Result<Vec<AgentSession>> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| ControlError::Server("control state lock poisoned".to_string()))?
            .sessions
            .values()
            .cloned()
            .collect())
    }

    pub fn revoke_session(&self, session_id: &str) -> Result<RevokedAgentSession> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| ControlError::Server("control state lock poisoned".to_string()))?;
        self.revoke_session_locked(&mut inner, session_id)
    }

    pub fn create_agent_grant(&self, request: CreateAgentGrantRequest) -> Result<AgentGrant> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| ControlError::Server("control state lock poisoned".to_string()))?;
        let session = inner
            .sessions
            .get(&request.session_id)
            .cloned()
            .ok_or_else(|| TelescopeError::SessionNotFound(request.session_id.clone()))?;
        session.assert_active()?;
        let allowed_client_origins = request
            .allowed_client_origins
            .iter()
            .map(|origin| WebOrigin::parse(origin))
            .collect::<CoreResult<Vec<_>>>()?;

        for tab_id in &request.allowed_tab_ids {
            let tab = inner
                .tabs
                .get(tab_id)
                .ok_or_else(|| ControlError::NotFound(format!("tab {tab_id}")))?;
            if tab.session_id.as_deref() != Some(&request.session_id) {
                return Err(TelescopeError::PolicyDenied(format!(
                    "tab `{tab_id}` is not attached to session `{}`",
                    request.session_id
                ))
                .into());
            }
        }

        let created_at_unix = now_unix();
        let grant = AgentGrant {
            token: format!("tg_{}", Uuid::new_v4().simple()),
            session_id: request.session_id,
            allowed_tab_ids: request.allowed_tab_ids,
            allowed_client_origins,
            created_at_unix,
            expires_at_unix: request
                .ttl_seconds
                .map(|ttl_seconds| created_at_unix + ttl_seconds),
        };
        inner
            .agent_grants
            .insert(grant.token.clone(), grant.clone());
        self.record_audit_locked(
            &mut inner,
            AuditEventKind::AgentGrantCreated {
                session_id: grant.session_id.clone(),
                allowed_tab_ids: grant.allowed_tab_ids.clone(),
                allowed_client_origins: grant.allowed_client_origins.clone(),
                expires_at_unix: grant.expires_at_unix,
            },
        )?;
        Ok(grant)
    }

    pub fn list_agent_grants(&self) -> Result<Vec<AgentGrant>> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| ControlError::Server("control state lock poisoned".to_string()))?
            .agent_grants
            .values()
            .cloned()
            .collect())
    }

    pub fn revoke_agent_grant(&self, token: &str) -> Result<RevokedAgentGrant> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| ControlError::Server("control state lock poisoned".to_string()))?;
        self.revoke_agent_grant_locked(&mut inner, token)
    }

    pub fn lookup_agent_grant(&self, token: &str) -> Result<AgentGrant> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| ControlError::Server("control state lock poisoned".to_string()))?;
        let grant = inner
            .agent_grants
            .get(token)
            .cloned()
            .ok_or(ControlError::Unauthorized)?;
        grant.assert_active()?;
        inner
            .sessions
            .get(&grant.session_id)
            .ok_or_else(|| TelescopeError::SessionNotFound(grant.session_id.clone()))?
            .assert_active()?;
        Ok(grant)
    }

    pub fn agent_grant_allows_tab(&self, grant: &AgentGrant, tab_id: &str) -> Result<bool> {
        grant.assert_active()?;
        let inner = self
            .inner
            .lock()
            .map_err(|_| ControlError::Server("control state lock poisoned".to_string()))?;

        if !grant.allowed_tab_ids.is_empty()
            && !grant.allowed_tab_ids.iter().any(|item| item == tab_id)
        {
            return Ok(false);
        }

        inner
            .sessions
            .get(&grant.session_id)
            .ok_or_else(|| TelescopeError::SessionNotFound(grant.session_id.clone()))?
            .assert_active()?;

        Ok(inner
            .tabs
            .get(tab_id)
            .is_some_and(|tab| tab.session_id.as_deref() == Some(&grant.session_id)))
    }

    pub fn create_tab(&self, request: CreateTabRequest) -> Result<TabState> {
        self.create_tab_inner(request, true)
    }

    pub fn register_tab(&self, request: CreateTabRequest) -> Result<TabState> {
        self.create_tab_inner(request, false)
    }

    fn create_tab_inner(
        &self,
        request: CreateTabRequest,
        queue_browser_open: bool,
    ) -> Result<TabState> {
        let url = request
            .url
            .as_deref()
            .map(sanitize_browser_tab_url)
            .transpose()?;
        if let (Some(session_id), Some(url)) = (&request.session_id, &url) {
            self.get_session_locked(session_id)?
                .assert_allows_url(url)?;
        }

        let tab = TabState {
            id: Uuid::new_v4().to_string(),
            current_url: url,
            session_id: request.session_id.clone(),
            title: None,
            created_at_unix: now_unix(),
            updated_at_unix: now_unix(),
        };

        let mut inner = self
            .inner
            .lock()
            .map_err(|_| ControlError::Server("control state lock poisoned".to_string()))?;
        inner.tabs.insert(tab.id.clone(), tab.clone());
        inner.active_tab_id = Some(tab.id.clone());

        if queue_browser_open {
            queue_command_locked(
                &mut inner,
                BrowserCommand::open_tab(tab.clone()),
                CommandScope::owner(),
            );
        }
        self.record_audit_locked(
            &mut inner,
            AuditEventKind::TabCreated {
                tab_id: tab.id.clone(),
                url: tab.current_url.clone(),
                session_id: tab.session_id.clone(),
                queued_browser_open: queue_browser_open,
            },
        )?;

        Ok(tab)
    }

    pub fn list_tabs(&self) -> Result<Vec<TabState>> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| ControlError::Server("control state lock poisoned".to_string()))?
            .tabs
            .values()
            .cloned()
            .collect())
    }

    pub fn active_tab(&self) -> Result<Option<TabState>> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| ControlError::Server("control state lock poisoned".to_string()))?;
        Ok(inner
            .active_tab_id
            .as_ref()
            .and_then(|tab_id| inner.tabs.get(tab_id))
            .cloned())
    }

    pub fn activate_tab(&self, tab_id: &str) -> Result<TabState> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| ControlError::Server("control state lock poisoned".to_string()))?;
        let tab = inner
            .tabs
            .get(tab_id)
            .cloned()
            .ok_or_else(|| ControlError::NotFound(format!("tab {tab_id}")))?;

        if inner.active_tab_id.as_deref() != Some(tab_id) {
            inner.active_tab_id = Some(tab_id.to_string());
            queue_command_locked(
                &mut inner,
                BrowserCommand::activate_tab(tab_id),
                CommandScope::owner(),
            );
            self.record_audit_locked(
                &mut inner,
                AuditEventKind::TabActivated {
                    tab_id: tab_id.to_string(),
                },
            )?;
        }

        Ok(tab)
    }

    pub fn close_tab(&self, tab_id: &str) -> Result<TabState> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| ControlError::Server("control state lock poisoned".to_string()))?;
        let tab = inner
            .tabs
            .remove(tab_id)
            .ok_or_else(|| ControlError::NotFound(format!("tab {tab_id}")))?;
        inner.page_contexts.remove(tab_id);
        inner
            .element_refs
            .retain(|_, reference| reference.tab_id != tab_id);

        let pane_ids = inner
            .agent_panes
            .iter()
            .filter_map(|(pane_id, pane)| {
                (pane.attached_tab_id.as_deref() == Some(tab_id)).then(|| pane_id.clone())
            })
            .collect::<Vec<_>>();
        let mut closed_pane_ids = Vec::new();
        for pane_id in pane_ids {
            let pane = inner.agent_panes.remove(&pane_id);
            inner.agent_pane_connections.remove(&pane_id);
            let command = BrowserCommand::close_agent_pane(tab_id, &pane_id);
            let scope = pane
                .and_then(|pane| pane.session_id)
                .map(|session_id| CommandScope::session(session_id, None))
                .unwrap_or_else(CommandScope::owner);
            queue_command_locked(&mut inner, command, scope);
            closed_pane_ids.push(pane_id);
        }

        queue_command_locked(
            &mut inner,
            BrowserCommand::close_tab(tab_id),
            CommandScope::owner(),
        );
        if inner.active_tab_id.as_deref() == Some(tab_id) {
            let next_active_tab_id = inner.tabs.keys().next().cloned();
            inner.active_tab_id = next_active_tab_id.clone();
            if let Some(next_active_tab_id) = next_active_tab_id {
                queue_command_locked(
                    &mut inner,
                    BrowserCommand::activate_tab(&next_active_tab_id),
                    CommandScope::owner(),
                );
            }
        }
        self.record_audit_locked(
            &mut inner,
            AuditEventKind::TabClosed {
                tab_id: tab_id.to_string(),
                closed_pane_ids,
            },
        )?;
        Ok(tab)
    }

    pub fn open_agent_pane(&self, request: OpenAgentPaneRequest) -> Result<AgentPaneState> {
        WebOrigin::from_url_str(&request.url)?;
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| ControlError::Server("control state lock poisoned".to_string()))?;
        let grant = match &request.agent_grant_token {
            Some(token) => Some(
                inner
                    .agent_grants
                    .get(token)
                    .cloned()
                    .ok_or(ControlError::Unauthorized)?,
            ),
            None => None,
        };

        if let Some(tab_id) = &request.attached_tab_id {
            let tab = inner
                .tabs
                .get(tab_id)
                .ok_or_else(|| ControlError::NotFound(format!("tab {tab_id}")))?;
            if let Some(session_id) = &request.session_id {
                if tab.session_id.as_deref() != Some(session_id) {
                    return Err(TelescopeError::PolicyDenied(format!(
                        "tab `{tab_id}` is not attached to session `{session_id}`"
                    ))
                    .into());
                }
            }
            if let Some(grant) = &grant {
                grant.assert_active()?;
                if !grant.allowed_tab_ids.is_empty()
                    && !grant.allowed_tab_ids.iter().any(|item| item == tab_id)
                {
                    return Err(TelescopeError::PolicyDenied(format!(
                        "agent grant cannot access tab `{tab_id}`"
                    ))
                    .into());
                }
                if tab.session_id.as_deref() != Some(&grant.session_id) {
                    return Err(TelescopeError::PolicyDenied(format!(
                        "tab `{tab_id}` is not attached to grant session `{}`",
                        grant.session_id
                    ))
                    .into());
                }
            }
        }

        if let Some(session_id) = &request.session_id {
            inner
                .sessions
                .get(session_id)
                .ok_or_else(|| TelescopeError::SessionNotFound(session_id.clone()))?
                .assert_active()?;
            if let Some(grant) = &grant {
                if grant.session_id != *session_id {
                    return Err(TelescopeError::PolicyDenied(format!(
                        "agent grant is scoped to session `{}`, not `{session_id}`",
                        grant.session_id
                    ))
                    .into());
                }
            }
        }

        if grant.is_some() && (request.attached_tab_id.is_none() || request.session_id.is_none()) {
            return Err(ControlError::BadRequest(
                "agent_grant_token requires attached_tab_id and session_id".to_string(),
            ));
        }

        let now = now_unix();
        let pane = AgentPaneState {
            id: Uuid::new_v4().to_string(),
            url: request.url,
            position: request.position,
            attached_tab_id: request.attached_tab_id,
            session_id: request.session_id,
            created_at_unix: now,
            updated_at_unix: now,
        };
        let command_tab_id = pane
            .attached_tab_id
            .clone()
            .unwrap_or_else(|| pane.id.clone());
        let connection = match grant {
            Some(grant) => {
                let connection = AgentPaneConnection {
                    pane_id: pane.id.clone(),
                    session_id: grant.session_id.clone(),
                    tab_id: pane.attached_tab_id.clone().ok_or_else(|| {
                        ControlError::BadRequest(
                            "agent_grant_token requires attached_tab_id".to_string(),
                        )
                    })?,
                    grant_token: grant.token.clone(),
                    session_policy: inner
                        .sessions
                        .get(&grant.session_id)
                        .ok_or_else(|| TelescopeError::SessionNotFound(grant.session_id.clone()))?
                        .policy
                        .clone(),
                    created_at_unix: now,
                    expires_at_unix: grant.expires_at_unix,
                };
                inner
                    .agent_pane_connections
                    .insert(pane.id.clone(), connection.clone());
                Some(connection)
            }
            None => None,
        };
        inner.agent_panes.insert(pane.id.clone(), pane.clone());
        let command =
            BrowserCommand::open_agent_pane(&command_tab_id, pane.clone(), connection.clone());
        let scope = pane
            .session_id
            .clone()
            .map(|session_id| {
                CommandScope::session(session_id, None)
                    .with_grant_token(pane_connection_grant_token(&connection))
            })
            .unwrap_or_else(CommandScope::owner);
        queue_command_locked(&mut inner, command, scope);
        self.record_audit_locked(
            &mut inner,
            AuditEventKind::AgentPaneOpened {
                pane_id: pane.id.clone(),
                url: pane.url.clone(),
                position: pane.position.clone(),
                attached_tab_id: pane.attached_tab_id.clone(),
                session_id: pane.session_id.clone(),
                scoped_connection: connection.is_some(),
            },
        )?;
        Ok(pane)
    }

    pub fn open_scoped_agent_pane(
        &self,
        request: OpenScopedAgentPaneRequest,
    ) -> Result<OpenedScopedAgentPane> {
        let pane_origin = WebOrigin::from_url_str(&request.url)?;
        let (tab_id, session, grant) =
            self.prepare_scoped_agent_pane_session(&request, pane_origin)?;
        let pane = self.open_agent_pane(OpenAgentPaneRequest {
            url: request.url,
            position: request.position,
            attached_tab_id: Some(tab_id),
            session_id: Some(session.id.clone()),
            agent_grant_token: Some(grant.token.clone()),
        })?;
        let connection = self.agent_pane_connection(&pane.id)?;

        Ok(OpenedScopedAgentPane {
            session,
            grant,
            pane,
            connection,
        })
    }

    pub fn list_agent_panes(&self) -> Result<Vec<AgentPaneState>> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| ControlError::Server("control state lock poisoned".to_string()))?
            .agent_panes
            .values()
            .cloned()
            .collect())
    }

    pub fn agent_pane_connection(&self, pane_id: &str) -> Result<AgentPaneConnection> {
        self.inner
            .lock()
            .map_err(|_| ControlError::Server("control state lock poisoned".to_string()))?
            .agent_pane_connections
            .get(pane_id)
            .cloned()
            .ok_or_else(|| ControlError::NotFound(format!("agent pane connection {pane_id}")))
    }

    pub fn close_agent_pane(&self, pane_id: &str) -> Result<AgentPaneState> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| ControlError::Server("control state lock poisoned".to_string()))?;
        let pane = inner
            .agent_panes
            .remove(pane_id)
            .ok_or_else(|| ControlError::NotFound(format!("agent pane {pane_id}")))?;
        inner.agent_pane_connections.remove(pane_id);
        let command_tab_id = pane
            .attached_tab_id
            .clone()
            .unwrap_or_else(|| pane.id.clone());
        let command = BrowserCommand::close_agent_pane(&command_tab_id, &pane.id);
        let scope = pane
            .session_id
            .clone()
            .map(|session_id| CommandScope::session(session_id, None))
            .unwrap_or_else(CommandScope::owner);
        queue_command_locked(&mut inner, command, scope);
        self.record_audit_locked(
            &mut inner,
            AuditEventKind::AgentPaneClosed {
                pane_id: pane.id.clone(),
                attached_tab_id: pane.attached_tab_id.clone(),
                session_id: pane.session_id.clone(),
            },
        )?;
        Ok(pane)
    }

    pub fn navigate_tab(&self, tab_id: &str, request: NavigateRequest) -> Result<TabState> {
        self.navigate_tab_inner(tab_id, request, None)
    }

    fn navigate_tab_inner(
        &self,
        tab_id: &str,
        request: NavigateRequest,
        grant_token: Option<&str>,
    ) -> Result<TabState> {
        let url = sanitize_browser_tab_url(&request.url)?;
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| ControlError::Server("control state lock poisoned".to_string()))?;
        let session_id = {
            let tab = inner
                .tabs
                .get(tab_id)
                .ok_or_else(|| ControlError::NotFound(format!("tab {tab_id}")))?;
            request
                .session_id
                .clone()
                .or_else(|| tab.session_id.clone())
        };

        let mut command_scope = CommandScope::owner();
        if let Some(session_id) = &session_id {
            let session = inner
                .sessions
                .get(session_id)
                .cloned()
                .ok_or_else(|| TelescopeError::SessionNotFound(session_id.clone()))?;
            let target_origin = session.assert_allows_url(&url)?;
            command_scope = CommandScope::session(session_id.clone(), Some(target_origin))
                .with_grant_token(grant_token);
        }

        let updated = {
            let tab = inner
                .tabs
                .get_mut(tab_id)
                .ok_or_else(|| ControlError::NotFound(format!("tab {tab_id}")))?;
            tab.current_url = Some(url.clone());
            if request.session_id.is_some() {
                tab.session_id = request.session_id;
            }
            tab.updated_at_unix = now_unix();
            tab.clone()
        };
        queue_command_locked(
            &mut inner,
            BrowserCommand::navigate(tab_id, url),
            command_scope,
        );
        self.record_audit_locked(
            &mut inner,
            AuditEventKind::TabNavigated {
                tab_id: tab_id.to_string(),
                url: updated.current_url.clone().unwrap_or_default(),
                session_id: updated.session_id.clone(),
            },
        )?;
        Ok(updated)
    }

    pub fn go_back(&self, tab_id: &str) -> Result<BrowserCommand> {
        self.queue_tab_browser_command(tab_id, BrowserCommand::go_back(tab_id), |command| {
            AuditEventKind::TabHistoryNavigationQueued {
                command_id: command.id.clone(),
                tab_id: command.tab_id.clone(),
                direction: TabHistoryDirection::Back,
            }
        })
    }

    pub fn go_forward(&self, tab_id: &str) -> Result<BrowserCommand> {
        self.queue_tab_browser_command(tab_id, BrowserCommand::go_forward(tab_id), |command| {
            AuditEventKind::TabHistoryNavigationQueued {
                command_id: command.id.clone(),
                tab_id: command.tab_id.clone(),
                direction: TabHistoryDirection::Forward,
            }
        })
    }

    pub fn reload_tab(&self, tab_id: &str) -> Result<BrowserCommand> {
        self.queue_tab_browser_command(tab_id, BrowserCommand::reload(tab_id), |command| {
            AuditEventKind::TabReloadQueued {
                command_id: command.id.clone(),
                tab_id: command.tab_id.clone(),
            }
        })
    }

    pub fn store_credential(&self, request: CredentialInput) -> Result<CredentialRecord> {
        let record = self
            .vault
            .lock()
            .map_err(|_| ControlError::Server("credential vault lock poisoned".to_string()))?
            .put(request)?;
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| ControlError::Server("control state lock poisoned".to_string()))?;
        self.record_audit_locked(
            &mut inner,
            AuditEventKind::CredentialStored {
                credential_id: record.id.clone(),
                origin: record.origin.clone(),
                username: record.username.clone(),
                login_url: record.login_url.clone(),
                label: record.label.clone(),
            },
        )?;
        Ok(record)
    }

    pub fn list_credentials(&self) -> Result<Vec<CredentialRecord>> {
        Ok(self
            .vault
            .lock()
            .map_err(|_| ControlError::Server("credential vault lock poisoned".to_string()))?
            .list())
    }

    pub fn store_credential_for_tab(
        &self,
        tab_id: &str,
        request: StoreTabCredentialRequest,
    ) -> Result<CredentialRecord> {
        let current_url = self.current_url_for_tab(tab_id)?;
        let origin = WebOrigin::from_url_str(&current_url)?;
        let login_url = request.login_url.or(Some(current_url));
        self.store_credential(CredentialInput {
            origin: origin.display_url(),
            username: request.username,
            password: request.password,
            login_url,
            label: request.label,
        })
    }

    pub fn list_credentials_for_tab(&self, tab_id: &str) -> Result<Vec<CredentialRecord>> {
        let current_url = self.current_url_for_tab(tab_id)?;
        let mut credentials = self
            .vault
            .lock()
            .map_err(|_| ControlError::Server("credential vault lock poisoned".to_string()))?
            .list_for_url(&current_url)?;
        credentials.sort_by(|left, right| {
            right
                .updated_at_unix
                .cmp(&left.updated_at_unix)
                .then_with(|| left.username.cmp(&right.username))
        });
        Ok(credentials)
    }

    pub fn list_login_options(
        &self,
        tab_id: &str,
        request: ListLoginOptionsRequest,
    ) -> Result<Vec<CredentialRecord>> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| ControlError::Server("control state lock poisoned".to_string()))?;
        let session = inner
            .sessions
            .get(&request.session_id)
            .cloned()
            .ok_or_else(|| TelescopeError::SessionNotFound(request.session_id.clone()))?;
        let tab = inner
            .tabs
            .get(tab_id)
            .cloned()
            .ok_or_else(|| ControlError::NotFound(format!("tab {tab_id}")))?;
        let target_url = tab
            .current_url
            .as_deref()
            .ok_or_else(|| ControlError::BadRequest("tab has no current URL".to_string()))?;
        let target_origin = session.assert_allows_url(target_url)?;
        if !session.policy.allow_credentials {
            return Err(TelescopeError::PolicyDenied(format!(
                "session `{}` cannot use credentials",
                session.id
            ))
            .into());
        }

        let mut credentials = self
            .vault
            .lock()
            .map_err(|_| ControlError::Server("credential vault lock poisoned".to_string()))?
            .list_for_url(target_url)?;
        credentials.sort_by(|left, right| {
            right
                .updated_at_unix
                .cmp(&left.updated_at_unix)
                .then_with(|| left.username.cmp(&right.username))
        });
        self.record_audit_locked(
            &mut inner,
            AuditEventKind::LoginOptionsListed {
                tab_id: tab_id.to_string(),
                session_id: session.id,
                target_origin,
                count: credentials.len(),
            },
        )?;
        Ok(credentials)
    }

    pub fn delete_credential(&self, credential_id: &str) -> Result<()> {
        self.vault
            .lock()
            .map_err(|_| ControlError::Server("credential vault lock poisoned".to_string()))?
            .delete(credential_id)?;
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| ControlError::Server("control state lock poisoned".to_string()))?;
        self.record_audit_locked(
            &mut inner,
            AuditEventKind::CredentialDeleted {
                credential_id: credential_id.to_string(),
            },
        )?;
        Ok(())
    }

    pub fn delete_credential_for_tab(&self, tab_id: &str, credential_id: &str) -> Result<()> {
        let target_url = self.current_url_for_tab(tab_id)?;
        let record = self
            .vault
            .lock()
            .map_err(|_| ControlError::Server("credential vault lock poisoned".to_string()))?
            .get_record(credential_id)?;
        if !record.origin.matches_url(&target_url)? {
            return Err(TelescopeError::PolicyDenied(format!(
                "credential `{credential_id}` is for `{}`, not tab URL `{target_url}`",
                record.origin
            ))
            .into());
        }

        self.delete_credential(credential_id)
    }

    pub fn credential_material_for_browser(
        &self,
        credential_id: &str,
    ) -> Result<BrowserCredentialMaterial> {
        Ok(self
            .vault
            .lock()
            .map_err(|_| ControlError::Server("credential vault lock poisoned".to_string()))?
            .material_for_browser(credential_id)?)
    }

    pub fn fill_login(&self, tab_id: &str, request: FillLoginRequest) -> Result<BrowserCommand> {
        self.fill_login_inner(tab_id, request, None)
    }

    fn fill_login_inner(
        &self,
        tab_id: &str,
        request: FillLoginRequest,
        grant_token: Option<&str>,
    ) -> Result<BrowserCommand> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| ControlError::Server("control state lock poisoned".to_string()))?;
        let session = inner
            .sessions
            .get(&request.session_id)
            .cloned()
            .ok_or_else(|| TelescopeError::SessionNotFound(request.session_id.clone()))?;
        let tab = inner
            .tabs
            .get(tab_id)
            .cloned()
            .ok_or_else(|| ControlError::NotFound(format!("tab {tab_id}")))?;
        let target_url = tab
            .current_url
            .as_deref()
            .ok_or_else(|| ControlError::BadRequest("tab has no current URL".to_string()))?;
        let record = self
            .vault
            .lock()
            .map_err(|_| ControlError::Server("credential vault lock poisoned".to_string()))?
            .get_record(&request.credential_id)?;

        session.assert_can_fill_credential(&record, target_url)?;
        let session_id = request.session_id.clone();
        let command = BrowserCommand::fill_login(tab_id, record.id, record.username, record.origin);
        if let BrowserCommandKind::FillLogin {
            credential_id,
            username,
            target_origin,
        } = &command.kind
        {
            queue_command_locked(
                &mut inner,
                command.clone(),
                CommandScope::session(session_id.clone(), Some(target_origin.clone()))
                    .with_grant_token(grant_token),
            );
            self.record_audit_locked(
                &mut inner,
                AuditEventKind::CredentialFillQueued {
                    command_id: command.id.clone(),
                    tab_id: tab_id.to_string(),
                    session_id: Some(session_id),
                    credential_id: credential_id.clone(),
                    username: username.clone(),
                    target_origin: target_origin.clone(),
                },
            )?;
        }
        Ok(command)
    }

    pub fn fill_credential_for_tab(
        &self,
        tab_id: &str,
        credential_id: &str,
    ) -> Result<BrowserCommand> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| ControlError::Server("control state lock poisoned".to_string()))?;
        let tab = inner
            .tabs
            .get(tab_id)
            .cloned()
            .ok_or_else(|| ControlError::NotFound(format!("tab {tab_id}")))?;
        let target_url = tab
            .current_url
            .as_deref()
            .ok_or_else(|| ControlError::BadRequest("tab has no current URL".to_string()))?;
        let record = self
            .vault
            .lock()
            .map_err(|_| ControlError::Server("credential vault lock poisoned".to_string()))?
            .get_record(credential_id)?;

        if !record.origin.matches_url(target_url)? {
            return Err(TelescopeError::PolicyDenied(format!(
                "credential `{credential_id}` is for `{}`, not tab URL `{target_url}`",
                record.origin
            ))
            .into());
        }

        let command = BrowserCommand::fill_login(tab_id, record.id, record.username, record.origin);
        if let BrowserCommandKind::FillLogin {
            credential_id,
            username,
            target_origin,
        } = &command.kind
        {
            queue_command_locked(
                &mut inner,
                command.clone(),
                CommandScope::owner_with_origin(target_origin.clone()),
            );
            self.record_audit_locked(
                &mut inner,
                AuditEventKind::CredentialFillQueued {
                    command_id: command.id.clone(),
                    tab_id: tab_id.to_string(),
                    session_id: None,
                    credential_id: credential_id.clone(),
                    username: username.clone(),
                    target_origin: target_origin.clone(),
                },
            )?;
        }
        Ok(command)
    }

    pub fn queue_agent_action(
        &self,
        tab_id: &str,
        request: AgentActionRequest,
    ) -> Result<BrowserCommand> {
        self.queue_agent_action_inner(tab_id, request, None)
    }

    fn queue_agent_action_inner(
        &self,
        tab_id: &str,
        request: AgentActionRequest,
        grant_token: Option<&str>,
    ) -> Result<BrowserCommand> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| ControlError::Server("control state lock poisoned".to_string()))?;
        let tab = inner
            .tabs
            .get(tab_id)
            .cloned()
            .ok_or_else(|| ControlError::NotFound(format!("tab {tab_id}")))?;
        let target_url = tab
            .current_url
            .as_deref()
            .ok_or_else(|| ControlError::BadRequest("tab has no current URL".to_string()))?;
        let session = inner
            .sessions
            .get(&request.session_id)
            .cloned()
            .ok_or_else(|| TelescopeError::SessionNotFound(request.session_id.clone()))?;
        let target_origin = session.assert_allows_url(target_url)?;

        if request.action.requires_interaction_permission() {
            session.assert_can_interact()?;
        }

        if request.action.requires_script_permission() && !session.policy.allow_scripts {
            return Err(TelescopeError::PolicyDenied(format!(
                "session `{}` cannot execute custom scripts",
                session.id
            ))
            .into());
        }

        let action =
            resolve_action_targets(tab_id, &target_origin, &inner.element_refs, request.action)?;
        let audit_action = action.audit_summary();
        let session_id = session.id.clone();
        let command = BrowserCommand::agent_action(tab_id, action, target_origin.clone());
        queue_command_locked(
            &mut inner,
            command.clone(),
            CommandScope::session(session_id.clone(), Some(target_origin.clone()))
                .with_grant_token(grant_token),
        );
        self.record_audit_locked(
            &mut inner,
            AuditEventKind::AgentActionQueued {
                command_id: command.id.clone(),
                tab_id: tab_id.to_string(),
                session_id,
                target_origin,
                action: audit_action,
            },
        )?;
        Ok(command)
    }

    pub fn publish_page_context(&self, request: PageContextRequest) -> Result<PageContextSnapshot> {
        WebOrigin::from_url_str(&request.url)?;
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| ControlError::Server("control state lock poisoned".to_string()))?;
        let observed_at_unix = now_unix();

        let snapshot = PageContextSnapshot {
            tab_id: request.tab_id,
            url: request.url,
            title: request.title,
            text_preview: request.text_preview,
            selected_element_id: request.selected_element_id,
            interactive_elements: sanitize_page_interactive_elements(request.interactive_elements),
            captured_at_unix: observed_at_unix,
        };
        let tab = inner
            .tabs
            .get_mut(&snapshot.tab_id)
            .ok_or_else(|| ControlError::NotFound(format!("tab {}", snapshot.tab_id)))?;
        tab.current_url = Some(snapshot.url.clone());
        tab.title = snapshot.title.clone();
        tab.updated_at_unix = observed_at_unix;
        inner
            .page_contexts
            .insert(snapshot.tab_id.clone(), snapshot.clone());
        Ok(snapshot)
    }

    pub fn list_page_contexts(&self) -> Result<Vec<PageContextSnapshot>> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| ControlError::Server("control state lock poisoned".to_string()))?
            .page_contexts
            .values()
            .cloned()
            .collect())
    }

    pub fn record_element_reference(
        &self,
        request: ElementReferenceInput,
    ) -> Result<ElementReference> {
        WebOrigin::from_url_str(&request.url)?;
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| ControlError::Server("control state lock poisoned".to_string()))?;
        if !inner.tabs.contains_key(&request.tab_id) {
            return Err(ControlError::NotFound(format!("tab {}", request.tab_id)));
        }

        let reference = ElementReference {
            id: Uuid::new_v4().to_string(),
            tab_id: request.tab_id,
            url: request.url,
            selector: request.selector,
            label: request.label,
            role: request.role,
            text: request.text,
            bounds: request.bounds,
            created_at_unix: now_unix(),
        };
        inner
            .element_refs
            .insert(reference.id.clone(), reference.clone());
        Ok(reference)
    }

    pub fn list_element_references(&self) -> Result<Vec<ElementReference>> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| ControlError::Server("control state lock poisoned".to_string()))?
            .element_refs
            .values()
            .cloned()
            .collect())
    }

    fn agent_grant_allows_element_reference(
        &self,
        grant: &AgentGrant,
        reference: &ElementReference,
    ) -> Result<bool> {
        grant.assert_active()?;
        if !grant.allowed_tab_ids.is_empty()
            && !grant
                .allowed_tab_ids
                .iter()
                .any(|item| item == &reference.tab_id)
        {
            return Ok(false);
        }

        let inner = self
            .inner
            .lock()
            .map_err(|_| ControlError::Server("control state lock poisoned".to_string()))?;
        let Some(tab) = inner.tabs.get(&reference.tab_id) else {
            return Ok(false);
        };
        if tab.session_id.as_deref() != Some(&grant.session_id) {
            return Ok(false);
        }
        let Some(current_url) = tab.current_url.as_deref() else {
            return Ok(false);
        };
        let session = inner
            .sessions
            .get(&grant.session_id)
            .ok_or_else(|| TelescopeError::SessionNotFound(grant.session_id.clone()))?;
        let Ok(current_origin) = session.assert_allows_url(current_url) else {
            return Ok(false);
        };
        element_reference_matches_origin(reference, &current_origin)
    }

    fn agent_grant_allows_page_context(
        &self,
        grant: &AgentGrant,
        context: &PageContextSnapshot,
    ) -> Result<bool> {
        grant.assert_active()?;
        if !grant.allowed_tab_ids.is_empty()
            && !grant
                .allowed_tab_ids
                .iter()
                .any(|item| item == &context.tab_id)
        {
            return Ok(false);
        }

        let inner = self
            .inner
            .lock()
            .map_err(|_| ControlError::Server("control state lock poisoned".to_string()))?;
        let Some(tab) = inner.tabs.get(&context.tab_id) else {
            return Ok(false);
        };
        if tab.session_id.as_deref() != Some(&grant.session_id) {
            return Ok(false);
        }
        if tab.current_url.as_deref() != Some(context.url.as_str()) {
            return Ok(false);
        }
        let session = inner
            .sessions
            .get(&grant.session_id)
            .ok_or_else(|| TelescopeError::SessionNotFound(grant.session_id.clone()))?;
        Ok(session.assert_allows_url(&context.url).is_ok())
    }

    fn agent_grant_allows_command_result(
        &self,
        grant: &AgentGrant,
        result: &CommandExecutionReport,
    ) -> Result<bool> {
        grant.assert_active()?;
        if result.session_id.as_deref() != Some(&grant.session_id) {
            return Ok(false);
        }
        if result.grant_token.as_deref() != Some(grant.token.as_str()) {
            return Ok(false);
        }
        if !self.agent_grant_allows_tab(grant, &result.tab_id)? {
            return Ok(false);
        }
        let Some(target_origin) = &result.target_origin else {
            return Ok(true);
        };
        let inner = self
            .inner
            .lock()
            .map_err(|_| ControlError::Server("control state lock poisoned".to_string()))?;
        let session = inner
            .sessions
            .get(&grant.session_id)
            .ok_or_else(|| TelescopeError::SessionNotFound(grant.session_id.clone()))?;
        session.assert_active()?;
        Ok(session
            .policy
            .allowed_origins
            .iter()
            .any(|allowed_origin| allowed_origin == target_origin))
    }

    pub fn poll_commands(&self, tab_id: Option<&str>) -> Result<Vec<BrowserCommand>> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| ControlError::Server("control state lock poisoned".to_string()))?;
        let mut retained = VecDeque::new();
        let mut drained = Vec::new();

        while let Some(command) = inner.commands.pop_front() {
            if tab_id.is_none_or(|id| id == command.tab_id) {
                drained.push(command);
            } else {
                retained.push_back(command);
            }
        }

        inner.commands = retained;
        Ok(drained)
    }

    pub fn record_command_result(
        &self,
        command_id: &str,
        tab_id: &str,
        status: CommandExecutionStatus,
        message: Option<String>,
    ) -> Result<CommandExecutionReport> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| ControlError::Server("control state lock poisoned".to_string()))?;
        let scope = inner
            .command_scopes
            .remove(command_id)
            .unwrap_or_else(CommandScope::owner);
        let report = CommandExecutionReport {
            command_id: command_id.to_string(),
            tab_id: tab_id.to_string(),
            session_id: scope.session_id,
            target_origin: scope.target_origin,
            grant_token: scope.grant_token,
            status,
            message,
            completed_at_unix: now_unix(),
        };
        inner.command_results.push_back(report.clone());
        trim_command_results(&mut inner.command_results);
        self.record_audit_locked(
            &mut inner,
            AuditEventKind::CommandResultRecorded {
                command_id: report.command_id.clone(),
                tab_id: report.tab_id.clone(),
                session_id: report.session_id.clone(),
                target_origin: report.target_origin.clone(),
                status: report.status.clone(),
            },
        )?;
        Ok(report)
    }

    pub fn list_command_results(&self) -> Result<Vec<CommandExecutionReport>> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| ControlError::Server("control state lock poisoned".to_string()))?
            .command_results
            .iter()
            .cloned()
            .collect())
    }

    pub fn list_audit_events(&self) -> Result<Vec<AuditEvent>> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| ControlError::Server("control state lock poisoned".to_string()))?
            .audit_events
            .iter()
            .cloned()
            .collect())
    }

    pub fn handoff_snapshot(&self) -> Result<HandoffSnapshot> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| ControlError::Server("control state lock poisoned".to_string()))?;
        let active_tab = inner
            .active_tab_id
            .as_ref()
            .and_then(|tab_id| inner.tabs.get(tab_id))
            .cloned();
        let mut tabs = inner.tabs.values().cloned().collect::<Vec<_>>();
        tabs.sort_by(|left, right| {
            left.created_at_unix
                .cmp(&right.created_at_unix)
                .then_with(|| left.id.cmp(&right.id))
        });
        let mut bookmarks = inner.bookmarks.values().cloned().collect::<Vec<_>>();
        bookmarks.sort_by(|left, right| {
            right
                .updated_at_unix
                .cmp(&left.updated_at_unix)
                .then_with(|| left.url.cmp(&right.url))
        });
        let mut agent_panes = inner.agent_panes.values().cloned().collect::<Vec<_>>();
        agent_panes.sort_by(|left, right| {
            left.created_at_unix
                .cmp(&right.created_at_unix)
                .then_with(|| left.id.cmp(&right.id))
        });
        let mut page_contexts = inner.page_contexts.values().cloned().collect::<Vec<_>>();
        page_contexts.sort_by(|left, right| {
            left.captured_at_unix
                .cmp(&right.captured_at_unix)
                .then_with(|| left.tab_id.cmp(&right.tab_id))
        });
        let mut element_refs = inner.element_refs.values().cloned().collect::<Vec<_>>();
        element_refs.sort_by(|left, right| {
            left.created_at_unix
                .cmp(&right.created_at_unix)
                .then_with(|| left.id.cmp(&right.id))
        });

        Ok(HandoffSnapshot {
            generated_at_unix: now_unix(),
            active_tab,
            tabs,
            sessions: inner.sessions.values().cloned().collect(),
            bookmarks,
            agent_panes,
            page_contexts,
            element_refs,
            command_results: inner.command_results.iter().cloned().collect(),
            audit_events: inner.audit_events.iter().cloned().collect(),
        })
    }

    pub fn create_bookmark(&self, request: CreateBookmarkRequest) -> Result<BookmarkRecord> {
        let url = sanitize_bookmark_url(&request.url)?;
        let title = bounded_optional_string(request.title, 240);
        let now = now_unix();
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| ControlError::Server("control state lock poisoned".to_string()))?;

        let bookmark_id = inner
            .bookmarks
            .values()
            .find(|bookmark| bookmark.url == url)
            .map(|bookmark| bookmark.id.clone())
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        let bookmark = match inner.bookmarks.get(&bookmark_id).cloned() {
            Some(mut bookmark) => {
                bookmark.title = title.or(bookmark.title);
                bookmark.updated_at_unix = now;
                bookmark
            }
            None => BookmarkRecord {
                id: bookmark_id,
                url,
                title,
                created_at_unix: now,
                updated_at_unix: now,
            },
        };
        inner
            .bookmarks
            .insert(bookmark.id.clone(), bookmark.clone());
        self.persist_bookmarks_locked(&inner)?;
        Ok(bookmark)
    }

    pub fn list_bookmarks(&self) -> Result<Vec<BookmarkRecord>> {
        let mut bookmarks = self
            .inner
            .lock()
            .map_err(|_| ControlError::Server("control state lock poisoned".to_string()))?
            .bookmarks
            .values()
            .cloned()
            .collect::<Vec<_>>();
        bookmarks.sort_by(|left, right| {
            right
                .updated_at_unix
                .cmp(&left.updated_at_unix)
                .then_with(|| left.url.cmp(&right.url))
        });
        Ok(bookmarks)
    }

    pub fn delete_bookmark(&self, bookmark_id: &str) -> Result<BookmarkRecord> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| ControlError::Server("control state lock poisoned".to_string()))?;
        let bookmark = inner
            .bookmarks
            .remove(bookmark_id)
            .ok_or_else(|| ControlError::NotFound(format!("bookmark {bookmark_id}")))?;
        self.persist_bookmarks_locked(&inner)?;
        Ok(bookmark)
    }

    pub fn cleanup_expired_access(&self) -> Result<Vec<ExpiredAccessCleanup>> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| ControlError::Server("control state lock poisoned".to_string()))?;
        let now = now_unix();
        let expired_session_ids = inner
            .sessions
            .iter()
            .filter_map(|(session_id, session)| {
                (session
                    .policy
                    .expires_at_unix
                    .is_some_and(|expires_at| now >= expires_at))
                .then(|| session_id.clone())
            })
            .collect::<Vec<_>>();
        let mut cleanups = Vec::new();

        for session_id in expired_session_ids {
            if inner.sessions.contains_key(&session_id) {
                cleanups.push(ExpiredAccessCleanup::Session(
                    self.revoke_session_locked(&mut inner, &session_id)?,
                ));
            }
        }

        let expired_grant_tokens = inner
            .agent_grants
            .iter()
            .filter_map(|(token, grant)| {
                (grant
                    .expires_at_unix
                    .is_some_and(|expires_at| now >= expires_at))
                .then(|| token.clone())
            })
            .collect::<Vec<_>>();

        for token in expired_grant_tokens {
            if inner.agent_grants.contains_key(&token) {
                cleanups.push(ExpiredAccessCleanup::Grant(
                    self.revoke_agent_grant_locked(&mut inner, &token)?,
                ));
            }
        }

        Ok(cleanups)
    }

    fn revoke_session_locked(
        &self,
        inner: &mut InnerState,
        session_id: &str,
    ) -> Result<RevokedAgentSession> {
        inner
            .sessions
            .remove(session_id)
            .ok_or_else(|| TelescopeError::SessionNotFound(session_id.to_string()))?;

        let revoked_grant_tokens = inner
            .agent_grants
            .iter()
            .filter_map(|(token, grant)| (grant.session_id == session_id).then(|| token.clone()))
            .collect::<Vec<_>>();
        for token in &revoked_grant_tokens {
            inner.agent_grants.remove(token);
        }

        let mut pane_ids = inner
            .agent_panes
            .iter()
            .filter_map(|(pane_id, pane)| {
                (pane.session_id.as_deref() == Some(session_id)).then(|| pane_id.clone())
            })
            .collect::<BTreeSet<_>>();
        pane_ids.extend(
            inner
                .agent_pane_connections
                .iter()
                .filter_map(|(pane_id, connection)| {
                    (connection.session_id == session_id).then(|| pane_id.clone())
                }),
        );

        let detached_tab_ids = inner
            .tabs
            .iter_mut()
            .filter_map(|(tab_id, tab)| {
                if tab.session_id.as_deref() == Some(session_id) {
                    tab.session_id = None;
                    tab.updated_at_unix = now_unix();
                    Some(tab_id.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        let purged_command_ids = purge_pending_session_commands_locked(inner, session_id);

        let mut closed_pane_ids = Vec::new();
        for pane_id in pane_ids {
            inner.agent_pane_connections.remove(&pane_id);
            if let Some(pane) = inner.agent_panes.remove(&pane_id) {
                let command_tab_id = pane
                    .attached_tab_id
                    .clone()
                    .unwrap_or_else(|| pane.id.clone());
                queue_command_locked(
                    inner,
                    BrowserCommand::close_agent_pane(&command_tab_id, &pane.id),
                    CommandScope::owner(),
                );
                closed_pane_ids.push(pane.id);
            }
        }

        self.record_audit_locked(
            inner,
            AuditEventKind::SessionRevoked {
                session_id: session_id.to_string(),
                revoked_grant_count: revoked_grant_tokens.len(),
                closed_pane_ids: closed_pane_ids.clone(),
                detached_tab_ids: detached_tab_ids.clone(),
                purged_command_ids: purged_command_ids.clone(),
            },
        )?;

        Ok(RevokedAgentSession {
            session_id: session_id.to_string(),
            revoked_grant_count: revoked_grant_tokens.len(),
            closed_pane_ids,
            detached_tab_ids,
            purged_command_ids,
        })
    }

    fn revoke_agent_grant_locked(
        &self,
        inner: &mut InnerState,
        token: &str,
    ) -> Result<RevokedAgentGrant> {
        let grant = inner
            .agent_grants
            .remove(token)
            .ok_or_else(|| ControlError::NotFound(format!("agent grant {token}")))?;
        let pane_ids = inner
            .agent_pane_connections
            .iter()
            .filter_map(|(pane_id, connection)| {
                (connection.grant_token == grant.token).then(|| pane_id.clone())
            })
            .collect::<Vec<_>>();
        let purged_command_ids = purge_pending_grant_commands_locked(inner, &grant.token);
        let mut closed_pane_ids = Vec::new();

        for pane_id in pane_ids {
            inner.agent_pane_connections.remove(&pane_id);
            if let Some(pane) = inner.agent_panes.remove(&pane_id) {
                let command_tab_id = pane
                    .attached_tab_id
                    .clone()
                    .unwrap_or_else(|| pane.id.clone());
                let command = BrowserCommand::close_agent_pane(&command_tab_id, &pane.id);
                let scope = pane
                    .session_id
                    .clone()
                    .map(|session_id| CommandScope::session(session_id, None))
                    .unwrap_or_else(CommandScope::owner);
                queue_command_locked(inner, command, scope);
                closed_pane_ids.push(pane.id);
            }
        }

        self.record_audit_locked(
            inner,
            AuditEventKind::AgentGrantRevoked {
                session_id: grant.session_id.clone(),
                closed_pane_ids: closed_pane_ids.clone(),
                purged_command_ids: purged_command_ids.clone(),
            },
        )?;

        Ok(RevokedAgentGrant {
            token: grant.token,
            closed_pane_ids,
            purged_command_ids,
        })
    }

    fn record_audit_locked(
        &self,
        inner: &mut InnerState,
        kind: AuditEventKind,
    ) -> Result<AuditEvent> {
        let event = AuditEvent {
            id: Uuid::new_v4().to_string(),
            created_at_unix: now_unix(),
            kind,
        };
        inner.audit_events.push_back(event.clone());
        trim_audit_events(&mut inner.audit_events);

        if let Some(path) = &self.audit_path {
            let mut file = open_private_append_file(path)?;
            serde_json::to_writer(&mut file, &event)?;
            file.write_all(b"\n")?;
        }

        Ok(event)
    }

    fn persist_bookmarks_locked(&self, inner: &InnerState) -> Result<()> {
        if let Some(path) = &self.bookmark_path {
            save_bookmarks(path, inner.bookmarks.values().cloned().collect())?;
        }
        Ok(())
    }

    fn queue_tab_browser_command(
        &self,
        tab_id: &str,
        command: BrowserCommand,
        audit_kind: impl FnOnce(&BrowserCommand) -> AuditEventKind,
    ) -> Result<BrowserCommand> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| ControlError::Server("control state lock poisoned".to_string()))?;
        if !inner.tabs.contains_key(tab_id) {
            return Err(ControlError::NotFound(format!("tab {tab_id}")));
        }
        queue_command_locked(&mut inner, command.clone(), CommandScope::owner());
        self.record_audit_locked(&mut inner, audit_kind(&command))?;
        Ok(command)
    }

    fn get_session_locked(&self, session_id: &str) -> Result<AgentSession> {
        self.inner
            .lock()
            .map_err(|_| ControlError::Server("control state lock poisoned".to_string()))?
            .sessions
            .get(session_id)
            .cloned()
            .ok_or_else(|| TelescopeError::SessionNotFound(session_id.to_string()).into())
    }

    fn current_url_for_tab(&self, tab_id: &str) -> Result<String> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| ControlError::Server("control state lock poisoned".to_string()))?;
        let tab = inner
            .tabs
            .get(tab_id)
            .ok_or_else(|| ControlError::NotFound(format!("tab {tab_id}")))?;
        tab.current_url
            .clone()
            .ok_or_else(|| ControlError::BadRequest("tab has no current URL".to_string()))
    }

    fn prepare_scoped_agent_pane_session(
        &self,
        request: &OpenScopedAgentPaneRequest,
        pane_origin: WebOrigin,
    ) -> Result<(String, AgentSession, AgentGrant)> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| ControlError::Server("control state lock poisoned".to_string()))?;
        let tab_id = match &request.tab_id {
            Some(tab_id) => tab_id.clone(),
            None => inner
                .active_tab_id
                .clone()
                .ok_or_else(|| ControlError::BadRequest("no active tab".to_string()))?,
        };
        let tab = inner
            .tabs
            .get(&tab_id)
            .cloned()
            .ok_or_else(|| ControlError::NotFound(format!("tab {tab_id}")))?;
        let current_url = tab
            .current_url
            .clone()
            .ok_or_else(|| ControlError::BadRequest("tab has no current URL".to_string()))?;
        let page_origin = WebOrigin::from_url_str(&current_url)?;

        let reusable_session = tab
            .session_id
            .as_ref()
            .and_then(|session_id| inner.sessions.get(session_id))
            .filter(|session| {
                session.assert_allows_url(&current_url).is_ok()
                    && session.policy.allow_credentials == request.allow_credentials
                    && session.policy.allow_interactions == request.allow_interactions
                    && session.policy.allow_scripts == request.allow_scripts
            })
            .cloned();
        let session = match reusable_session {
            Some(session) => session,
            None => {
                let mut policy = AgentPolicy::new(vec![page_origin]);
                policy.allow_credentials = request.allow_credentials;
                policy.allow_interactions = request.allow_interactions;
                policy.allow_scripts = request.allow_scripts;
                if let Some(ttl_seconds) = request.ttl_seconds {
                    policy.expires_at_unix = Some(now_unix() + ttl_seconds);
                }
                let session = AgentSession::new(policy);
                inner.sessions.insert(session.id.clone(), session.clone());
                let tab = inner
                    .tabs
                    .get_mut(&tab_id)
                    .ok_or_else(|| ControlError::NotFound(format!("tab {tab_id}")))?;
                tab.session_id = Some(session.id.clone());
                tab.updated_at_unix = now_unix();
                self.record_audit_locked(
                    &mut inner,
                    AuditEventKind::SessionCreated {
                        session_id: session.id.clone(),
                        allowed_origins: session.policy.allowed_origins.clone(),
                        allow_credentials: session.policy.allow_credentials,
                        allow_interactions: session.policy.allow_interactions,
                        allow_scripts: session.policy.allow_scripts,
                        expires_at_unix: session.policy.expires_at_unix,
                    },
                )?;
                session
            }
        };

        let created_at_unix = now_unix();
        let grant = AgentGrant {
            token: format!("tg_{}", Uuid::new_v4().simple()),
            session_id: session.id.clone(),
            allowed_tab_ids: vec![tab_id.clone()],
            allowed_client_origins: vec![pane_origin],
            created_at_unix,
            expires_at_unix: request
                .ttl_seconds
                .map(|ttl_seconds| created_at_unix + ttl_seconds),
        };
        inner
            .agent_grants
            .insert(grant.token.clone(), grant.clone());
        self.record_audit_locked(
            &mut inner,
            AuditEventKind::AgentGrantCreated {
                session_id: grant.session_id.clone(),
                allowed_tab_ids: grant.allowed_tab_ids.clone(),
                allowed_client_origins: grant.allowed_client_origins.clone(),
                expires_at_unix: grant.expires_at_unix,
            },
        )?;
        Ok((tab_id, session, grant))
    }
}

fn trim_command_results(results: &mut VecDeque<CommandExecutionReport>) {
    const MAX_COMMAND_RESULTS: usize = 500;
    while results.len() > MAX_COMMAND_RESULTS {
        results.pop_front();
    }
}

fn trim_audit_events(events: &mut VecDeque<AuditEvent>) {
    const MAX_AUDIT_EVENTS: usize = 1_000;
    while events.len() > MAX_AUDIT_EVENTS {
        events.pop_front();
    }
}

fn sanitize_page_interactive_elements(
    elements: Vec<PageInteractiveElement>,
) -> Vec<PageInteractiveElement> {
    const MAX_INTERACTIVE_ELEMENTS: usize = 80;
    const MAX_SELECTOR_CHARS: usize = 512;
    const MAX_TAG_CHARS: usize = 64;
    const MAX_ROLE_CHARS: usize = 80;
    const MAX_LABEL_CHARS: usize = 240;
    const MAX_TEXT_CHARS: usize = 240;
    const MAX_INPUT_TYPE_CHARS: usize = 40;

    elements
        .into_iter()
        .filter_map(|element| {
            let selector = truncate_string(element.selector, MAX_SELECTOR_CHARS);
            if selector.trim().is_empty() {
                return None;
            }

            let input_type = bounded_optional_string(element.input_type, MAX_INPUT_TYPE_CHARS);
            let mut text = bounded_optional_string(element.text, MAX_TEXT_CHARS);
            if input_type.as_deref() == Some("password") {
                text = None;
            }

            Some(PageInteractiveElement {
                selector,
                tag_name: truncate_string(element.tag_name, MAX_TAG_CHARS),
                role: bounded_optional_string(element.role, MAX_ROLE_CHARS),
                label: bounded_optional_string(element.label, MAX_LABEL_CHARS),
                text,
                input_type,
                bounds: element.bounds,
                disabled: element.disabled,
            })
        })
        .take(MAX_INTERACTIVE_ELEMENTS)
        .collect()
}

fn bounded_optional_string(input: Option<String>, max_chars: usize) -> Option<String> {
    input.and_then(|value| {
        let value = truncate_string(value.trim().to_string(), max_chars);
        (!value.is_empty()).then_some(value)
    })
}

fn truncate_string(input: String, max_chars: usize) -> String {
    if input.chars().count() <= max_chars {
        return input;
    }
    input.chars().take(max_chars).collect()
}

fn sanitize_bookmark_url(url: &str) -> Result<String> {
    let url = url.trim();
    if url.is_empty() {
        return Err(ControlError::BadRequest(
            "bookmark URL cannot be empty".to_string(),
        ));
    }
    WebOrigin::from_url_str(url)?;
    Ok(url.to_string())
}

fn sanitize_browser_tab_url(url: &str) -> Result<String> {
    let url = url.trim();
    if url.is_empty() {
        return Err(ControlError::BadRequest(
            "browser tab URL cannot be empty".to_string(),
        ));
    }
    if url == "about:blank" {
        return Ok(url.to_string());
    }
    WebOrigin::from_url_str(url)?;
    Ok(url.to_string())
}

fn load_bookmarks(path: &Path) -> Result<BTreeMap<String, BookmarkRecord>> {
    if !path.exists() {
        return Ok(BTreeMap::new());
    }

    let file = fs::read_to_string(path)?;
    let store = serde_json::from_str::<BookmarkStore>(&file)?;
    if store.version != BOOKMARK_STORE_VERSION {
        return Err(ControlError::BadRequest(format!(
            "unsupported bookmark store version {}",
            store.version
        )));
    }
    Ok(store
        .bookmarks
        .into_iter()
        .map(|bookmark| (bookmark.id.clone(), bookmark))
        .collect())
}

fn save_bookmarks(path: &Path, mut bookmarks: Vec<BookmarkRecord>) -> Result<()> {
    bookmarks.sort_by(|left, right| {
        right
            .updated_at_unix
            .cmp(&left.updated_at_unix)
            .then_with(|| left.url.cmp(&right.url))
    });
    let store = BookmarkStore {
        version: BOOKMARK_STORE_VERSION,
        bookmarks,
    };
    write_private_json_file(path, &store)
}

fn write_private_json_file<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let body = serde_json::to_vec_pretty(value)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(&body)?;
        file.sync_all()?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }

    #[cfg(not(unix))]
    {
        fs::write(path, body)?;
    }

    Ok(())
}

fn load_audit_events(path: &Path) -> Result<VecDeque<AuditEvent>> {
    if !path.exists() {
        return Ok(VecDeque::new());
    }

    let file = fs::File::open(path)?;
    let reader = std::io::BufReader::new(file);
    let mut events = VecDeque::new();
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        events.push_back(serde_json::from_str(&line)?);
        trim_audit_events(&mut events);
    }
    Ok(events)
}

fn open_private_append_file(path: &Path) -> Result<fs::File> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        Ok(file)
    }

    #[cfg(not(unix))]
    {
        Ok(OpenOptions::new().create(true).append(true).open(path)?)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvent {
    pub id: String,
    pub created_at_unix: u64,
    pub kind: AuditEventKind,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuditEventKind {
    SessionCreated {
        session_id: String,
        allowed_origins: Vec<WebOrigin>,
        allow_credentials: bool,
        allow_interactions: bool,
        allow_scripts: bool,
        expires_at_unix: Option<u64>,
    },
    SessionRevoked {
        session_id: String,
        revoked_grant_count: usize,
        closed_pane_ids: Vec<String>,
        detached_tab_ids: Vec<String>,
        purged_command_ids: Vec<String>,
    },
    AgentGrantCreated {
        session_id: String,
        allowed_tab_ids: Vec<String>,
        allowed_client_origins: Vec<WebOrigin>,
        expires_at_unix: Option<u64>,
    },
    AgentGrantRevoked {
        session_id: String,
        closed_pane_ids: Vec<String>,
        #[serde(default)]
        purged_command_ids: Vec<String>,
    },
    TabCreated {
        tab_id: String,
        url: Option<String>,
        session_id: Option<String>,
        queued_browser_open: bool,
    },
    TabActivated {
        tab_id: String,
    },
    TabNavigated {
        tab_id: String,
        url: String,
        session_id: Option<String>,
    },
    TabHistoryNavigationQueued {
        command_id: String,
        tab_id: String,
        direction: TabHistoryDirection,
    },
    TabReloadQueued {
        command_id: String,
        tab_id: String,
    },
    TabClosed {
        tab_id: String,
        closed_pane_ids: Vec<String>,
    },
    CredentialStored {
        credential_id: String,
        origin: WebOrigin,
        username: String,
        login_url: Option<String>,
        label: Option<String>,
    },
    CredentialDeleted {
        credential_id: String,
    },
    CredentialFillQueued {
        command_id: String,
        tab_id: String,
        session_id: Option<String>,
        credential_id: String,
        username: String,
        target_origin: WebOrigin,
    },
    LoginOptionsListed {
        tab_id: String,
        session_id: String,
        target_origin: WebOrigin,
        count: usize,
    },
    AgentActionQueued {
        command_id: String,
        tab_id: String,
        session_id: String,
        target_origin: WebOrigin,
        action: AgentActionAudit,
    },
    AgentPaneOpened {
        pane_id: String,
        url: String,
        position: PanePosition,
        attached_tab_id: Option<String>,
        session_id: Option<String>,
        scoped_connection: bool,
    },
    AgentPaneClosed {
        pane_id: String,
        attached_tab_id: Option<String>,
        session_id: Option<String>,
    },
    CommandResultRecorded {
        command_id: String,
        tab_id: String,
        session_id: Option<String>,
        target_origin: Option<WebOrigin>,
        status: CommandExecutionStatus,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TabHistoryDirection {
    Back,
    Forward,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentActionAudit {
    Click {
        selector: Option<String>,
        element_ref_id: Option<String>,
    },
    DoubleClick {
        selector: Option<String>,
        element_ref_id: Option<String>,
    },
    DragTo {
        source_selector: Option<String>,
        source_element_ref_id: Option<String>,
        target_selector: Option<String>,
        target_element_ref_id: Option<String>,
    },
    Hover {
        selector: Option<String>,
        element_ref_id: Option<String>,
    },
    Focus {
        selector: Option<String>,
        element_ref_id: Option<String>,
    },
    TypeText {
        selector: Option<String>,
        element_ref_id: Option<String>,
        clear_first: bool,
    },
    SelectOption {
        selector: Option<String>,
        element_ref_id: Option<String>,
    },
    SetChecked {
        selector: Option<String>,
        element_ref_id: Option<String>,
        checked: bool,
    },
    ScrollBy {
        delta_x: i32,
        delta_y: i32,
    },
    ScrollIntoView {
        selector: Option<String>,
        element_ref_id: Option<String>,
    },
    PressKey {
        key: String,
    },
    Submit {
        selector: Option<String>,
        element_ref_id: Option<String>,
    },
    WaitForSelector {
        selector: String,
        timeout_ms: Option<u64>,
    },
    ExtractText {
        selector: Option<String>,
        element_ref_id: Option<String>,
    },
    InspectElement {
        selector: Option<String>,
        element_ref_id: Option<String>,
    },
    StartElementPicker,
    ExecuteScript,
}

const BOOKMARK_STORE_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct BookmarkStore {
    version: u32,
    bookmarks: Vec<BookmarkRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BookmarkRecord {
    pub id: String,
    pub url: String,
    pub title: Option<String>,
    pub created_at_unix: u64,
    pub updated_at_unix: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct HandoffSnapshot {
    pub generated_at_unix: u64,
    pub active_tab: Option<TabState>,
    pub tabs: Vec<TabState>,
    pub sessions: Vec<AgentSession>,
    pub bookmarks: Vec<BookmarkRecord>,
    pub agent_panes: Vec<AgentPaneState>,
    pub page_contexts: Vec<PageContextSnapshot>,
    pub element_refs: Vec<ElementReference>,
    pub command_results: Vec<CommandExecutionReport>,
    pub audit_events: Vec<AuditEvent>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateBookmarkRequest {
    pub url: String,
    pub title: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateSessionRequest {
    pub allowed_origins: Vec<String>,
    #[serde(default)]
    pub allow_credentials: bool,
    #[serde(default = "default_true")]
    pub allow_interactions: bool,
    #[serde(default)]
    pub allow_scripts: bool,
    pub ttl_seconds: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevokedAgentSession {
    pub session_id: String,
    pub revoked_grant_count: usize,
    pub closed_pane_ids: Vec<String>,
    pub detached_tab_ids: Vec<String>,
    pub purged_command_ids: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ExpiredAccessCleanup {
    Session(RevokedAgentSession),
    Grant(RevokedAgentGrant),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateAgentGrantRequest {
    pub session_id: String,
    #[serde(default)]
    pub allowed_tab_ids: Vec<String>,
    #[serde(default)]
    pub allowed_client_origins: Vec<String>,
    pub ttl_seconds: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentGrant {
    pub token: String,
    pub session_id: String,
    pub allowed_tab_ids: Vec<String>,
    pub allowed_client_origins: Vec<WebOrigin>,
    pub created_at_unix: u64,
    pub expires_at_unix: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevokedAgentGrant {
    pub token: String,
    pub closed_pane_ids: Vec<String>,
    pub purged_command_ids: Vec<String>,
}

impl AgentGrant {
    fn assert_active(&self) -> Result<()> {
        if let Some(expires_at_unix) = self.expires_at_unix {
            if now_unix() >= expires_at_unix {
                return Err(TelescopeError::PolicyDenied(format!(
                    "agent grant for session `{}` is expired",
                    self.session_id
                ))
                .into());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateTabRequest {
    pub url: Option<String>,
    pub session_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NavigateRequest {
    pub url: String,
    pub session_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FillLoginRequest {
    pub session_id: String,
    pub credential_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListLoginOptionsRequest {
    pub session_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoreTabCredentialRequest {
    pub username: String,
    pub password: String,
    pub login_url: Option<String>,
    pub label: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentActionRequest {
    pub session_id: String,
    pub action: AgentAction,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentAction {
    Click {
        selector: Option<String>,
        element_ref_id: Option<String>,
    },
    DoubleClick {
        selector: Option<String>,
        element_ref_id: Option<String>,
    },
    DragTo {
        source_selector: Option<String>,
        source_element_ref_id: Option<String>,
        target_selector: Option<String>,
        target_element_ref_id: Option<String>,
    },
    Hover {
        selector: Option<String>,
        element_ref_id: Option<String>,
    },
    Focus {
        selector: Option<String>,
        element_ref_id: Option<String>,
    },
    TypeText {
        selector: Option<String>,
        element_ref_id: Option<String>,
        text: String,
        #[serde(default)]
        clear_first: bool,
    },
    SelectOption {
        selector: Option<String>,
        element_ref_id: Option<String>,
        value: String,
    },
    SetChecked {
        selector: Option<String>,
        element_ref_id: Option<String>,
        checked: bool,
    },
    ScrollBy {
        delta_x: i32,
        delta_y: i32,
    },
    ScrollIntoView {
        selector: Option<String>,
        element_ref_id: Option<String>,
    },
    PressKey {
        key: String,
    },
    Submit {
        selector: Option<String>,
        element_ref_id: Option<String>,
    },
    WaitForSelector {
        selector: String,
        timeout_ms: Option<u64>,
    },
    ExtractText {
        selector: Option<String>,
        element_ref_id: Option<String>,
    },
    InspectElement {
        selector: Option<String>,
        element_ref_id: Option<String>,
    },
    StartElementPicker,
    ExecuteScript {
        script: String,
    },
}

impl AgentAction {
    fn requires_interaction_permission(&self) -> bool {
        matches!(
            self,
            Self::Click { .. }
                | Self::DoubleClick { .. }
                | Self::DragTo { .. }
                | Self::Hover { .. }
                | Self::Focus { .. }
                | Self::TypeText { .. }
                | Self::SelectOption { .. }
                | Self::SetChecked { .. }
                | Self::ScrollBy { .. }
                | Self::ScrollIntoView { .. }
                | Self::PressKey { .. }
                | Self::Submit { .. }
                | Self::StartElementPicker
        )
    }

    fn requires_script_permission(&self) -> bool {
        matches!(self, Self::ExecuteScript { .. })
    }

    fn audit_summary(&self) -> AgentActionAudit {
        match self {
            Self::Click {
                selector,
                element_ref_id,
            } => AgentActionAudit::Click {
                selector: selector.clone(),
                element_ref_id: element_ref_id.clone(),
            },
            Self::DoubleClick {
                selector,
                element_ref_id,
            } => AgentActionAudit::DoubleClick {
                selector: selector.clone(),
                element_ref_id: element_ref_id.clone(),
            },
            Self::DragTo {
                source_selector,
                source_element_ref_id,
                target_selector,
                target_element_ref_id,
            } => AgentActionAudit::DragTo {
                source_selector: source_selector.clone(),
                source_element_ref_id: source_element_ref_id.clone(),
                target_selector: target_selector.clone(),
                target_element_ref_id: target_element_ref_id.clone(),
            },
            Self::Hover {
                selector,
                element_ref_id,
            } => AgentActionAudit::Hover {
                selector: selector.clone(),
                element_ref_id: element_ref_id.clone(),
            },
            Self::Focus {
                selector,
                element_ref_id,
            } => AgentActionAudit::Focus {
                selector: selector.clone(),
                element_ref_id: element_ref_id.clone(),
            },
            Self::TypeText {
                selector,
                element_ref_id,
                clear_first,
                ..
            } => AgentActionAudit::TypeText {
                selector: selector.clone(),
                element_ref_id: element_ref_id.clone(),
                clear_first: *clear_first,
            },
            Self::SelectOption {
                selector,
                element_ref_id,
                ..
            } => AgentActionAudit::SelectOption {
                selector: selector.clone(),
                element_ref_id: element_ref_id.clone(),
            },
            Self::SetChecked {
                selector,
                element_ref_id,
                checked,
            } => AgentActionAudit::SetChecked {
                selector: selector.clone(),
                element_ref_id: element_ref_id.clone(),
                checked: *checked,
            },
            Self::ScrollBy { delta_x, delta_y } => AgentActionAudit::ScrollBy {
                delta_x: *delta_x,
                delta_y: *delta_y,
            },
            Self::ScrollIntoView {
                selector,
                element_ref_id,
            } => AgentActionAudit::ScrollIntoView {
                selector: selector.clone(),
                element_ref_id: element_ref_id.clone(),
            },
            Self::PressKey { key } => AgentActionAudit::PressKey { key: key.clone() },
            Self::Submit {
                selector,
                element_ref_id,
            } => AgentActionAudit::Submit {
                selector: selector.clone(),
                element_ref_id: element_ref_id.clone(),
            },
            Self::WaitForSelector {
                selector,
                timeout_ms,
            } => AgentActionAudit::WaitForSelector {
                selector: selector.clone(),
                timeout_ms: *timeout_ms,
            },
            Self::ExtractText {
                selector,
                element_ref_id,
            } => AgentActionAudit::ExtractText {
                selector: selector.clone(),
                element_ref_id: element_ref_id.clone(),
            },
            Self::InspectElement {
                selector,
                element_ref_id,
            } => AgentActionAudit::InspectElement {
                selector: selector.clone(),
                element_ref_id: element_ref_id.clone(),
            },
            Self::StartElementPicker => AgentActionAudit::StartElementPicker,
            Self::ExecuteScript { .. } => AgentActionAudit::ExecuteScript,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenAgentPaneRequest {
    pub url: String,
    pub position: PanePosition,
    pub attached_tab_id: Option<String>,
    pub session_id: Option<String>,
    #[serde(default)]
    pub agent_grant_token: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenScopedAgentPaneRequest {
    pub url: String,
    pub position: PanePosition,
    pub tab_id: Option<String>,
    #[serde(default = "default_true")]
    pub allow_credentials: bool,
    #[serde(default = "default_true")]
    pub allow_interactions: bool,
    #[serde(default)]
    pub allow_scripts: bool,
    pub ttl_seconds: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenedScopedAgentPane {
    pub session: AgentSession,
    pub grant: AgentGrant,
    pub pane: AgentPaneState,
    pub connection: AgentPaneConnection,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentPaneState {
    pub id: String,
    pub url: String,
    pub position: PanePosition,
    pub attached_tab_id: Option<String>,
    pub session_id: Option<String>,
    pub created_at_unix: u64,
    pub updated_at_unix: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentPaneConnection {
    pub pane_id: String,
    pub session_id: String,
    pub tab_id: String,
    pub grant_token: String,
    pub session_policy: AgentPolicy,
    pub created_at_unix: u64,
    pub expires_at_unix: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PanePosition {
    Left,
    Right,
    Bottom,
}

fn default_true() -> bool {
    true
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PageContextRequest {
    pub tab_id: String,
    pub url: String,
    pub title: Option<String>,
    pub text_preview: Option<String>,
    pub selected_element_id: Option<String>,
    #[serde(default)]
    pub interactive_elements: Vec<PageInteractiveElement>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PageContextSnapshot {
    pub tab_id: String,
    pub url: String,
    pub title: Option<String>,
    pub text_preview: Option<String>,
    pub selected_element_id: Option<String>,
    pub interactive_elements: Vec<PageInteractiveElement>,
    pub captured_at_unix: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PageInteractiveElement {
    pub selector: String,
    pub tag_name: String,
    pub role: Option<String>,
    pub label: Option<String>,
    pub text: Option<String>,
    pub input_type: Option<String>,
    pub bounds: Option<ElementBounds>,
    #[serde(default)]
    pub disabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ElementReferenceInput {
    pub tab_id: String,
    pub url: String,
    pub selector: String,
    pub label: Option<String>,
    pub role: Option<String>,
    pub text: Option<String>,
    pub bounds: Option<ElementBounds>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ElementReference {
    pub id: String,
    pub tab_id: String,
    pub url: String,
    pub selector: String,
    pub label: Option<String>,
    pub role: Option<String>,
    pub text: Option<String>,
    pub bounds: Option<ElementBounds>,
    pub created_at_unix: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ElementBounds {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommandResultRequest {
    pub tab_id: String,
    pub status: CommandExecutionStatus,
    pub message: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommandResultIpcRequest {
    pub command_id: String,
    pub tab_id: String,
    pub status: CommandExecutionStatus,
    pub message: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommandExecutionReport {
    pub command_id: String,
    pub tab_id: String,
    pub session_id: Option<String>,
    pub target_origin: Option<WebOrigin>,
    #[serde(skip)]
    pub grant_token: Option<String>,
    pub status: CommandExecutionStatus,
    pub message: Option<String>,
    pub completed_at_unix: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommandScope {
    pub session_id: Option<String>,
    pub target_origin: Option<WebOrigin>,
    #[serde(skip)]
    pub grant_token: Option<String>,
}

impl CommandScope {
    fn owner() -> Self {
        Self {
            session_id: None,
            target_origin: None,
            grant_token: None,
        }
    }

    fn owner_with_origin(target_origin: WebOrigin) -> Self {
        Self {
            session_id: None,
            target_origin: Some(target_origin),
            grant_token: None,
        }
    }

    fn session(session_id: impl Into<String>, target_origin: Option<WebOrigin>) -> Self {
        Self {
            session_id: Some(session_id.into()),
            target_origin,
            grant_token: None,
        }
    }

    fn with_grant_token(mut self, grant_token: Option<&str>) -> Self {
        self.grant_token = grant_token.map(str::to_string);
        self
    }
}

fn queue_command_locked(inner: &mut InnerState, command: BrowserCommand, scope: CommandScope) {
    inner.command_scopes.insert(command.id.clone(), scope);
    inner.commands.push_back(command);
}

fn purge_pending_session_commands_locked(inner: &mut InnerState, session_id: &str) -> Vec<String> {
    let mut retained = VecDeque::new();
    let mut purged_command_ids = Vec::new();

    while let Some(command) = inner.commands.pop_front() {
        let should_purge = inner
            .command_scopes
            .get(&command.id)
            .and_then(|scope| scope.session_id.as_deref())
            == Some(session_id);

        if should_purge {
            inner.command_scopes.remove(&command.id);
            purged_command_ids.push(command.id);
        } else {
            retained.push_back(command);
        }
    }

    inner.commands = retained;
    purged_command_ids
}

fn purge_pending_grant_commands_locked(inner: &mut InnerState, token: &str) -> Vec<String> {
    let mut retained = VecDeque::new();
    let mut purged_command_ids = Vec::new();

    while let Some(command) = inner.commands.pop_front() {
        let should_purge = inner
            .command_scopes
            .get(&command.id)
            .and_then(|scope| scope.grant_token.as_deref())
            == Some(token);

        if should_purge {
            inner.command_scopes.remove(&command.id);
            purged_command_ids.push(command.id);
        } else {
            retained.push_back(command);
        }
    }

    inner.commands = retained;
    purged_command_ids
}

fn pane_connection_grant_token(connection: &Option<AgentPaneConnection>) -> Option<&str> {
    connection
        .as_ref()
        .map(|connection| connection.grant_token.as_str())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CommandExecutionStatus {
    Succeeded,
    Failed,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TabState {
    pub id: String,
    pub current_url: Option<String>,
    pub session_id: Option<String>,
    pub title: Option<String>,
    pub created_at_unix: u64,
    pub updated_at_unix: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserCommand {
    pub id: String,
    pub tab_id: String,
    pub issued_at_unix: u64,
    pub kind: BrowserCommandKind,
}

impl BrowserCommand {
    fn open_tab(tab: TabState) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            tab_id: tab.id.clone(),
            issued_at_unix: now_unix(),
            kind: BrowserCommandKind::OpenTab { tab },
        }
    }

    fn close_tab(tab_id: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            tab_id: tab_id.to_string(),
            issued_at_unix: now_unix(),
            kind: BrowserCommandKind::CloseTab,
        }
    }

    fn activate_tab(tab_id: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            tab_id: tab_id.to_string(),
            issued_at_unix: now_unix(),
            kind: BrowserCommandKind::ActivateTab,
        }
    }

    fn navigate(tab_id: &str, url: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            tab_id: tab_id.to_string(),
            issued_at_unix: now_unix(),
            kind: BrowserCommandKind::Navigate { url },
        }
    }

    fn go_back(tab_id: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            tab_id: tab_id.to_string(),
            issued_at_unix: now_unix(),
            kind: BrowserCommandKind::GoBack,
        }
    }

    fn go_forward(tab_id: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            tab_id: tab_id.to_string(),
            issued_at_unix: now_unix(),
            kind: BrowserCommandKind::GoForward,
        }
    }

    fn reload(tab_id: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            tab_id: tab_id.to_string(),
            issued_at_unix: now_unix(),
            kind: BrowserCommandKind::Reload,
        }
    }

    fn fill_login(
        tab_id: &str,
        credential_id: String,
        username: String,
        target_origin: WebOrigin,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            tab_id: tab_id.to_string(),
            issued_at_unix: now_unix(),
            kind: BrowserCommandKind::FillLogin {
                credential_id,
                username,
                target_origin,
            },
        }
    }

    fn agent_action(tab_id: &str, action: AgentAction, target_origin: WebOrigin) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            tab_id: tab_id.to_string(),
            issued_at_unix: now_unix(),
            kind: BrowserCommandKind::AgentAction {
                action,
                target_origin,
            },
        }
    }

    fn open_agent_pane(
        tab_id: &str,
        pane: AgentPaneState,
        connection: Option<AgentPaneConnection>,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            tab_id: tab_id.to_string(),
            issued_at_unix: now_unix(),
            kind: BrowserCommandKind::OpenAgentPane { pane, connection },
        }
    }

    fn close_agent_pane(tab_id: &str, pane_id: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            tab_id: tab_id.to_string(),
            issued_at_unix: now_unix(),
            kind: BrowserCommandKind::CloseAgentPane {
                pane_id: pane_id.to_string(),
            },
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BrowserCommandKind {
    OpenTab {
        tab: TabState,
    },
    CloseTab,
    ActivateTab,
    Navigate {
        url: String,
    },
    GoBack,
    GoForward,
    Reload,
    FillLogin {
        credential_id: String,
        username: String,
        target_origin: WebOrigin,
    },
    AgentAction {
        action: AgentAction,
        target_origin: WebOrigin,
    },
    OpenAgentPane {
        pane: AgentPaneState,
        connection: Option<AgentPaneConnection>,
    },
    CloseAgentPane {
        pane_id: String,
    },
}

fn resolve_action_targets(
    tab_id: &str,
    target_origin: &WebOrigin,
    element_refs: &BTreeMap<String, ElementReference>,
    action: AgentAction,
) -> Result<AgentAction> {
    match action {
        AgentAction::Click {
            selector,
            element_ref_id,
        } => {
            let selector = resolve_selector(
                tab_id,
                target_origin,
                element_refs,
                selector,
                element_ref_id.as_ref(),
            )?;
            Ok(AgentAction::Click {
                selector: Some(selector),
                element_ref_id,
            })
        }
        AgentAction::DoubleClick {
            selector,
            element_ref_id,
        } => {
            let selector = resolve_selector(
                tab_id,
                target_origin,
                element_refs,
                selector,
                element_ref_id.as_ref(),
            )?;
            Ok(AgentAction::DoubleClick {
                selector: Some(selector),
                element_ref_id,
            })
        }
        AgentAction::DragTo {
            source_selector,
            source_element_ref_id,
            target_selector,
            target_element_ref_id,
        } => {
            let source_selector = resolve_selector(
                tab_id,
                target_origin,
                element_refs,
                source_selector,
                source_element_ref_id.as_ref(),
            )?;
            let target_selector = resolve_selector(
                tab_id,
                target_origin,
                element_refs,
                target_selector,
                target_element_ref_id.as_ref(),
            )?;
            Ok(AgentAction::DragTo {
                source_selector: Some(source_selector),
                source_element_ref_id,
                target_selector: Some(target_selector),
                target_element_ref_id,
            })
        }
        AgentAction::Hover {
            selector,
            element_ref_id,
        } => {
            let selector = resolve_selector(
                tab_id,
                target_origin,
                element_refs,
                selector,
                element_ref_id.as_ref(),
            )?;
            Ok(AgentAction::Hover {
                selector: Some(selector),
                element_ref_id,
            })
        }
        AgentAction::Focus {
            selector,
            element_ref_id,
        } => {
            let selector = resolve_selector(
                tab_id,
                target_origin,
                element_refs,
                selector,
                element_ref_id.as_ref(),
            )?;
            Ok(AgentAction::Focus {
                selector: Some(selector),
                element_ref_id,
            })
        }
        AgentAction::TypeText {
            selector,
            element_ref_id,
            text,
            clear_first,
        } => {
            let selector = resolve_selector(
                tab_id,
                target_origin,
                element_refs,
                selector,
                element_ref_id.as_ref(),
            )?;
            Ok(AgentAction::TypeText {
                selector: Some(selector),
                element_ref_id,
                text,
                clear_first,
            })
        }
        AgentAction::ExtractText {
            selector,
            element_ref_id,
        } => {
            let selector = resolve_selector(
                tab_id,
                target_origin,
                element_refs,
                selector,
                element_ref_id.as_ref(),
            )?;
            Ok(AgentAction::ExtractText {
                selector: Some(selector),
                element_ref_id,
            })
        }
        AgentAction::InspectElement {
            selector,
            element_ref_id,
        } => {
            let selector = resolve_selector(
                tab_id,
                target_origin,
                element_refs,
                selector,
                element_ref_id.as_ref(),
            )?;
            Ok(AgentAction::InspectElement {
                selector: Some(selector),
                element_ref_id,
            })
        }
        AgentAction::SelectOption {
            selector,
            element_ref_id,
            value,
        } => {
            let selector = resolve_selector(
                tab_id,
                target_origin,
                element_refs,
                selector,
                element_ref_id.as_ref(),
            )?;
            Ok(AgentAction::SelectOption {
                selector: Some(selector),
                element_ref_id,
                value,
            })
        }
        AgentAction::SetChecked {
            selector,
            element_ref_id,
            checked,
        } => {
            let selector = resolve_selector(
                tab_id,
                target_origin,
                element_refs,
                selector,
                element_ref_id.as_ref(),
            )?;
            Ok(AgentAction::SetChecked {
                selector: Some(selector),
                element_ref_id,
                checked,
            })
        }
        AgentAction::ScrollIntoView {
            selector,
            element_ref_id,
        } => {
            let selector = resolve_selector(
                tab_id,
                target_origin,
                element_refs,
                selector,
                element_ref_id.as_ref(),
            )?;
            Ok(AgentAction::ScrollIntoView {
                selector: Some(selector),
                element_ref_id,
            })
        }
        AgentAction::Submit {
            selector,
            element_ref_id,
        } => {
            let selector = resolve_selector(
                tab_id,
                target_origin,
                element_refs,
                selector,
                element_ref_id.as_ref(),
            )?;
            Ok(AgentAction::Submit {
                selector: Some(selector),
                element_ref_id,
            })
        }
        other => Ok(other),
    }
}

fn resolve_selector(
    tab_id: &str,
    target_origin: &WebOrigin,
    element_refs: &BTreeMap<String, ElementReference>,
    selector: Option<String>,
    element_ref_id: Option<&String>,
) -> Result<String> {
    if let Some(selector) = selector {
        if selector.trim().is_empty() {
            return Err(ControlError::BadRequest(
                "selector cannot be empty".to_string(),
            ));
        }
        return Ok(selector);
    }

    let Some(element_ref_id) = element_ref_id else {
        return Err(ControlError::BadRequest(
            "selector or element_ref_id is required".to_string(),
        ));
    };
    let reference = element_refs
        .get(element_ref_id)
        .ok_or_else(|| ControlError::NotFound(format!("element reference {element_ref_id}")))?;
    if reference.tab_id != tab_id {
        return Err(TelescopeError::PolicyDenied(format!(
            "element reference `{element_ref_id}` belongs to tab `{}`, not `{tab_id}`",
            reference.tab_id
        ))
        .into());
    }
    if !element_reference_matches_origin(reference, target_origin)? {
        let reference_origin = WebOrigin::from_url_str(&reference.url)?;
        return Err(TelescopeError::PolicyDenied(format!(
            "element reference `{element_ref_id}` was captured for `{reference_origin}`, not current origin `{target_origin}`"
        ))
        .into());
    }
    Ok(reference.selector.clone())
}

fn element_reference_matches_origin(
    reference: &ElementReference,
    origin: &WebOrigin,
) -> Result<bool> {
    Ok(WebOrigin::from_url_str(&reference.url)? == *origin)
}

#[derive(Clone, Debug)]
pub struct ServeConfig {
    pub addr: String,
    pub bearer_token: String,
}

impl ServeConfig {
    pub fn localhost(token: impl Into<String>) -> Self {
        Self {
            addr: "127.0.0.1:47639".to_string(),
            bearer_token: token.into(),
        }
    }
}

pub fn serve(config: ServeConfig, plane: ControlPlane) -> Result<()> {
    let (server, _) = bind_control_server(&config.addr)?;
    serve_server(server, config.bearer_token, plane)
}

pub fn bind_control_server(addr: &str) -> Result<(Server, String)> {
    let server =
        Server::http(resolve_addr(addr)?).map_err(|err| ControlError::Server(err.to_string()))?;
    let actual_addr = server.server_addr().to_ip().ok_or_else(|| {
        ControlError::Server("control server did not bind to an IP socket".into())
    })?;
    Ok((server, format!("http://{actual_addr}")))
}

pub fn serve_server(
    server: Server,
    bearer_token: impl Into<String>,
    plane: ControlPlane,
) -> Result<()> {
    let bearer_token = bearer_token.into();
    for request in server.incoming_requests() {
        let response = route_request(request, &plane, &bearer_token);
        if let Err(err) = response {
            eprintln!("telescope-control request failed: {err}");
        }
    }
    Ok(())
}

fn resolve_addr(addr: &str) -> Result<std::net::SocketAddr> {
    addr.to_socket_addrs()?
        .next()
        .ok_or_else(|| ControlError::BadRequest(format!("could not resolve address `{addr}`")))
}

fn route_request(mut request: Request, plane: &ControlPlane, bearer_token: &str) -> Result<()> {
    if request.method() == &Method::Get && request.url() == "/health" {
        return respond_json(
            request,
            200,
            &serde_json::json!({"status": "ok", "service": "telescope"}),
        );
    }

    if request.method() == &Method::Options {
        return respond_empty(request, 204);
    }

    if let Err(error) = plane.cleanup_expired_access() {
        let status = status_for_error(&error);
        return respond_error(request, status, error);
    }

    let method = request.method().clone();
    let url = request.url().to_string();
    let path = url.split('?').next().unwrap_or(url.as_str());
    let parts = path
        .trim_matches('/')
        .split('/')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();

    let auth = match authorization_scope(&request, bearer_token, plane) {
        Ok(auth) => auth,
        Err(error) => {
            let status = status_for_error(&error);
            return respond_error(request, status, error);
        }
    };

    let outcome = match (method, parts.as_slice()) {
        (Method::Post, ["v1", "sessions"]) => {
            let body = read_json::<CreateSessionRequest>(&mut request);
            body.and_then(|body| {
                require_owner(&auth)?;
                json_outcome(201, &plane.create_session(body)?)
            })
        }
        (Method::Get, ["v1", "sessions"]) => {
            require_owner(&auth).and_then(|()| json_outcome(200, &plane.list_sessions()?))
        }
        (Method::Delete, ["v1", "sessions", session_id]) => {
            require_owner(&auth)?;
            json_outcome(200, &plane.revoke_session(session_id)?)
        }
        (Method::Post, ["v1", "agent-grants"]) => {
            let body = read_json::<CreateAgentGrantRequest>(&mut request);
            body.and_then(|body| {
                require_owner(&auth)?;
                json_outcome(201, &plane.create_agent_grant(body)?)
            })
        }
        (Method::Get, ["v1", "agent-grants"]) => {
            require_owner(&auth).and_then(|()| json_outcome(200, &plane.list_agent_grants()?))
        }
        (Method::Delete, ["v1", "agent-grants", token]) => {
            require_owner(&auth)?;
            json_outcome(200, &plane.revoke_agent_grant(token)?)
        }
        (Method::Post, ["v1", "tabs"]) => {
            let body = read_json::<CreateTabRequest>(&mut request);
            body.and_then(|body| {
                require_owner(&auth)?;
                json_outcome(201, &plane.create_tab(body)?)
            })
        }
        (Method::Get, ["v1", "tabs"]) => {
            require_owner(&auth).and_then(|()| json_outcome(200, &plane.list_tabs()?))
        }
        (Method::Get, ["v1", "tabs", "active"]) => {
            require_owner(&auth).and_then(|()| json_outcome(200, &plane.active_tab()?))
        }
        (Method::Post, ["v1", "tabs", tab_id, "activate"]) => {
            require_owner(&auth)?;
            json_outcome(200, &plane.activate_tab(tab_id)?)
        }
        (Method::Delete, ["v1", "tabs", tab_id]) => {
            require_owner(&auth)?;
            json_outcome(200, &plane.close_tab(tab_id)?)
        }
        (Method::Post, ["v1", "tabs", tab_id, "navigate"]) => {
            let body = read_json::<NavigateRequest>(&mut request);
            body.and_then(|mut body| {
                let grant_token = if let AuthScope::Agent(grant) = &auth {
                    body.session_id = Some(grant.session_id.clone());
                    authorize_agent_tab_navigation(&auth, plane, &grant.session_id, tab_id)?;
                    Some(grant.token.as_str())
                } else {
                    None
                };
                json_outcome(200, &plane.navigate_tab_inner(tab_id, body, grant_token)?)
            })
        }
        (Method::Post, ["v1", "tabs", tab_id, "back"]) => {
            require_owner(&auth)?;
            json_outcome(202, &plane.go_back(tab_id)?)
        }
        (Method::Post, ["v1", "tabs", tab_id, "forward"]) => {
            require_owner(&auth)?;
            json_outcome(202, &plane.go_forward(tab_id)?)
        }
        (Method::Post, ["v1", "tabs", tab_id, "reload"]) => {
            require_owner(&auth)?;
            json_outcome(202, &plane.reload_tab(tab_id)?)
        }
        (Method::Post, ["v1", "tabs", tab_id, "fill-login"]) => {
            let body = read_json::<FillLoginRequest>(&mut request);
            body.and_then(|body| {
                authorize_session_tab(&auth, plane, &body.session_id, tab_id)?;
                let grant_token = auth.agent_grant_token();
                json_outcome(202, &plane.fill_login_inner(tab_id, body, grant_token)?)
            })
        }
        (Method::Post, ["v1", "tabs", tab_id, "login-options"]) => {
            let body = read_json::<ListLoginOptionsRequest>(&mut request);
            body.and_then(|body| {
                authorize_session_tab(&auth, plane, &body.session_id, tab_id)?;
                json_outcome(200, &plane.list_login_options(tab_id, body)?)
            })
        }
        (Method::Get, ["v1", "tabs", tab_id, "credentials"]) => {
            require_owner(&auth)?;
            json_outcome(200, &plane.list_credentials_for_tab(tab_id)?)
        }
        (Method::Post, ["v1", "tabs", tab_id, "credentials"]) => {
            let body = read_json::<StoreTabCredentialRequest>(&mut request);
            body.and_then(|body| {
                require_owner(&auth)?;
                json_outcome(201, &plane.store_credential_for_tab(tab_id, body)?)
            })
        }
        (Method::Post, ["v1", "tabs", tab_id, "credentials", credential_id, "fill"]) => {
            require_owner(&auth)?;
            json_outcome(202, &plane.fill_credential_for_tab(tab_id, credential_id)?)
        }
        (Method::Delete, ["v1", "tabs", tab_id, "credentials", credential_id]) => {
            require_owner(&auth)?;
            plane.delete_credential_for_tab(tab_id, credential_id)?;
            json_outcome(200, &serde_json::json!({"deleted": true}))
        }
        (Method::Post, ["v1", "tabs", tab_id, "actions"]) => {
            let body = read_json::<AgentActionRequest>(&mut request);
            body.and_then(|body| {
                authorize_session_tab(&auth, plane, &body.session_id, tab_id)?;
                let grant_token = auth.agent_grant_token();
                json_outcome(
                    202,
                    &plane.queue_agent_action_inner(tab_id, body, grant_token)?,
                )
            })
        }
        (Method::Post, ["v1", "agent-panes"]) => {
            let body = read_json::<OpenAgentPaneRequest>(&mut request);
            body.and_then(|body| {
                require_owner(&auth)?;
                json_outcome(201, &plane.open_agent_pane(body)?)
            })
        }
        (Method::Post, ["v1", "scoped-agent-panes"]) => {
            let body = read_json::<OpenScopedAgentPaneRequest>(&mut request);
            body.and_then(|body| {
                require_owner(&auth)?;
                json_outcome(201, &plane.open_scoped_agent_pane(body)?)
            })
        }
        (Method::Get, ["v1", "agent-panes"]) => {
            require_owner(&auth).and_then(|()| json_outcome(200, &plane.list_agent_panes()?))
        }
        (Method::Get, ["v1", "agent-panes", pane_id, "connection"]) => {
            let connection = plane.agent_pane_connection(pane_id);
            connection.and_then(|connection| {
                authorize_agent_pane_connection(&auth, &connection)?;
                json_outcome(200, &connection)
            })
        }
        (Method::Delete, ["v1", "agent-panes", pane_id]) => {
            authorize_agent_pane_close(&auth, plane, pane_id)?;
            json_outcome(200, &plane.close_agent_pane(pane_id)?)
        }
        (Method::Post, ["v1", "page-contexts"]) => {
            let body = read_json::<PageContextRequest>(&mut request);
            body.and_then(|body| {
                require_owner(&auth)?;
                json_outcome(201, &plane.publish_page_context(body)?)
            })
        }
        (Method::Get, ["v1", "page-contexts"]) => {
            let contexts = plane.list_page_contexts();
            contexts.and_then(|contexts| {
                json_outcome(200, &filter_page_contexts_for_auth(&auth, plane, contexts)?)
            })
        }
        (Method::Post, ["v1", "element-refs"]) => {
            let body = read_json::<ElementReferenceInput>(&mut request);
            body.and_then(|body| {
                require_owner(&auth)?;
                json_outcome(201, &plane.record_element_reference(body)?)
            })
        }
        (Method::Get, ["v1", "element-refs"]) => {
            let refs = plane.list_element_references();
            refs.and_then(|refs| {
                json_outcome(200, &filter_element_refs_for_auth(&auth, plane, refs)?)
            })
        }
        (Method::Get, ["v1", "commands"]) => {
            require_owner(&auth).and_then(|()| json_outcome(200, &plane.poll_commands(None)?))
        }
        (Method::Post, ["v1", "commands", command_id, "result"]) => {
            let body = read_json::<CommandResultRequest>(&mut request);
            body.and_then(|body| {
                require_owner(&auth)?;
                json_outcome(
                    201,
                    &plane.record_command_result(
                        command_id,
                        &body.tab_id,
                        body.status,
                        body.message,
                    )?,
                )
            })
        }
        (Method::Get, ["v1", "command-results"]) => {
            let results = plane.list_command_results();
            results.and_then(|results| {
                json_outcome(
                    200,
                    &filter_command_results_for_auth(&auth, plane, results)?,
                )
            })
        }
        (Method::Get, ["v1", "audit-events"]) => {
            require_owner(&auth).and_then(|()| json_outcome(200, &plane.list_audit_events()?))
        }
        (Method::Get, ["v1", "handoff"]) => {
            require_owner(&auth).and_then(|()| json_outcome(200, &plane.handoff_snapshot()?))
        }
        (Method::Post, ["v1", "bookmarks"]) => {
            let body = read_json::<CreateBookmarkRequest>(&mut request);
            body.and_then(|body| {
                require_owner(&auth)?;
                json_outcome(201, &plane.create_bookmark(body)?)
            })
        }
        (Method::Get, ["v1", "bookmarks"]) => {
            require_owner(&auth).and_then(|()| json_outcome(200, &plane.list_bookmarks()?))
        }
        (Method::Delete, ["v1", "bookmarks", bookmark_id]) => {
            require_owner(&auth)?;
            json_outcome(200, &plane.delete_bookmark(bookmark_id)?)
        }
        (Method::Post, ["v1", "credentials"]) => {
            let body = read_json::<CredentialInput>(&mut request);
            body.and_then(|body| {
                require_owner(&auth)?;
                json_outcome(201, &plane.store_credential(body)?)
            })
        }
        (Method::Get, ["v1", "credentials"]) => {
            require_owner(&auth).and_then(|()| json_outcome(200, &plane.list_credentials()?))
        }
        (Method::Delete, ["v1", "credentials", credential_id]) => {
            require_owner(&auth)?;
            plane.delete_credential(credential_id)?;
            json_outcome(200, &serde_json::json!({"deleted": true}))
        }
        _ => Err(ControlError::NotFound(path.to_string())),
    };

    match outcome {
        Ok((status, value)) => respond_json(request, status, &value),
        Err(error) => {
            let status = status_for_error(&error);
            respond_error(request, status, error)
        }
    }
}

fn read_json<T: DeserializeOwned>(request: &mut Request) -> Result<T> {
    let mut body = String::new();
    request.as_reader().read_to_string(&mut body)?;
    if body.trim().is_empty() {
        return Err(ControlError::BadRequest("missing JSON body".to_string()));
    }
    Ok(serde_json::from_str(&body)?)
}

#[derive(Clone, Debug)]
enum AuthScope {
    Owner,
    Agent(AgentGrant),
}

impl AuthScope {
    fn agent_grant_token(&self) -> Option<&str> {
        match self {
            Self::Owner => None,
            Self::Agent(grant) => Some(grant.token.as_str()),
        }
    }
}

fn authorization_scope(
    request: &Request,
    owner_token: &str,
    plane: &ControlPlane,
) -> Result<AuthScope> {
    let token = bearer_token(request).ok_or(ControlError::Unauthorized)?;
    if token == owner_token {
        return Ok(AuthScope::Owner);
    }
    let grant = plane.lookup_agent_grant(token)?;
    authorize_agent_request_origin(request, &grant)?;
    Ok(AuthScope::Agent(grant))
}

fn bearer_token(request: &Request) -> Option<&str> {
    request.headers().iter().find_map(|header| {
        if !header.field.equiv("Authorization") {
            return None;
        }
        header.value.as_str().trim().strip_prefix("Bearer ")
    })
}

fn origin_header(request: &Request) -> Option<&str> {
    request.headers().iter().find_map(|header| {
        if !header.field.equiv("Origin") {
            return None;
        }
        Some(header.value.as_str().trim())
    })
}

fn authorize_agent_request_origin(request: &Request, grant: &AgentGrant) -> Result<()> {
    if grant.allowed_client_origins.is_empty() {
        return Ok(());
    }

    let Some(origin) = origin_header(request) else {
        return Err(TelescopeError::PolicyDenied(
            "origin-bound agent grant requires an Origin header".to_string(),
        )
        .into());
    };
    let origin = WebOrigin::parse(origin)?;
    if grant
        .allowed_client_origins
        .iter()
        .any(|allowed| allowed == &origin)
    {
        return Ok(());
    }

    Err(TelescopeError::PolicyDenied(format!(
        "agent grant cannot be used from client origin `{origin}`"
    ))
    .into())
}

fn require_owner(auth: &AuthScope) -> Result<()> {
    match auth {
        AuthScope::Owner => Ok(()),
        AuthScope::Agent(_) => Err(TelescopeError::PolicyDenied(
            "owner token required for this endpoint".to_string(),
        )
        .into()),
    }
}

fn authorize_session_tab(
    auth: &AuthScope,
    plane: &ControlPlane,
    session_id: &str,
    tab_id: &str,
) -> Result<()> {
    match auth {
        AuthScope::Owner => Ok(()),
        AuthScope::Agent(grant) => {
            if grant.session_id != session_id {
                return Err(TelescopeError::PolicyDenied(format!(
                    "agent grant is scoped to session `{}`, not `{session_id}`",
                    grant.session_id
                ))
                .into());
            }
            if !plane.agent_grant_allows_tab(grant, tab_id)? {
                return Err(TelescopeError::PolicyDenied(format!(
                    "agent grant cannot access tab `{tab_id}`"
                ))
                .into());
            }
            Ok(())
        }
    }
}

fn authorize_agent_tab_navigation(
    auth: &AuthScope,
    plane: &ControlPlane,
    session_id: &str,
    tab_id: &str,
) -> Result<()> {
    authorize_session_tab(auth, plane, session_id, tab_id)?;
    if matches!(auth, AuthScope::Agent(_)) {
        plane
            .get_session_locked(session_id)?
            .assert_can_interact()?;
    }
    Ok(())
}

fn authorize_agent_pane_connection(
    auth: &AuthScope,
    connection: &AgentPaneConnection,
) -> Result<()> {
    match auth {
        AuthScope::Owner => Ok(()),
        AuthScope::Agent(grant) => {
            if grant.token != connection.grant_token {
                return Err(TelescopeError::PolicyDenied(
                    "agent grant cannot access this pane connection".to_string(),
                )
                .into());
            }
            if grant.session_id != connection.session_id {
                return Err(TelescopeError::PolicyDenied(format!(
                    "agent grant is scoped to session `{}`, not `{}`",
                    grant.session_id, connection.session_id
                ))
                .into());
            }
            Ok(())
        }
    }
}

fn authorize_agent_pane_close(auth: &AuthScope, plane: &ControlPlane, pane_id: &str) -> Result<()> {
    match auth {
        AuthScope::Owner => Ok(()),
        AuthScope::Agent(_) => {
            let connection = plane.agent_pane_connection(pane_id)?;
            authorize_agent_pane_connection(auth, &connection)
        }
    }
}

fn filter_page_contexts_for_auth(
    auth: &AuthScope,
    plane: &ControlPlane,
    contexts: Vec<PageContextSnapshot>,
) -> Result<Vec<PageContextSnapshot>> {
    match auth {
        AuthScope::Owner => Ok(contexts),
        AuthScope::Agent(grant) => contexts
            .into_iter()
            .filter_map(
                |context| match plane.agent_grant_allows_page_context(grant, &context) {
                    Ok(true) => Some(Ok(context)),
                    Ok(false) => None,
                    Err(error) => Some(Err(error)),
                },
            )
            .collect(),
    }
}

fn filter_element_refs_for_auth(
    auth: &AuthScope,
    plane: &ControlPlane,
    refs: Vec<ElementReference>,
) -> Result<Vec<ElementReference>> {
    match auth {
        AuthScope::Owner => Ok(refs),
        AuthScope::Agent(grant) => refs
            .into_iter()
            .filter_map(|reference| {
                match plane.agent_grant_allows_element_reference(grant, &reference) {
                    Ok(true) => Some(Ok(reference)),
                    Ok(false) => None,
                    Err(error) => Some(Err(error)),
                }
            })
            .collect(),
    }
}

fn filter_command_results_for_auth(
    auth: &AuthScope,
    plane: &ControlPlane,
    results: Vec<CommandExecutionReport>,
) -> Result<Vec<CommandExecutionReport>> {
    match auth {
        AuthScope::Owner => Ok(results),
        AuthScope::Agent(grant) => results
            .into_iter()
            .filter_map(
                |result| match plane.agent_grant_allows_command_result(grant, &result) {
                    Ok(true) => Some(Ok(result)),
                    Ok(false) => None,
                    Err(error) => Some(Err(error)),
                },
            )
            .collect(),
    }
}

fn json_outcome<T: Serialize>(status: u16, value: &T) -> Result<(u16, serde_json::Value)> {
    Ok((status, serde_json::to_value(value)?))
}

fn status_for_error(error: &ControlError) -> u16 {
    match error {
        ControlError::BadRequest(_) | ControlError::Json(_) => 400,
        ControlError::Unauthorized => 401,
        ControlError::NotFound(_) => 404,
        ControlError::Core(TelescopeError::CredentialNotFound(_))
        | ControlError::Core(TelescopeError::SessionNotFound(_)) => 404,
        ControlError::Core(TelescopeError::PolicyDenied(_)) => 403,
        ControlError::Core(TelescopeError::InvalidOrigin(_)) => 400,
        ControlError::Core(_) | ControlError::Io(_) | ControlError::Server(_) => 500,
    }
}

fn respond_json<T: Serialize>(request: Request, status: u16, value: &T) -> Result<()> {
    let body = serde_json::to_string(value)?;
    let response = with_cors_headers(
        Response::from_string(body)
            .with_status_code(StatusCode(status))
            .with_header(json_header()),
    );
    request
        .respond(response)
        .map_err(|err| ControlError::Server(err.to_string()))
}

fn respond_error(request: Request, status: u16, error: ControlError) -> Result<()> {
    let body = serde_json::json!({ "error": error.to_string() }).to_string();
    let response = with_cors_headers(
        Response::from_string(body)
            .with_status_code(StatusCode(status))
            .with_header(json_header()),
    );
    request
        .respond(response)
        .map_err(|err| ControlError::Server(err.to_string()))
}

fn respond_empty(request: Request, status: u16) -> Result<()> {
    let response = with_cors_headers(Response::empty(StatusCode(status)));
    request
        .respond(response)
        .map_err(|err| ControlError::Server(err.to_string()))
}

fn json_header() -> Header {
    Header::from_bytes("Content-Type", "application/json").expect("valid static header")
}

fn with_cors_headers<R>(mut response: Response<R>) -> Response<R>
where
    R: std::io::Read,
{
    for header in cors_headers() {
        response.add_header(header);
    }
    response
}

fn cors_headers() -> Vec<Header> {
    [
        ("Access-Control-Allow-Origin", "*"),
        (
            "Access-Control-Allow-Headers",
            "Authorization, Content-Type",
        ),
        ("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS"),
        ("Access-Control-Allow-Private-Network", "true"),
        ("Access-Control-Max-Age", "600"),
    ]
    .into_iter()
    .map(|(name, value)| Header::from_bytes(name, value).expect("valid static header"))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use telescope_core::{CredentialVault, MemorySecretStore};

    fn plane() -> ControlPlane {
        ControlPlane::new(CredentialVault::ephemeral(
            "test",
            Arc::new(MemorySecretStore::new()),
        ))
    }

    #[test]
    fn fill_login_queues_username_without_password() {
        let plane = plane();
        let session = plane
            .create_session(CreateSessionRequest {
                allowed_origins: vec!["https://example.com".to_string()],
                allow_credentials: true,
                allow_interactions: true,
                allow_scripts: false,
                ttl_seconds: None,
            })
            .unwrap();
        let tab = plane
            .create_tab(CreateTabRequest {
                url: Some("https://example.com/login".to_string()),
                session_id: Some(session.id.clone()),
            })
            .unwrap();
        let credential = plane
            .store_credential(CredentialInput {
                origin: "https://example.com".to_string(),
                username: "me".to_string(),
                password: "secret".to_string(),
                login_url: None,
                label: None,
            })
            .unwrap();

        let command = plane
            .fill_login(
                &tab.id,
                FillLoginRequest {
                    session_id: session.id,
                    credential_id: credential.id,
                },
            )
            .unwrap();

        match &command.kind {
            BrowserCommandKind::FillLogin {
                username,
                target_origin,
                ..
            } => {
                assert_eq!(username, "me");
                assert_eq!(target_origin.display_url(), "https://example.com");
            }
            _ => panic!("expected fill-login command"),
        }
        assert!(!serde_json::to_string(&command).unwrap().contains("secret"));
    }

    #[test]
    fn owner_tab_urls_are_restricted_to_browser_pages() {
        let plane = plane();
        let tab = plane
            .create_tab(CreateTabRequest {
                url: Some(" about:blank ".to_string()),
                session_id: None,
            })
            .unwrap();
        assert_eq!(tab.current_url.as_deref(), Some("about:blank"));

        let navigated = plane
            .navigate_tab(
                &tab.id,
                NavigateRequest {
                    url: " https://example.com/path ".to_string(),
                    session_id: None,
                },
            )
            .unwrap();
        assert_eq!(
            navigated.current_url.as_deref(),
            Some("https://example.com/path")
        );

        assert!(plane
            .create_tab(CreateTabRequest {
                url: Some("javascript:alert(1)".to_string()),
                session_id: None,
            })
            .is_err());
        assert!(plane
            .navigate_tab(
                &tab.id,
                NavigateRequest {
                    url: "data:text/html,blocked".to_string(),
                    session_id: None,
                },
            )
            .is_err());
        assert_eq!(
            plane.active_tab().unwrap().unwrap().current_url.as_deref(),
            Some("https://example.com/path")
        );
    }

    #[test]
    fn login_options_are_scoped_to_session_origin_and_credential_permission() {
        let plane = plane();
        let session = plane
            .create_session(CreateSessionRequest {
                allowed_origins: vec!["https://example.com".to_string()],
                allow_credentials: true,
                allow_interactions: false,
                allow_scripts: false,
                ttl_seconds: None,
            })
            .unwrap();
        let no_credentials_session = plane
            .create_session(CreateSessionRequest {
                allowed_origins: vec!["https://example.com".to_string()],
                allow_credentials: false,
                allow_interactions: false,
                allow_scripts: false,
                ttl_seconds: None,
            })
            .unwrap();
        let tab = plane
            .create_tab(CreateTabRequest {
                url: Some("https://example.com/login".to_string()),
                session_id: Some(session.id.clone()),
            })
            .unwrap();
        let credential = plane
            .store_credential(CredentialInput {
                origin: "https://example.com".to_string(),
                username: "me@example.com".to_string(),
                password: "secret-password".to_string(),
                login_url: None,
                label: Some("Work".to_string()),
            })
            .unwrap();
        plane
            .store_credential(CredentialInput {
                origin: "https://other.example".to_string(),
                username: "other@example.com".to_string(),
                password: "other-secret".to_string(),
                login_url: None,
                label: None,
            })
            .unwrap();

        let options = plane
            .list_login_options(
                &tab.id,
                ListLoginOptionsRequest {
                    session_id: session.id.clone(),
                },
            )
            .unwrap();

        assert_eq!(options.len(), 1);
        assert_eq!(options[0].id, credential.id);
        assert_eq!(options[0].username, "me@example.com");
        let serialized = serde_json::to_string(&options).unwrap();
        assert!(serialized.contains("me@example.com"));
        assert!(!serialized.contains("secret-password"));
        assert!(!serialized.contains("other-secret"));
        assert!(plane.list_audit_events().unwrap().iter().any(|event| {
            matches!(
                event.kind,
                AuditEventKind::LoginOptionsListed {
                    count: 1,
                    ref session_id,
                    ..
                } if session_id == &session.id
            )
        }));

        let denied = plane
            .list_login_options(
                &tab.id,
                ListLoginOptionsRequest {
                    session_id: no_credentials_session.id,
                },
            )
            .unwrap_err();
        assert!(denied.to_string().contains("cannot use credentials"));
    }

    #[test]
    fn store_and_fill_credential_for_tab_uses_current_origin() {
        let plane = plane();
        let tab = plane
            .create_tab(CreateTabRequest {
                url: Some("https://example.com/login".to_string()),
                session_id: None,
            })
            .unwrap();

        let credential = plane
            .store_credential_for_tab(
                &tab.id,
                StoreTabCredentialRequest {
                    username: "me".to_string(),
                    password: "secret".to_string(),
                    login_url: None,
                    label: Some("Example".to_string()),
                },
            )
            .unwrap();

        assert_eq!(credential.origin.display_url(), "https://example.com");
        assert_eq!(
            credential.login_url.as_deref(),
            Some("https://example.com/login")
        );
        assert_eq!(
            plane.list_credentials_for_tab(&tab.id).unwrap(),
            vec![credential.clone()]
        );
        let updated_credential = plane
            .store_credential_for_tab(
                &tab.id,
                StoreTabCredentialRequest {
                    username: "me".to_string(),
                    password: "new-secret".to_string(),
                    login_url: None,
                    label: None,
                },
            )
            .unwrap();
        assert_eq!(updated_credential.id, credential.id);
        assert_eq!(
            updated_credential.created_at_unix,
            credential.created_at_unix
        );
        assert_eq!(updated_credential.label.as_deref(), Some("Example"));
        assert_eq!(
            plane.list_credentials_for_tab(&tab.id).unwrap(),
            vec![updated_credential.clone()]
        );
        assert_eq!(
            plane
                .credential_material_for_browser(&credential.id)
                .unwrap()
                .password,
            "new-secret"
        );

        let command = plane
            .fill_credential_for_tab(&tab.id, &updated_credential.id)
            .unwrap();
        match &command.kind {
            BrowserCommandKind::FillLogin {
                username,
                target_origin,
                ..
            } => {
                assert_eq!(username, "me");
                assert_eq!(target_origin.display_url(), "https://example.com");
            }
            other => panic!("unexpected command kind: {other:?}"),
        }
        assert!(!serde_json::to_string(&command).unwrap().contains("secret"));

        plane
            .delete_credential_for_tab(&tab.id, &updated_credential.id)
            .unwrap();
        assert!(plane.list_credentials_for_tab(&tab.id).unwrap().is_empty());
        assert!(matches!(
            plane.credential_material_for_browser(&updated_credential.id),
            Err(ControlError::Core(TelescopeError::CredentialNotFound(_)))
        ));
        assert!(plane.list_audit_events().unwrap().iter().any(|event| {
            matches!(
                event.kind,
                AuditEventKind::CredentialDeleted { ref credential_id }
                    if credential_id == &updated_credential.id
            )
        }));
    }

    #[test]
    fn active_tab_credential_actions_reject_cross_origin_credentials() {
        let plane = plane();
        let tab = plane
            .create_tab(CreateTabRequest {
                url: Some("https://example.com/login".to_string()),
                session_id: None,
            })
            .unwrap();
        let credential = plane
            .store_credential(CredentialInput {
                origin: "https://attacker.example".to_string(),
                username: "me".to_string(),
                password: "secret".to_string(),
                login_url: None,
                label: None,
            })
            .unwrap();

        let error = plane
            .fill_credential_for_tab(&tab.id, &credential.id)
            .unwrap_err();
        assert!(matches!(
            error,
            ControlError::Core(TelescopeError::PolicyDenied(_))
        ));

        let error = plane
            .delete_credential_for_tab(&tab.id, &credential.id)
            .unwrap_err();
        assert!(matches!(
            error,
            ControlError::Core(TelescopeError::PolicyDenied(_))
        ));
        assert!(plane
            .credential_material_for_browser(&credential.id)
            .is_ok());
    }

    #[test]
    fn audit_events_are_persisted_and_redact_sensitive_payloads() {
        let mut path = std::env::temp_dir();
        let nonce = now_unix();
        path.push(format!("telescope-audit-{nonce}-{}.jsonl", Uuid::new_v4()));
        let store = Arc::new(MemorySecretStore::new());
        let plane = ControlPlane::with_audit_log(
            CredentialVault::ephemeral("audit-test", store.clone()),
            &path,
        )
        .unwrap();
        let session = plane
            .create_session(CreateSessionRequest {
                allowed_origins: vec!["https://example.com".to_string()],
                allow_credentials: true,
                allow_interactions: true,
                allow_scripts: true,
                ttl_seconds: Some(60),
            })
            .unwrap();
        let tab = plane
            .create_tab(CreateTabRequest {
                url: Some("https://example.com/login".to_string()),
                session_id: Some(session.id.clone()),
            })
            .unwrap();
        let credential = plane
            .store_credential(CredentialInput {
                origin: "https://example.com".to_string(),
                username: "me".to_string(),
                password: "secret".to_string(),
                login_url: None,
                label: None,
            })
            .unwrap();
        plane
            .fill_login(
                &tab.id,
                FillLoginRequest {
                    session_id: session.id.clone(),
                    credential_id: credential.id.clone(),
                },
            )
            .unwrap();
        plane
            .queue_agent_action(
                &tab.id,
                AgentActionRequest {
                    session_id: session.id.clone(),
                    action: AgentAction::TypeText {
                        selector: Some("input[type=password]".to_string()),
                        element_ref_id: None,
                        text: "typed secret".to_string(),
                        clear_first: true,
                    },
                },
            )
            .unwrap();
        plane
            .queue_agent_action(
                &tab.id,
                AgentActionRequest {
                    session_id: session.id.clone(),
                    action: AgentAction::SelectOption {
                        selector: Some("select[name=role]".to_string()),
                        element_ref_id: None,
                        value: "select secret".to_string(),
                    },
                },
            )
            .unwrap();
        plane
            .queue_agent_action(
                &tab.id,
                AgentActionRequest {
                    session_id: session.id.clone(),
                    action: AgentAction::SetChecked {
                        selector: Some("input[type=checkbox]".to_string()),
                        element_ref_id: None,
                        checked: true,
                    },
                },
            )
            .unwrap();
        plane
            .queue_agent_action(
                &tab.id,
                AgentActionRequest {
                    session_id: session.id,
                    action: AgentAction::ExecuteScript {
                        script: "return 'script secret';".to_string(),
                    },
                },
            )
            .unwrap();

        let events = plane.list_audit_events().unwrap();
        assert!(events
            .iter()
            .any(|event| matches!(event.kind, AuditEventKind::CredentialStored { .. })));
        assert!(events
            .iter()
            .any(|event| matches!(event.kind, AuditEventKind::CredentialFillQueued { .. })));
        assert!(events.iter().any(|event| matches!(
            event.kind,
            AuditEventKind::AgentActionQueued {
                action: AgentActionAudit::TypeText { .. },
                ..
            }
        )));
        assert!(events.iter().any(|event| matches!(
            event.kind,
            AuditEventKind::AgentActionQueued {
                action: AgentActionAudit::SelectOption { .. },
                ..
            }
        )));
        assert!(events.iter().any(|event| matches!(
            event.kind,
            AuditEventKind::AgentActionQueued {
                action: AgentActionAudit::SetChecked { checked: true, .. },
                ..
            }
        )));
        assert!(events.iter().any(|event| matches!(
            event.kind,
            AuditEventKind::AgentActionQueued {
                action: AgentActionAudit::ExecuteScript,
                ..
            }
        )));

        let audit_json = std::fs::read_to_string(&path).unwrap();
        assert!(audit_json.contains("input[type=password]"));
        assert!(!audit_json.contains("secret"));
        assert!(!audit_json.contains("typed secret"));
        assert!(!audit_json.contains("select secret"));
        assert!(!audit_json.contains("script secret"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        let reloaded =
            ControlPlane::with_audit_log(CredentialVault::ephemeral("audit-test-2", store), &path)
                .unwrap();
        assert_eq!(reloaded.list_audit_events().unwrap().len(), events.len());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn bookmarks_are_persisted_private_and_upserted_by_url() {
        let mut dir = std::env::temp_dir();
        let nonce = now_unix();
        dir.push(format!("telescope-bookmarks-{nonce}-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let audit_path = dir.join("audit.jsonl");
        let bookmark_path = dir.join("bookmarks.json");
        let store = Arc::new(MemorySecretStore::new());
        let plane = ControlPlane::with_profile_storage(
            CredentialVault::ephemeral("bookmark-test", store.clone()),
            &audit_path,
            &bookmark_path,
        )
        .unwrap();

        let bookmark = plane
            .create_bookmark(CreateBookmarkRequest {
                url: "https://example.com/dashboard".to_string(),
                title: Some("Dashboard".to_string()),
            })
            .unwrap();
        let updated = plane
            .create_bookmark(CreateBookmarkRequest {
                url: "https://example.com/dashboard".to_string(),
                title: Some("Home".to_string()),
            })
            .unwrap();

        assert_eq!(updated.id, bookmark.id);
        assert_eq!(updated.title.as_deref(), Some("Home"));
        assert_eq!(plane.list_bookmarks().unwrap(), vec![updated.clone()]);
        let bookmark_json = std::fs::read_to_string(&bookmark_path).unwrap();
        assert!(bookmark_json.contains("https://example.com/dashboard"));
        assert!(bookmark_json.contains("Home"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&bookmark_path)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }

        let reloaded = ControlPlane::with_profile_storage(
            CredentialVault::ephemeral("bookmark-test-2", store),
            &audit_path,
            &bookmark_path,
        )
        .unwrap();
        assert_eq!(reloaded.list_bookmarks().unwrap(), vec![updated.clone()]);
        assert_eq!(reloaded.delete_bookmark(&updated.id).unwrap(), updated);
        assert!(reloaded.list_bookmarks().unwrap().is_empty());
        let reloaded_empty = ControlPlane::with_profile_storage(
            CredentialVault::ephemeral("bookmark-test-3", Arc::new(MemorySecretStore::new())),
            &audit_path,
            &bookmark_path,
        )
        .unwrap();
        assert!(reloaded_empty.list_bookmarks().unwrap().is_empty());

        let invalid = plane.create_bookmark(CreateBookmarkRequest {
            url: "javascript:alert(1)".to_string(),
            title: None,
        });
        assert!(invalid.is_err());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn handoff_snapshot_captures_state_without_grant_tokens_or_passwords() {
        let plane = plane();
        let session = plane
            .create_session(CreateSessionRequest {
                allowed_origins: vec!["https://example.com".to_string()],
                allow_credentials: true,
                allow_interactions: true,
                allow_scripts: false,
                ttl_seconds: None,
            })
            .unwrap();
        let tab = plane
            .create_tab(CreateTabRequest {
                url: Some("https://example.com/login".to_string()),
                session_id: Some(session.id.clone()),
            })
            .unwrap();
        plane
            .publish_page_context(PageContextRequest {
                tab_id: tab.id.clone(),
                url: "https://example.com/login".to_string(),
                title: Some("Login".to_string()),
                text_preview: Some("Sign in".to_string()),
                selected_element_id: None,
                interactive_elements: vec![PageInteractiveElement {
                    selector: "button[type=\"submit\"]".to_string(),
                    tag_name: "button".to_string(),
                    role: Some("button".to_string()),
                    label: Some("Sign in".to_string()),
                    text: Some("Sign in".to_string()),
                    input_type: None,
                    bounds: None,
                    disabled: false,
                }],
            })
            .unwrap();
        plane
            .record_element_reference(ElementReferenceInput {
                tab_id: tab.id.clone(),
                url: "https://example.com/login".to_string(),
                selector: "button[type=\"submit\"]".to_string(),
                label: Some("Sign in".to_string()),
                role: Some("button".to_string()),
                text: Some("Sign in".to_string()),
                bounds: None,
            })
            .unwrap();
        let bookmark = plane
            .create_bookmark(CreateBookmarkRequest {
                url: "https://example.com/login".to_string(),
                title: Some("Login".to_string()),
            })
            .unwrap();
        plane
            .store_credential(CredentialInput {
                origin: "https://example.com".to_string(),
                username: "me@example.com".to_string(),
                password: "handoff-secret".to_string(),
                login_url: None,
                label: None,
            })
            .unwrap();
        let grant = plane
            .create_agent_grant(CreateAgentGrantRequest {
                session_id: session.id.clone(),
                allowed_tab_ids: vec![tab.id.clone()],
                allowed_client_origins: vec!["https://codex.example".to_string()],
                ttl_seconds: Some(60),
            })
            .unwrap();
        let pane = plane
            .open_agent_pane(OpenAgentPaneRequest {
                url: "https://codex.example/login".to_string(),
                position: PanePosition::Right,
                attached_tab_id: Some(tab.id.clone()),
                session_id: Some(session.id.clone()),
                agent_grant_token: Some(grant.token.clone()),
            })
            .unwrap();
        let command = plane
            .queue_agent_action(
                &tab.id,
                AgentActionRequest {
                    session_id: session.id.clone(),
                    action: AgentAction::ExtractText {
                        selector: Some("main".to_string()),
                        element_ref_id: None,
                    },
                },
            )
            .unwrap();
        plane
            .record_command_result(
                &command.id,
                &tab.id,
                CommandExecutionStatus::Succeeded,
                Some(r#"{"ok":true,"text":"visible"}"#.to_string()),
            )
            .unwrap();

        let snapshot = plane.handoff_snapshot().unwrap();
        assert_eq!(
            snapshot.active_tab.as_ref().map(|tab| &tab.id),
            Some(&tab.id)
        );
        assert_eq!(snapshot.tabs.len(), 1);
        assert_eq!(snapshot.sessions.len(), 1);
        assert_eq!(snapshot.bookmarks, vec![bookmark]);
        assert_eq!(snapshot.page_contexts.len(), 1);
        assert_eq!(snapshot.element_refs.len(), 1);
        assert_eq!(snapshot.agent_panes, vec![pane]);
        assert_eq!(snapshot.command_results.len(), 1);
        assert!(!snapshot.audit_events.is_empty());

        let snapshot_json = serde_json::to_string(&snapshot).unwrap();
        assert!(snapshot_json.contains("me@example.com"));
        assert!(snapshot_json.contains("visible"));
        assert!(!snapshot_json.contains(&grant.token));
        assert!(!snapshot_json.contains("handoff-secret"));
    }

    #[test]
    fn browser_material_is_available_only_in_process() {
        let plane = plane();
        let record = plane
            .store_credential(CredentialInput {
                origin: "https://example.com".to_string(),
                username: "me".to_string(),
                password: "secret".to_string(),
                login_url: None,
                label: None,
            })
            .unwrap();

        let material = plane.credential_material_for_browser(&record.id).unwrap();
        assert_eq!(material.password, "secret");
    }

    #[test]
    fn create_tab_queues_browser_open_command() {
        let plane = plane();

        let tab = plane
            .create_tab(CreateTabRequest {
                url: Some("https://example.com".to_string()),
                session_id: None,
            })
            .unwrap();

        let commands = plane.poll_commands(Some(&tab.id)).unwrap();
        assert_eq!(commands.len(), 1);
        match &commands[0].kind {
            BrowserCommandKind::OpenTab { tab: command_tab } => {
                assert_eq!(command_tab.id, tab.id);
                assert_eq!(
                    command_tab.current_url.as_deref(),
                    Some("https://example.com")
                );
            }
            other => panic!("unexpected command kind: {other:?}"),
        }
    }

    #[test]
    fn activate_tab_queues_browser_command() {
        let plane = plane();
        let first = plane
            .create_tab(CreateTabRequest {
                url: Some("https://example.com/first".to_string()),
                session_id: None,
            })
            .unwrap();
        let second = plane
            .create_tab(CreateTabRequest {
                url: Some("https://example.com/second".to_string()),
                session_id: None,
            })
            .unwrap();
        assert_eq!(plane.active_tab().unwrap().unwrap().id, second.id);

        plane.poll_commands(None).unwrap();
        let activated = plane.activate_tab(&first.id).unwrap();
        assert_eq!(activated.id, first.id);
        assert_eq!(plane.active_tab().unwrap().unwrap().id, first.id);

        let commands = plane.poll_commands(Some(&first.id)).unwrap();
        assert_eq!(commands.len(), 1);
        assert!(matches!(commands[0].kind, BrowserCommandKind::ActivateTab));
    }

    #[test]
    fn browser_history_and_reload_commands_are_queued_and_audited() {
        let plane = plane();
        let tab = plane
            .create_tab(CreateTabRequest {
                url: Some("https://example.com".to_string()),
                session_id: None,
            })
            .unwrap();
        plane.poll_commands(None).unwrap();

        let back = plane.go_back(&tab.id).unwrap();
        let forward = plane.go_forward(&tab.id).unwrap();
        let reload = plane.reload_tab(&tab.id).unwrap();

        let commands = plane.poll_commands(Some(&tab.id)).unwrap();
        assert_eq!(
            commands,
            vec![back.clone(), forward.clone(), reload.clone()]
        );
        assert!(matches!(commands[0].kind, BrowserCommandKind::GoBack));
        assert!(matches!(commands[1].kind, BrowserCommandKind::GoForward));
        assert!(matches!(commands[2].kind, BrowserCommandKind::Reload));

        let events = plane.list_audit_events().unwrap();
        assert!(events.iter().any(|event| {
            matches!(
                &event.kind,
                AuditEventKind::TabHistoryNavigationQueued {
                    command_id,
                    tab_id,
                    direction: TabHistoryDirection::Back,
                } if command_id == &back.id && tab_id == &tab.id
            )
        }));
        assert!(events.iter().any(|event| {
            matches!(
                &event.kind,
                AuditEventKind::TabHistoryNavigationQueued {
                    command_id,
                    tab_id,
                    direction: TabHistoryDirection::Forward,
                } if command_id == &forward.id && tab_id == &tab.id
            )
        }));
        assert!(events.iter().any(|event| {
            matches!(
                &event.kind,
                AuditEventKind::TabReloadQueued { command_id, tab_id }
                    if command_id == &reload.id && tab_id == &tab.id
            )
        }));
    }

    #[test]
    fn closing_active_tab_queues_activation_for_remaining_tab() {
        let plane = plane();
        let first = plane
            .create_tab(CreateTabRequest {
                url: Some("https://example.com/first".to_string()),
                session_id: None,
            })
            .unwrap();
        let second = plane
            .create_tab(CreateTabRequest {
                url: Some("https://example.com/second".to_string()),
                session_id: None,
            })
            .unwrap();
        plane.poll_commands(None).unwrap();

        let closed = plane.close_tab(&second.id).unwrap();
        assert_eq!(closed.id, second.id);
        assert_eq!(plane.active_tab().unwrap().unwrap().id, first.id);

        let commands = plane.poll_commands(None).unwrap();
        assert_eq!(commands.len(), 2);
        assert!(matches!(commands[0].kind, BrowserCommandKind::CloseTab));
        assert_eq!(commands[0].tab_id, second.id);
        assert!(matches!(commands[1].kind, BrowserCommandKind::ActivateTab));
        assert_eq!(commands[1].tab_id, first.id);
    }

    #[test]
    fn navigation_is_origin_scoped() {
        let plane = plane();
        let session = plane
            .create_session(CreateSessionRequest {
                allowed_origins: vec!["https://example.com".to_string()],
                allow_credentials: false,
                allow_interactions: true,
                allow_scripts: false,
                ttl_seconds: None,
            })
            .unwrap();
        let tab = plane
            .create_tab(CreateTabRequest {
                url: Some("https://example.com".to_string()),
                session_id: Some(session.id.clone()),
            })
            .unwrap();

        let denied = plane
            .navigate_tab(
                &tab.id,
                NavigateRequest {
                    url: "https://attacker.example".to_string(),
                    session_id: Some(session.id),
                },
            )
            .unwrap_err();
        assert!(denied.to_string().contains("not allowed"));
    }

    #[test]
    fn opens_agent_panes_at_requested_edge() {
        let plane = plane();
        let tab = plane
            .register_tab(CreateTabRequest {
                url: Some("https://example.com".to_string()),
                session_id: None,
            })
            .unwrap();

        let pane = plane
            .open_agent_pane(OpenAgentPaneRequest {
                url: "https://codex.example/login".to_string(),
                position: PanePosition::Right,
                attached_tab_id: Some(tab.id.clone()),
                session_id: None,
                agent_grant_token: None,
            })
            .unwrap();

        assert_eq!(pane.position, PanePosition::Right);
        assert_eq!(pane.attached_tab_id, Some(tab.id.clone()));
        assert_eq!(plane.list_agent_panes().unwrap().len(), 1);

        let commands = plane.poll_commands(Some(&tab.id)).unwrap();
        assert_eq!(commands.len(), 1);
        match &commands[0].kind {
            BrowserCommandKind::OpenAgentPane { pane, connection } => {
                assert_eq!(pane.position, PanePosition::Right);
                assert_eq!(pane.url, "https://codex.example/login");
                assert!(connection.is_none());
            }
            other => panic!("unexpected command kind: {other:?}"),
        }
    }

    #[test]
    fn open_scoped_agent_pane_for_active_tab_creates_session_grant_and_connection() {
        let plane = plane();
        let tab = plane
            .create_tab(CreateTabRequest {
                url: Some("https://example.com/dashboard".to_string()),
                session_id: None,
            })
            .unwrap();
        plane.poll_commands(None).unwrap();

        let opened = plane
            .open_scoped_agent_pane(OpenScopedAgentPaneRequest {
                url: "https://codex.example/login".to_string(),
                position: PanePosition::Right,
                tab_id: None,
                allow_credentials: true,
                allow_interactions: true,
                allow_scripts: false,
                ttl_seconds: Some(600),
            })
            .unwrap();

        assert_eq!(
            opened.pane.attached_tab_id.as_deref(),
            Some(tab.id.as_str())
        );
        assert_eq!(
            opened.pane.session_id.as_deref(),
            Some(opened.session.id.as_str())
        );
        assert_eq!(opened.grant.session_id, opened.session.id);
        assert_eq!(opened.grant.allowed_tab_ids, vec![tab.id.clone()]);
        assert_eq!(
            opened.grant.allowed_client_origins[0].display_url(),
            "https://codex.example"
        );
        assert_eq!(opened.connection.pane_id, opened.pane.id);
        assert_eq!(opened.connection.tab_id, tab.id);
        assert_eq!(opened.connection.grant_token, opened.grant.token);
        assert_eq!(
            opened.connection.session_policy,
            opened.session.policy.clone()
        );
        assert!(opened.connection.session_policy.allow_credentials);
        assert!(opened.connection.session_policy.allow_interactions);
        assert!(!opened.connection.session_policy.allow_scripts);
        assert_eq!(
            plane.active_tab().unwrap().unwrap().session_id.as_deref(),
            Some(opened.connection.session_id.as_str())
        );

        let commands = plane.poll_commands(None).unwrap();
        assert_eq!(commands.len(), 1);
        match &commands[0].kind {
            BrowserCommandKind::OpenAgentPane { pane, connection } => {
                assert_eq!(pane.id, opened.pane.id);
                assert!(connection.is_some());
            }
            other => panic!("unexpected command kind: {other:?}"),
        }
    }

    #[test]
    fn open_scoped_agent_pane_requires_active_web_url() {
        let plane = plane();
        plane
            .create_tab(CreateTabRequest {
                url: Some("about:blank".to_string()),
                session_id: None,
            })
            .unwrap();

        let error = plane
            .open_scoped_agent_pane(OpenScopedAgentPaneRequest {
                url: "https://codex.example/login".to_string(),
                position: PanePosition::Left,
                tab_id: None,
                allow_credentials: true,
                allow_interactions: true,
                allow_scripts: false,
                ttl_seconds: Some(600),
            })
            .unwrap_err();
        assert!(matches!(
            error,
            ControlError::Core(TelescopeError::InvalidOrigin(_))
        ));
    }

    #[test]
    fn closes_agent_pane_and_queues_browser_command() {
        let plane = plane();
        let tab = plane
            .register_tab(CreateTabRequest {
                url: Some("https://example.com".to_string()),
                session_id: None,
            })
            .unwrap();
        let pane = plane
            .open_agent_pane(OpenAgentPaneRequest {
                url: "https://codex.example/login".to_string(),
                position: PanePosition::Bottom,
                attached_tab_id: Some(tab.id.clone()),
                session_id: None,
                agent_grant_token: None,
            })
            .unwrap();
        plane.poll_commands(Some(&tab.id)).unwrap();

        let closed = plane.close_agent_pane(&pane.id).unwrap();

        assert_eq!(closed.id, pane.id);
        assert!(plane.list_agent_panes().unwrap().is_empty());
        let commands = plane.poll_commands(Some(&tab.id)).unwrap();
        assert_eq!(commands.len(), 1);
        match &commands[0].kind {
            BrowserCommandKind::CloseAgentPane { pane_id } => assert_eq!(pane_id, &pane.id),
            other => panic!("unexpected command kind: {other:?}"),
        }
    }

    #[test]
    fn close_tab_removes_context_refs_and_attached_panes() {
        let plane = plane();
        let tab = plane
            .create_tab(CreateTabRequest {
                url: Some("https://example.com/dashboard".to_string()),
                session_id: None,
            })
            .unwrap();
        plane.poll_commands(Some(&tab.id)).unwrap();
        let pane = plane
            .open_agent_pane(OpenAgentPaneRequest {
                url: "https://codex.example/login".to_string(),
                position: PanePosition::Right,
                attached_tab_id: Some(tab.id.clone()),
                session_id: None,
                agent_grant_token: None,
            })
            .unwrap();
        plane
            .publish_page_context(PageContextRequest {
                tab_id: tab.id.clone(),
                url: "https://example.com/dashboard".to_string(),
                title: Some("Dashboard".to_string()),
                text_preview: Some("Account".to_string()),
                selected_element_id: None,
                interactive_elements: Vec::new(),
            })
            .unwrap();
        plane
            .record_element_reference(ElementReferenceInput {
                tab_id: tab.id.clone(),
                url: "https://example.com/dashboard".to_string(),
                selector: "main".to_string(),
                label: None,
                role: None,
                text: None,
                bounds: None,
            })
            .unwrap();
        plane.poll_commands(Some(&tab.id)).unwrap();

        let closed = plane.close_tab(&tab.id).unwrap();

        assert_eq!(closed.id, tab.id);
        assert!(plane.list_tabs().unwrap().is_empty());
        assert!(plane.list_agent_panes().unwrap().is_empty());
        assert!(plane.agent_pane_connection(&pane.id).is_err());
        assert!(plane.list_page_contexts().unwrap().is_empty());
        assert!(plane.list_element_references().unwrap().is_empty());
        let commands = plane.poll_commands(Some(&tab.id)).unwrap();
        assert_eq!(commands.len(), 2);
        match &commands[0].kind {
            BrowserCommandKind::CloseAgentPane { pane_id } => assert_eq!(pane_id, &pane.id),
            other => panic!("unexpected command kind: {other:?}"),
        }
        assert!(matches!(commands[1].kind, BrowserCommandKind::CloseTab));
    }

    #[test]
    fn page_context_updates_authoritative_tab_location() {
        let plane = plane();
        let tab = plane
            .register_tab(CreateTabRequest {
                url: Some("https://example.com/dashboard".to_string()),
                session_id: None,
            })
            .unwrap();

        let snapshot = plane
            .publish_page_context(PageContextRequest {
                tab_id: tab.id.clone(),
                url: "https://example.com/settings".to_string(),
                title: Some("Settings".to_string()),
                text_preview: Some("Account settings".to_string()),
                selected_element_id: None,
                interactive_elements: Vec::new(),
            })
            .unwrap();

        assert_eq!(snapshot.url, "https://example.com/settings");
        let updated = plane.list_tabs().unwrap();
        assert_eq!(updated.len(), 1);
        assert_eq!(
            updated[0].current_url.as_deref(),
            Some("https://example.com/settings")
        );
        assert_eq!(updated[0].title.as_deref(), Some("Settings"));
        assert!(updated[0].updated_at_unix >= tab.updated_at_unix);
    }

    #[test]
    fn page_context_stores_bounded_interactive_elements_without_password_text() {
        let plane = plane();
        let tab = plane
            .register_tab(CreateTabRequest {
                url: Some("https://example.com/login".to_string()),
                session_id: None,
            })
            .unwrap();
        let mut interactive_elements = vec![
            PageInteractiveElement {
                selector: "".to_string(),
                tag_name: "button".to_string(),
                role: Some("button".to_string()),
                label: None,
                text: None,
                input_type: None,
                bounds: None,
                disabled: false,
            },
            PageInteractiveElement {
                selector: "#password".to_string(),
                tag_name: "input".to_string(),
                role: Some("textbox".to_string()),
                label: Some("Password".repeat(80)),
                text: Some("secret-password".to_string()),
                input_type: Some("password".to_string()),
                bounds: Some(ElementBounds {
                    x: 1.0,
                    y: 2.0,
                    width: 3.0,
                    height: 4.0,
                }),
                disabled: false,
            },
        ];
        for index in 0..100 {
            interactive_elements.push(PageInteractiveElement {
                selector: format!("#item-{index}"),
                tag_name: "button".to_string(),
                role: Some("button".to_string()),
                label: Some("Action".to_string()),
                text: Some("Click me".to_string()),
                input_type: None,
                bounds: None,
                disabled: false,
            });
        }

        let snapshot = plane
            .publish_page_context(PageContextRequest {
                tab_id: tab.id,
                url: "https://example.com/login".to_string(),
                title: Some("Login".to_string()),
                text_preview: Some("Welcome".to_string()),
                selected_element_id: None,
                interactive_elements,
            })
            .unwrap();

        assert_eq!(snapshot.interactive_elements.len(), 80);
        assert!(snapshot
            .interactive_elements
            .iter()
            .all(|element| !element.selector.trim().is_empty()));
        let password = snapshot
            .interactive_elements
            .iter()
            .find(|element| element.selector == "#password")
            .unwrap();
        assert_eq!(password.input_type.as_deref(), Some("password"));
        assert!(password.text.is_none());
        assert!(password.label.as_ref().unwrap().chars().count() <= 240);
    }

    #[test]
    fn observed_cross_origin_navigation_blocks_agent_actions() {
        let plane = plane();
        let session = plane
            .create_session(CreateSessionRequest {
                allowed_origins: vec!["https://example.com".to_string()],
                allow_credentials: false,
                allow_interactions: true,
                allow_scripts: false,
                ttl_seconds: None,
            })
            .unwrap();
        let tab = plane
            .register_tab(CreateTabRequest {
                url: Some("https://example.com/dashboard".to_string()),
                session_id: Some(session.id.clone()),
            })
            .unwrap();
        plane
            .publish_page_context(PageContextRequest {
                tab_id: tab.id.clone(),
                url: "https://attacker.example/dashboard".to_string(),
                title: Some("Different origin".to_string()),
                text_preview: Some("Not the allowed origin".to_string()),
                selected_element_id: None,
                interactive_elements: Vec::new(),
            })
            .unwrap();

        let denied = plane
            .queue_agent_action(
                &tab.id,
                AgentActionRequest {
                    session_id: session.id.clone(),
                    action: AgentAction::Click {
                        selector: Some("button".to_string()),
                        element_ref_id: None,
                    },
                },
            )
            .unwrap_err();

        assert!(denied.to_string().contains("not allowed"));
    }

    #[test]
    fn read_only_sessions_can_read_but_not_interact() {
        let plane = plane();
        let session = plane
            .create_session(CreateSessionRequest {
                allowed_origins: vec!["https://example.com".to_string()],
                allow_credentials: false,
                allow_interactions: false,
                allow_scripts: false,
                ttl_seconds: None,
            })
            .unwrap();
        let tab = plane
            .register_tab(CreateTabRequest {
                url: Some("https://example.com/dashboard".to_string()),
                session_id: Some(session.id.clone()),
            })
            .unwrap();

        let extract = plane
            .queue_agent_action(
                &tab.id,
                AgentActionRequest {
                    session_id: session.id.clone(),
                    action: AgentAction::ExtractText {
                        selector: Some("main".to_string()),
                        element_ref_id: None,
                    },
                },
            )
            .unwrap();
        assert!(matches!(
            extract.kind,
            BrowserCommandKind::AgentAction {
                action: AgentAction::ExtractText { .. },
                ..
            }
        ));
        let inspect = plane
            .queue_agent_action(
                &tab.id,
                AgentActionRequest {
                    session_id: session.id.clone(),
                    action: AgentAction::InspectElement {
                        selector: Some("button".to_string()),
                        element_ref_id: None,
                    },
                },
            )
            .unwrap();
        assert!(matches!(
            inspect.kind,
            BrowserCommandKind::AgentAction {
                action: AgentAction::InspectElement { .. },
                ..
            }
        ));

        let denied = plane
            .queue_agent_action(
                &tab.id,
                AgentActionRequest {
                    session_id: session.id.clone(),
                    action: AgentAction::Click {
                        selector: Some("button".to_string()),
                        element_ref_id: None,
                    },
                },
            )
            .unwrap_err();

        assert!(denied.to_string().contains("cannot interact"));

        let denied = plane
            .queue_agent_action(
                &tab.id,
                AgentActionRequest {
                    session_id: session.id.clone(),
                    action: AgentAction::DoubleClick {
                        selector: Some("button".to_string()),
                        element_ref_id: None,
                    },
                },
            )
            .unwrap_err();
        assert!(denied.to_string().contains("cannot interact"));

        let denied = plane
            .queue_agent_action(
                &tab.id,
                AgentActionRequest {
                    session_id: session.id.clone(),
                    action: AgentAction::DragTo {
                        source_selector: Some("#source".to_string()),
                        source_element_ref_id: None,
                        target_selector: Some("#target".to_string()),
                        target_element_ref_id: None,
                    },
                },
            )
            .unwrap_err();
        assert!(denied.to_string().contains("cannot interact"));

        let denied = plane
            .queue_agent_action(
                &tab.id,
                AgentActionRequest {
                    session_id: session.id.clone(),
                    action: AgentAction::Hover {
                        selector: Some("button".to_string()),
                        element_ref_id: None,
                    },
                },
            )
            .unwrap_err();
        assert!(denied.to_string().contains("cannot interact"));

        let denied = plane
            .queue_agent_action(
                &tab.id,
                AgentActionRequest {
                    session_id: session.id.clone(),
                    action: AgentAction::Focus {
                        selector: Some("input".to_string()),
                        element_ref_id: None,
                    },
                },
            )
            .unwrap_err();
        assert!(denied.to_string().contains("cannot interact"));

        let denied = plane
            .queue_agent_action(
                &tab.id,
                AgentActionRequest {
                    session_id: session.id.clone(),
                    action: AgentAction::SelectOption {
                        selector: Some("select".to_string()),
                        element_ref_id: None,
                        value: "admin".to_string(),
                    },
                },
            )
            .unwrap_err();
        assert!(denied.to_string().contains("cannot interact"));

        let denied = plane
            .queue_agent_action(
                &tab.id,
                AgentActionRequest {
                    session_id: session.id.clone(),
                    action: AgentAction::SetChecked {
                        selector: Some("input[type=checkbox]".to_string()),
                        element_ref_id: None,
                        checked: true,
                    },
                },
            )
            .unwrap_err();
        assert!(denied.to_string().contains("cannot interact"));

        let denied = plane
            .queue_agent_action(
                &tab.id,
                AgentActionRequest {
                    session_id: session.id.clone(),
                    action: AgentAction::ScrollBy {
                        delta_x: 0,
                        delta_y: 600,
                    },
                },
            )
            .unwrap_err();
        assert!(denied.to_string().contains("cannot interact"));
    }

    #[test]
    fn submit_actions_require_interaction_permission() {
        let plane = plane();
        let session = plane
            .create_session(CreateSessionRequest {
                allowed_origins: vec!["https://example.com".to_string()],
                allow_credentials: false,
                allow_interactions: false,
                allow_scripts: false,
                ttl_seconds: None,
            })
            .unwrap();
        let tab = plane
            .register_tab(CreateTabRequest {
                url: Some("https://example.com/login".to_string()),
                session_id: Some(session.id.clone()),
            })
            .unwrap();

        let denied = plane
            .queue_agent_action(
                &tab.id,
                AgentActionRequest {
                    session_id: session.id,
                    action: AgentAction::Submit {
                        selector: Some("form".to_string()),
                        element_ref_id: None,
                    },
                },
            )
            .unwrap_err();

        assert!(denied.to_string().contains("cannot interact"));
    }

    #[test]
    fn observed_cross_origin_navigation_blocks_credential_fill() {
        let plane = plane();
        let session = plane
            .create_session(CreateSessionRequest {
                allowed_origins: vec!["https://example.com".to_string()],
                allow_credentials: true,
                allow_interactions: true,
                allow_scripts: false,
                ttl_seconds: None,
            })
            .unwrap();
        let tab = plane
            .register_tab(CreateTabRequest {
                url: Some("https://example.com/login".to_string()),
                session_id: Some(session.id.clone()),
            })
            .unwrap();
        let credential = plane
            .store_credential(CredentialInput {
                origin: "https://example.com".to_string(),
                username: "me".to_string(),
                password: "secret".to_string(),
                login_url: None,
                label: None,
            })
            .unwrap();
        plane
            .publish_page_context(PageContextRequest {
                tab_id: tab.id.clone(),
                url: "https://attacker.example/login".to_string(),
                title: Some("Phishing page".to_string()),
                text_preview: Some("Sign in".to_string()),
                selected_element_id: None,
                interactive_elements: Vec::new(),
            })
            .unwrap();

        let denied = plane
            .fill_login(
                &tab.id,
                FillLoginRequest {
                    session_id: session.id,
                    credential_id: credential.id,
                },
            )
            .unwrap_err();

        assert!(denied.to_string().contains("not allowed"));
    }

    #[test]
    fn agent_pane_session_must_match_attached_tab() {
        let plane = plane();
        let session = plane
            .create_session(CreateSessionRequest {
                allowed_origins: vec!["https://example.com".to_string()],
                allow_credentials: false,
                allow_interactions: true,
                allow_scripts: false,
                ttl_seconds: None,
            })
            .unwrap();
        let other_session = plane
            .create_session(CreateSessionRequest {
                allowed_origins: vec!["https://example.com".to_string()],
                allow_credentials: false,
                allow_interactions: true,
                allow_scripts: false,
                ttl_seconds: None,
            })
            .unwrap();
        let tab = plane
            .register_tab(CreateTabRequest {
                url: Some("https://example.com".to_string()),
                session_id: Some(session.id),
            })
            .unwrap();

        let denied = plane
            .open_agent_pane(OpenAgentPaneRequest {
                url: "https://codex.example/login".to_string(),
                position: PanePosition::Left,
                attached_tab_id: Some(tab.id),
                session_id: Some(other_session.id),
                agent_grant_token: None,
            })
            .unwrap_err();

        assert!(denied.to_string().contains("not attached to session"));
    }

    #[test]
    fn revoking_agent_grant_closes_connected_panes() {
        let plane = plane();
        let session = plane
            .create_session(CreateSessionRequest {
                allowed_origins: vec!["https://example.com".to_string()],
                allow_credentials: false,
                allow_interactions: true,
                allow_scripts: false,
                ttl_seconds: None,
            })
            .unwrap();
        let tab = plane
            .register_tab(CreateTabRequest {
                url: Some("https://example.com".to_string()),
                session_id: Some(session.id.clone()),
            })
            .unwrap();
        let grant = plane
            .create_agent_grant(CreateAgentGrantRequest {
                session_id: session.id.clone(),
                allowed_tab_ids: vec![tab.id.clone()],
                allowed_client_origins: Vec::new(),
                ttl_seconds: Some(60),
            })
            .unwrap();
        let pane = plane
            .open_agent_pane(OpenAgentPaneRequest {
                url: "https://codex.example/login".to_string(),
                position: PanePosition::Left,
                attached_tab_id: Some(tab.id.clone()),
                session_id: Some(session.id),
                agent_grant_token: Some(grant.token.clone()),
            })
            .unwrap();
        plane.poll_commands(Some(&tab.id)).unwrap();

        let revoked = plane.revoke_agent_grant(&grant.token).unwrap();

        assert_eq!(revoked.token, grant.token);
        assert_eq!(revoked.closed_pane_ids, vec![pane.id.clone()]);
        assert!(revoked.purged_command_ids.is_empty());
        assert!(plane.list_agent_panes().unwrap().is_empty());
        assert!(plane.agent_pane_connection(&pane.id).is_err());
        assert!(plane.lookup_agent_grant(&grant.token).is_err());
        let commands = plane.poll_commands(Some(&tab.id)).unwrap();
        assert_eq!(commands.len(), 1);
        match &commands[0].kind {
            BrowserCommandKind::CloseAgentPane { pane_id } => assert_eq!(pane_id, &pane.id),
            other => panic!("unexpected command kind: {other:?}"),
        }
    }

    #[test]
    fn revoking_agent_grant_purges_pending_grant_scoped_commands() {
        let plane = plane();
        let session = plane
            .create_session(CreateSessionRequest {
                allowed_origins: vec!["https://example.com".to_string()],
                allow_credentials: false,
                allow_interactions: true,
                allow_scripts: false,
                ttl_seconds: None,
            })
            .unwrap();
        let tab = plane
            .register_tab(CreateTabRequest {
                url: Some("https://example.com".to_string()),
                session_id: Some(session.id.clone()),
            })
            .unwrap();
        let grant = plane
            .create_agent_grant(CreateAgentGrantRequest {
                session_id: session.id.clone(),
                allowed_tab_ids: vec![tab.id.clone()],
                allowed_client_origins: Vec::new(),
                ttl_seconds: Some(60),
            })
            .unwrap();
        let pane = plane
            .open_agent_pane(OpenAgentPaneRequest {
                url: "https://codex.example/login".to_string(),
                position: PanePosition::Left,
                attached_tab_id: Some(tab.id.clone()),
                session_id: Some(session.id.clone()),
                agent_grant_token: Some(grant.token.clone()),
            })
            .unwrap();
        let action = plane
            .queue_agent_action_inner(
                &tab.id,
                AgentActionRequest {
                    session_id: session.id,
                    action: AgentAction::ExtractText {
                        selector: Some("main".to_string()),
                        element_ref_id: None,
                    },
                },
                Some(&grant.token),
            )
            .unwrap();

        let revoked = plane.revoke_agent_grant(&grant.token).unwrap();

        assert_eq!(revoked.closed_pane_ids, vec![pane.id.clone()]);
        assert_eq!(revoked.purged_command_ids.len(), 2);
        assert!(revoked
            .purged_command_ids
            .iter()
            .any(|command_id| command_id == &action.id));
        let commands = plane.poll_commands(Some(&tab.id)).unwrap();
        assert_eq!(commands.len(), 1);
        match &commands[0].kind {
            BrowserCommandKind::CloseAgentPane { pane_id } => assert_eq!(pane_id, &pane.id),
            other => panic!("unexpected command kind: {other:?}"),
        }
    }

    #[test]
    fn revoking_session_revokes_grants_closes_panes_detaches_tabs_and_purges_commands() {
        let plane = plane();
        let session = plane
            .create_session(CreateSessionRequest {
                allowed_origins: vec!["https://example.com".to_string()],
                allow_credentials: false,
                allow_interactions: true,
                allow_scripts: false,
                ttl_seconds: None,
            })
            .unwrap();
        let tab = plane
            .register_tab(CreateTabRequest {
                url: Some("https://example.com/dashboard".to_string()),
                session_id: Some(session.id.clone()),
            })
            .unwrap();
        let grant = plane
            .create_agent_grant(CreateAgentGrantRequest {
                session_id: session.id.clone(),
                allowed_tab_ids: vec![tab.id.clone()],
                allowed_client_origins: Vec::new(),
                ttl_seconds: Some(60),
            })
            .unwrap();
        let pane = plane
            .open_agent_pane(OpenAgentPaneRequest {
                url: "https://codex.example/login".to_string(),
                position: PanePosition::Right,
                attached_tab_id: Some(tab.id.clone()),
                session_id: Some(session.id.clone()),
                agent_grant_token: Some(grant.token.clone()),
            })
            .unwrap();
        plane.poll_commands(Some(&tab.id)).unwrap();
        let action = plane
            .queue_agent_action(
                &tab.id,
                AgentActionRequest {
                    session_id: session.id.clone(),
                    action: AgentAction::ExtractText {
                        selector: Some("main".to_string()),
                        element_ref_id: None,
                    },
                },
            )
            .unwrap();

        let revoked = plane.revoke_session(&session.id).unwrap();

        assert_eq!(revoked.session_id, session.id);
        assert_eq!(revoked.revoked_grant_count, 1);
        assert_eq!(revoked.closed_pane_ids, vec![pane.id.clone()]);
        assert_eq!(revoked.detached_tab_ids, vec![tab.id.clone()]);
        assert_eq!(revoked.purged_command_ids, vec![action.id.clone()]);
        let audit_json = serde_json::to_string(&plane.list_audit_events().unwrap()).unwrap();
        assert!(audit_json.contains("session_revoked"));
        assert!(!audit_json.contains(&grant.token));
        assert!(plane.list_sessions().unwrap().is_empty());
        assert!(plane.lookup_agent_grant(&grant.token).is_err());
        assert!(plane.list_agent_panes().unwrap().is_empty());
        assert!(plane.agent_pane_connection(&pane.id).is_err());
        assert_eq!(
            plane
                .list_tabs()
                .unwrap()
                .into_iter()
                .find(|item| item.id == tab.id)
                .unwrap()
                .session_id,
            None
        );

        let commands = plane.poll_commands(Some(&tab.id)).unwrap();
        assert_eq!(commands.len(), 1);
        match &commands[0].kind {
            BrowserCommandKind::CloseAgentPane { pane_id } => assert_eq!(pane_id, &pane.id),
            other => panic!("unexpected command kind: {other:?}"),
        }
        assert_ne!(commands[0].id, action.id);

        let denied = plane
            .queue_agent_action(
                &tab.id,
                AgentActionRequest {
                    session_id: revoked.session_id,
                    action: AgentAction::ExtractText {
                        selector: Some("main".to_string()),
                        element_ref_id: None,
                    },
                },
            )
            .unwrap_err();
        assert!(denied.to_string().contains("session not found"));
    }

    #[test]
    fn cleanup_expired_access_revokes_expired_session_and_purges_commands() {
        let plane = plane();
        let session = plane
            .create_session(CreateSessionRequest {
                allowed_origins: vec!["https://example.com".to_string()],
                allow_credentials: false,
                allow_interactions: true,
                allow_scripts: false,
                ttl_seconds: None,
            })
            .unwrap();
        let tab = plane
            .register_tab(CreateTabRequest {
                url: Some("https://example.com/dashboard".to_string()),
                session_id: Some(session.id.clone()),
            })
            .unwrap();
        let grant = plane
            .create_agent_grant(CreateAgentGrantRequest {
                session_id: session.id.clone(),
                allowed_tab_ids: vec![tab.id.clone()],
                allowed_client_origins: Vec::new(),
                ttl_seconds: Some(60),
            })
            .unwrap();
        let pane = plane
            .open_agent_pane(OpenAgentPaneRequest {
                url: "https://codex.example/login".to_string(),
                position: PanePosition::Right,
                attached_tab_id: Some(tab.id.clone()),
                session_id: Some(session.id.clone()),
                agent_grant_token: Some(grant.token.clone()),
            })
            .unwrap();
        plane.poll_commands(Some(&tab.id)).unwrap();
        let action = plane
            .queue_agent_action(
                &tab.id,
                AgentActionRequest {
                    session_id: session.id.clone(),
                    action: AgentAction::ExtractText {
                        selector: Some("main".to_string()),
                        element_ref_id: None,
                    },
                },
            )
            .unwrap();
        {
            let mut inner = plane.inner.lock().unwrap();
            inner
                .sessions
                .get_mut(&session.id)
                .unwrap()
                .policy
                .expires_at_unix = Some(now_unix());
        }

        let cleanups = plane.cleanup_expired_access().unwrap();

        assert_eq!(cleanups.len(), 1);
        let ExpiredAccessCleanup::Session(cleanup) = &cleanups[0] else {
            panic!("expected session cleanup");
        };
        assert_eq!(cleanup.session_id, session.id);
        assert_eq!(cleanup.revoked_grant_count, 1);
        assert_eq!(cleanup.closed_pane_ids, vec![pane.id.clone()]);
        assert_eq!(cleanup.detached_tab_ids, vec![tab.id.clone()]);
        assert_eq!(cleanup.purged_command_ids, vec![action.id.clone()]);
        assert!(plane.lookup_agent_grant(&grant.token).is_err());
        assert!(plane.list_agent_panes().unwrap().is_empty());
        let commands = plane.poll_commands(Some(&tab.id)).unwrap();
        assert_eq!(commands.len(), 1);
        assert!(matches!(
            commands[0].kind,
            BrowserCommandKind::CloseAgentPane { .. }
        ));
    }

    #[test]
    fn cleanup_expired_access_revokes_expired_grant_and_closes_pane() {
        let plane = plane();
        let session = plane
            .create_session(CreateSessionRequest {
                allowed_origins: vec!["https://example.com".to_string()],
                allow_credentials: false,
                allow_interactions: true,
                allow_scripts: false,
                ttl_seconds: None,
            })
            .unwrap();
        let tab = plane
            .register_tab(CreateTabRequest {
                url: Some("https://example.com/dashboard".to_string()),
                session_id: Some(session.id.clone()),
            })
            .unwrap();
        let grant = plane
            .create_agent_grant(CreateAgentGrantRequest {
                session_id: session.id.clone(),
                allowed_tab_ids: vec![tab.id.clone()],
                allowed_client_origins: Vec::new(),
                ttl_seconds: Some(60),
            })
            .unwrap();
        let pane = plane
            .open_agent_pane(OpenAgentPaneRequest {
                url: "https://codex.example/login".to_string(),
                position: PanePosition::Right,
                attached_tab_id: Some(tab.id.clone()),
                session_id: Some(session.id.clone()),
                agent_grant_token: Some(grant.token.clone()),
            })
            .unwrap();
        plane.poll_commands(Some(&tab.id)).unwrap();
        {
            let mut inner = plane.inner.lock().unwrap();
            inner
                .agent_grants
                .get_mut(&grant.token)
                .unwrap()
                .expires_at_unix = Some(now_unix());
        }

        let cleanups = plane.cleanup_expired_access().unwrap();

        assert_eq!(cleanups.len(), 1);
        let ExpiredAccessCleanup::Grant(cleanup) = &cleanups[0] else {
            panic!("expected grant cleanup");
        };
        assert_eq!(cleanup.token, grant.token);
        assert_eq!(cleanup.closed_pane_ids, vec![pane.id.clone()]);
        assert!(plane.lookup_agent_grant(&grant.token).is_err());
        assert!(plane.list_agent_panes().unwrap().is_empty());
        assert_eq!(plane.list_sessions().unwrap().len(), 1);
        assert_eq!(
            plane.list_tabs().unwrap()[0].session_id.as_deref(),
            Some(session.id.as_str())
        );
        let commands = plane.poll_commands(Some(&tab.id)).unwrap();
        assert_eq!(commands.len(), 1);
        assert!(matches!(
            commands[0].kind,
            BrowserCommandKind::CloseAgentPane { .. }
        ));
    }

    #[test]
    fn cursor_element_reference_can_drive_agent_action() {
        let plane = plane();
        let session = plane
            .create_session(CreateSessionRequest {
                allowed_origins: vec!["https://example.com".to_string()],
                allow_credentials: false,
                allow_interactions: true,
                allow_scripts: false,
                ttl_seconds: None,
            })
            .unwrap();
        let tab = plane
            .register_tab(CreateTabRequest {
                url: Some("https://example.com/dashboard".to_string()),
                session_id: Some(session.id.clone()),
            })
            .unwrap();
        let reference = plane
            .record_element_reference(ElementReferenceInput {
                tab_id: tab.id.clone(),
                url: "https://example.com/dashboard".to_string(),
                selector: "button[data-action=\"save\"]".to_string(),
                label: Some("Save".to_string()),
                role: Some("button".to_string()),
                text: Some("Save".to_string()),
                bounds: Some(ElementBounds {
                    x: 10.0,
                    y: 20.0,
                    width: 80.0,
                    height: 32.0,
                }),
            })
            .unwrap();

        let command = plane
            .queue_agent_action(
                &tab.id,
                AgentActionRequest {
                    session_id: session.id,
                    action: AgentAction::Click {
                        selector: None,
                        element_ref_id: Some(reference.id),
                    },
                },
            )
            .unwrap();

        match command.kind {
            BrowserCommandKind::AgentAction {
                action:
                    AgentAction::Click {
                        selector: Some(selector),
                        ..
                    },
                target_origin,
            } => {
                assert_eq!(selector, "button[data-action=\"save\"]");
                assert_eq!(target_origin.display_url(), "https://example.com");
            }
            other => panic!("unexpected command kind: {other:?}"),
        }
    }

    #[test]
    fn cursor_element_reference_can_drive_hover_and_focus_actions() {
        let plane = plane();
        let session = plane
            .create_session(CreateSessionRequest {
                allowed_origins: vec!["https://example.com".to_string()],
                allow_credentials: false,
                allow_interactions: true,
                allow_scripts: false,
                ttl_seconds: None,
            })
            .unwrap();
        let tab = plane
            .register_tab(CreateTabRequest {
                url: Some("https://example.com/dashboard".to_string()),
                session_id: Some(session.id.clone()),
            })
            .unwrap();
        let menu_reference = plane
            .record_element_reference(ElementReferenceInput {
                tab_id: tab.id.clone(),
                url: "https://example.com/dashboard".to_string(),
                selector: "button[data-menu=\"account\"]".to_string(),
                label: Some("Account".to_string()),
                role: Some("button".to_string()),
                text: Some("Account".to_string()),
                bounds: None,
            })
            .unwrap();
        let input_reference = plane
            .record_element_reference(ElementReferenceInput {
                tab_id: tab.id.clone(),
                url: "https://example.com/dashboard".to_string(),
                selector: "input[name=\"search\"]".to_string(),
                label: Some("Search".to_string()),
                role: Some("textbox".to_string()),
                text: None,
                bounds: None,
            })
            .unwrap();

        let hover = plane
            .queue_agent_action(
                &tab.id,
                AgentActionRequest {
                    session_id: session.id.clone(),
                    action: AgentAction::Hover {
                        selector: None,
                        element_ref_id: Some(menu_reference.id),
                    },
                },
            )
            .unwrap();
        let focus = plane
            .queue_agent_action(
                &tab.id,
                AgentActionRequest {
                    session_id: session.id,
                    action: AgentAction::Focus {
                        selector: None,
                        element_ref_id: Some(input_reference.id),
                    },
                },
            )
            .unwrap();

        match hover.kind {
            BrowserCommandKind::AgentAction {
                action:
                    AgentAction::Hover {
                        selector: Some(selector),
                        ..
                    },
                target_origin,
            } => {
                assert_eq!(selector, "button[data-menu=\"account\"]");
                assert_eq!(target_origin.display_url(), "https://example.com");
            }
            other => panic!("unexpected command kind: {other:?}"),
        }
        match focus.kind {
            BrowserCommandKind::AgentAction {
                action:
                    AgentAction::Focus {
                        selector: Some(selector),
                        ..
                    },
                target_origin,
            } => {
                assert_eq!(selector, "input[name=\"search\"]");
                assert_eq!(target_origin.display_url(), "https://example.com");
            }
            other => panic!("unexpected command kind: {other:?}"),
        }
    }

    #[test]
    fn cursor_element_reference_can_drive_double_click_and_drag_actions() {
        let plane = plane();
        let session = plane
            .create_session(CreateSessionRequest {
                allowed_origins: vec!["https://example.com".to_string()],
                allow_credentials: false,
                allow_interactions: true,
                allow_scripts: false,
                ttl_seconds: None,
            })
            .unwrap();
        let tab = plane
            .register_tab(CreateTabRequest {
                url: Some("https://example.com/board".to_string()),
                session_id: Some(session.id.clone()),
            })
            .unwrap();
        let card_reference = plane
            .record_element_reference(ElementReferenceInput {
                tab_id: tab.id.clone(),
                url: "https://example.com/board".to_string(),
                selector: "[data-card=\"todo-1\"]".to_string(),
                label: Some("Todo 1".to_string()),
                role: Some("listitem".to_string()),
                text: Some("Todo 1".to_string()),
                bounds: None,
            })
            .unwrap();
        let column_reference = plane
            .record_element_reference(ElementReferenceInput {
                tab_id: tab.id.clone(),
                url: "https://example.com/board".to_string(),
                selector: "[data-column=\"done\"]".to_string(),
                label: Some("Done".to_string()),
                role: Some("list".to_string()),
                text: Some("Done".to_string()),
                bounds: None,
            })
            .unwrap();

        let double_click = plane
            .queue_agent_action(
                &tab.id,
                AgentActionRequest {
                    session_id: session.id.clone(),
                    action: AgentAction::DoubleClick {
                        selector: None,
                        element_ref_id: Some(card_reference.id.clone()),
                    },
                },
            )
            .unwrap();
        let drag = plane
            .queue_agent_action(
                &tab.id,
                AgentActionRequest {
                    session_id: session.id,
                    action: AgentAction::DragTo {
                        source_selector: None,
                        source_element_ref_id: Some(card_reference.id),
                        target_selector: None,
                        target_element_ref_id: Some(column_reference.id),
                    },
                },
            )
            .unwrap();

        match double_click.kind {
            BrowserCommandKind::AgentAction {
                action:
                    AgentAction::DoubleClick {
                        selector: Some(selector),
                        ..
                    },
                target_origin,
            } => {
                assert_eq!(selector, "[data-card=\"todo-1\"]");
                assert_eq!(target_origin.display_url(), "https://example.com");
            }
            other => panic!("unexpected command kind: {other:?}"),
        }
        match drag.kind {
            BrowserCommandKind::AgentAction {
                action:
                    AgentAction::DragTo {
                        source_selector: Some(source_selector),
                        target_selector: Some(target_selector),
                        ..
                    },
                target_origin,
            } => {
                assert_eq!(source_selector, "[data-card=\"todo-1\"]");
                assert_eq!(target_selector, "[data-column=\"done\"]");
                assert_eq!(target_origin.display_url(), "https://example.com");
            }
            other => panic!("unexpected command kind: {other:?}"),
        }
    }

    #[test]
    fn cursor_element_reference_can_drive_inspect_action() {
        let plane = plane();
        let session = plane
            .create_session(CreateSessionRequest {
                allowed_origins: vec!["https://example.com".to_string()],
                allow_credentials: false,
                allow_interactions: false,
                allow_scripts: false,
                ttl_seconds: None,
            })
            .unwrap();
        let tab = plane
            .register_tab(CreateTabRequest {
                url: Some("https://example.com/profile".to_string()),
                session_id: Some(session.id.clone()),
            })
            .unwrap();
        let reference = plane
            .record_element_reference(ElementReferenceInput {
                tab_id: tab.id.clone(),
                url: "https://example.com/profile".to_string(),
                selector: "button[data-action=\"edit\"]".to_string(),
                label: Some("Edit".to_string()),
                role: Some("button".to_string()),
                text: Some("Edit".to_string()),
                bounds: None,
            })
            .unwrap();

        let command = plane
            .queue_agent_action(
                &tab.id,
                AgentActionRequest {
                    session_id: session.id,
                    action: AgentAction::InspectElement {
                        selector: None,
                        element_ref_id: Some(reference.id),
                    },
                },
            )
            .unwrap();

        match command.kind {
            BrowserCommandKind::AgentAction {
                action:
                    AgentAction::InspectElement {
                        selector: Some(selector),
                        ..
                    },
                target_origin,
            } => {
                assert_eq!(selector, "button[data-action=\"edit\"]");
                assert_eq!(target_origin.display_url(), "https://example.com");
            }
            other => panic!("unexpected command kind: {other:?}"),
        }
    }

    #[test]
    fn cursor_element_reference_can_drive_submit_action() {
        let plane = plane();
        let session = plane
            .create_session(CreateSessionRequest {
                allowed_origins: vec!["https://example.com".to_string()],
                allow_credentials: false,
                allow_interactions: true,
                allow_scripts: false,
                ttl_seconds: None,
            })
            .unwrap();
        let tab = plane
            .register_tab(CreateTabRequest {
                url: Some("https://example.com/login".to_string()),
                session_id: Some(session.id.clone()),
            })
            .unwrap();
        let reference = plane
            .record_element_reference(ElementReferenceInput {
                tab_id: tab.id.clone(),
                url: "https://example.com/login".to_string(),
                selector: "button[type=\"submit\"]".to_string(),
                label: Some("Sign in".to_string()),
                role: Some("button".to_string()),
                text: Some("Sign in".to_string()),
                bounds: None,
            })
            .unwrap();

        let command = plane
            .queue_agent_action(
                &tab.id,
                AgentActionRequest {
                    session_id: session.id,
                    action: AgentAction::Submit {
                        selector: None,
                        element_ref_id: Some(reference.id),
                    },
                },
            )
            .unwrap();

        match command.kind {
            BrowserCommandKind::AgentAction {
                action:
                    AgentAction::Submit {
                        selector: Some(selector),
                        ..
                    },
                target_origin,
            } => {
                assert_eq!(selector, "button[type=\"submit\"]");
                assert_eq!(target_origin.display_url(), "https://example.com");
            }
            other => panic!("unexpected command kind: {other:?}"),
        }
    }

    #[test]
    fn cursor_element_reference_can_drive_scroll_into_view_action() {
        let plane = plane();
        let session = plane
            .create_session(CreateSessionRequest {
                allowed_origins: vec!["https://example.com".to_string()],
                allow_credentials: false,
                allow_interactions: true,
                allow_scripts: false,
                ttl_seconds: None,
            })
            .unwrap();
        let tab = plane
            .register_tab(CreateTabRequest {
                url: Some("https://example.com/dashboard".to_string()),
                session_id: Some(session.id.clone()),
            })
            .unwrap();
        let reference = plane
            .record_element_reference(ElementReferenceInput {
                tab_id: tab.id.clone(),
                url: "https://example.com/dashboard".to_string(),
                selector: "#deep-section".to_string(),
                label: Some("Deep Section".to_string()),
                role: Some("region".to_string()),
                text: Some("Deep Section".to_string()),
                bounds: Some(ElementBounds {
                    x: 0.0,
                    y: 2400.0,
                    width: 720.0,
                    height: 320.0,
                }),
            })
            .unwrap();

        let command = plane
            .queue_agent_action(
                &tab.id,
                AgentActionRequest {
                    session_id: session.id,
                    action: AgentAction::ScrollIntoView {
                        selector: None,
                        element_ref_id: Some(reference.id),
                    },
                },
            )
            .unwrap();

        match command.kind {
            BrowserCommandKind::AgentAction {
                action:
                    AgentAction::ScrollIntoView {
                        selector: Some(selector),
                        ..
                    },
                target_origin,
            } => {
                assert_eq!(selector, "#deep-section");
                assert_eq!(target_origin.display_url(), "https://example.com");
            }
            other => panic!("unexpected command kind: {other:?}"),
        }
    }

    #[test]
    fn cursor_element_reference_can_drive_select_and_checked_actions() {
        let plane = plane();
        let session = plane
            .create_session(CreateSessionRequest {
                allowed_origins: vec!["https://example.com".to_string()],
                allow_credentials: false,
                allow_interactions: true,
                allow_scripts: false,
                ttl_seconds: None,
            })
            .unwrap();
        let tab = plane
            .register_tab(CreateTabRequest {
                url: Some("https://example.com/settings".to_string()),
                session_id: Some(session.id.clone()),
            })
            .unwrap();
        let select_reference = plane
            .record_element_reference(ElementReferenceInput {
                tab_id: tab.id.clone(),
                url: "https://example.com/settings".to_string(),
                selector: "select[name=\"timezone\"]".to_string(),
                label: Some("Timezone".to_string()),
                role: Some("combobox".to_string()),
                text: None,
                bounds: None,
            })
            .unwrap();
        let checkbox_reference = plane
            .record_element_reference(ElementReferenceInput {
                tab_id: tab.id.clone(),
                url: "https://example.com/settings".to_string(),
                selector: "input[name=\"email_updates\"]".to_string(),
                label: Some("Email updates".to_string()),
                role: Some("checkbox".to_string()),
                text: None,
                bounds: None,
            })
            .unwrap();

        let select_command = plane
            .queue_agent_action(
                &tab.id,
                AgentActionRequest {
                    session_id: session.id.clone(),
                    action: AgentAction::SelectOption {
                        selector: None,
                        element_ref_id: Some(select_reference.id),
                        value: "UTC".to_string(),
                    },
                },
            )
            .unwrap();
        let checked_command = plane
            .queue_agent_action(
                &tab.id,
                AgentActionRequest {
                    session_id: session.id,
                    action: AgentAction::SetChecked {
                        selector: None,
                        element_ref_id: Some(checkbox_reference.id),
                        checked: true,
                    },
                },
            )
            .unwrap();

        match select_command.kind {
            BrowserCommandKind::AgentAction {
                action:
                    AgentAction::SelectOption {
                        selector: Some(selector),
                        value,
                        ..
                    },
                target_origin,
            } => {
                assert_eq!(selector, "select[name=\"timezone\"]");
                assert_eq!(value, "UTC");
                assert_eq!(target_origin.display_url(), "https://example.com");
            }
            other => panic!("unexpected command kind: {other:?}"),
        }
        match checked_command.kind {
            BrowserCommandKind::AgentAction {
                action:
                    AgentAction::SetChecked {
                        selector: Some(selector),
                        checked,
                        ..
                    },
                target_origin,
            } => {
                assert_eq!(selector, "input[name=\"email_updates\"]");
                assert!(checked);
                assert_eq!(target_origin.display_url(), "https://example.com");
            }
            other => panic!("unexpected command kind: {other:?}"),
        }
    }

    #[test]
    fn element_reference_origin_must_match_current_tab_origin() {
        let plane = plane();
        let session = plane
            .create_session(CreateSessionRequest {
                allowed_origins: vec![
                    "https://example.com".to_string(),
                    "https://app.example".to_string(),
                ],
                allow_credentials: false,
                allow_interactions: true,
                allow_scripts: false,
                ttl_seconds: None,
            })
            .unwrap();
        let tab = plane
            .register_tab(CreateTabRequest {
                url: Some("https://example.com/dashboard".to_string()),
                session_id: Some(session.id.clone()),
            })
            .unwrap();
        let reference = plane
            .record_element_reference(ElementReferenceInput {
                tab_id: tab.id.clone(),
                url: "https://example.com/dashboard".to_string(),
                selector: "button[data-action=\"save\"]".to_string(),
                label: Some("Save".to_string()),
                role: Some("button".to_string()),
                text: Some("Save".to_string()),
                bounds: None,
            })
            .unwrap();
        plane
            .publish_page_context(PageContextRequest {
                tab_id: tab.id.clone(),
                url: "https://app.example/settings".to_string(),
                title: Some("Settings".to_string()),
                text_preview: None,
                selected_element_id: None,
                interactive_elements: Vec::new(),
            })
            .unwrap();

        let denied = plane
            .queue_agent_action(
                &tab.id,
                AgentActionRequest {
                    session_id: session.id,
                    action: AgentAction::Click {
                        selector: None,
                        element_ref_id: Some(reference.id),
                    },
                },
            )
            .unwrap_err();

        assert!(denied.to_string().contains("was captured for"));
    }

    #[test]
    fn scoped_element_reference_listing_hides_disallowed_current_origin() {
        let plane = plane();
        let session = plane
            .create_session(CreateSessionRequest {
                allowed_origins: vec!["https://example.com".to_string()],
                allow_credentials: false,
                allow_interactions: true,
                allow_scripts: false,
                ttl_seconds: None,
            })
            .unwrap();
        let tab = plane
            .register_tab(CreateTabRequest {
                url: Some("https://example.com/dashboard".to_string()),
                session_id: Some(session.id.clone()),
            })
            .unwrap();
        let grant = plane
            .create_agent_grant(CreateAgentGrantRequest {
                session_id: session.id,
                allowed_tab_ids: vec![tab.id.clone()],
                allowed_client_origins: Vec::new(),
                ttl_seconds: None,
            })
            .unwrap();
        let reference = plane
            .record_element_reference(ElementReferenceInput {
                tab_id: tab.id.clone(),
                url: "https://example.com/dashboard".to_string(),
                selector: "button[data-action=\"save\"]".to_string(),
                label: Some("Save".to_string()),
                role: Some("button".to_string()),
                text: Some("Save".to_string()),
                bounds: None,
            })
            .unwrap();
        let refs = filter_element_refs_for_auth(
            &AuthScope::Agent(grant.clone()),
            &plane,
            plane.list_element_references().unwrap(),
        )
        .unwrap();
        assert_eq!(refs, vec![reference]);

        plane
            .publish_page_context(PageContextRequest {
                tab_id: tab.id,
                url: "https://attacker.example/dashboard".to_string(),
                title: Some("Attacker".to_string()),
                text_preview: None,
                selected_element_id: None,
                interactive_elements: Vec::new(),
            })
            .unwrap();
        let refs = filter_element_refs_for_auth(
            &AuthScope::Agent(grant),
            &plane,
            plane.list_element_references().unwrap(),
        )
        .unwrap();
        assert!(refs.is_empty());
    }

    #[test]
    fn scoped_page_context_listing_hides_disallowed_current_origin() {
        let plane = plane();
        let session = plane
            .create_session(CreateSessionRequest {
                allowed_origins: vec!["https://example.com".to_string()],
                allow_credentials: false,
                allow_interactions: true,
                allow_scripts: false,
                ttl_seconds: None,
            })
            .unwrap();
        let tab = plane
            .register_tab(CreateTabRequest {
                url: Some("https://example.com/dashboard".to_string()),
                session_id: Some(session.id.clone()),
            })
            .unwrap();
        let grant = plane
            .create_agent_grant(CreateAgentGrantRequest {
                session_id: session.id,
                allowed_tab_ids: vec![tab.id.clone()],
                allowed_client_origins: Vec::new(),
                ttl_seconds: None,
            })
            .unwrap();
        let context = plane
            .publish_page_context(PageContextRequest {
                tab_id: tab.id.clone(),
                url: "https://example.com/dashboard".to_string(),
                title: Some("Dashboard".to_string()),
                text_preview: Some("Allowed page text".to_string()),
                selected_element_id: None,
                interactive_elements: Vec::new(),
            })
            .unwrap();
        let visible = filter_page_contexts_for_auth(
            &AuthScope::Agent(grant.clone()),
            &plane,
            plane.list_page_contexts().unwrap(),
        )
        .unwrap();
        assert_eq!(visible, vec![context]);

        plane
            .publish_page_context(PageContextRequest {
                tab_id: tab.id,
                url: "https://attacker.example/dashboard".to_string(),
                title: Some("Attacker".to_string()),
                text_preview: Some("Disallowed page text".to_string()),
                selected_element_id: None,
                interactive_elements: Vec::new(),
            })
            .unwrap();
        let visible = filter_page_contexts_for_auth(
            &AuthScope::Agent(grant),
            &plane,
            plane.list_page_contexts().unwrap(),
        )
        .unwrap();
        assert!(visible.is_empty());
    }

    #[test]
    fn scoped_command_results_are_grant_scoped() {
        let plane = plane();
        let first_session = plane
            .create_session(CreateSessionRequest {
                allowed_origins: vec!["https://example.com".to_string()],
                allow_credentials: false,
                allow_interactions: true,
                allow_scripts: false,
                ttl_seconds: None,
            })
            .unwrap();
        let tab = plane
            .register_tab(CreateTabRequest {
                url: Some("https://example.com/dashboard".to_string()),
                session_id: Some(first_session.id.clone()),
            })
            .unwrap();
        let first_grant = plane
            .create_agent_grant(CreateAgentGrantRequest {
                session_id: first_session.id.clone(),
                allowed_tab_ids: vec![tab.id.clone()],
                allowed_client_origins: Vec::new(),
                ttl_seconds: None,
            })
            .unwrap();
        let same_session_other_grant = plane
            .create_agent_grant(CreateAgentGrantRequest {
                session_id: first_session.id.clone(),
                allowed_tab_ids: vec![tab.id.clone()],
                allowed_client_origins: Vec::new(),
                ttl_seconds: None,
            })
            .unwrap();
        let command = plane
            .queue_agent_action_inner(
                &tab.id,
                AgentActionRequest {
                    session_id: first_session.id.clone(),
                    action: AgentAction::ExtractText {
                        selector: Some("main".to_string()),
                        element_ref_id: None,
                    },
                },
                Some(&first_grant.token),
            )
            .unwrap();
        plane
            .record_command_result(
                &command.id,
                &tab.id,
                CommandExecutionStatus::Succeeded,
                Some(r#"{"text":"private dashboard text"}"#.to_string()),
            )
            .unwrap();
        let results = plane.list_command_results().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].session_id.as_deref(),
            Some(first_session.id.as_str())
        );
        assert_eq!(
            results[0].grant_token.as_deref(),
            Some(first_grant.token.as_str())
        );
        assert_eq!(
            results[0].target_origin.as_ref().unwrap().display_url(),
            "https://example.com"
        );
        let first_visible = filter_command_results_for_auth(
            &AuthScope::Agent(first_grant.clone()),
            &plane,
            results.clone(),
        )
        .unwrap();
        assert_eq!(first_visible.len(), 1);
        assert!(!serde_json::to_string(&first_visible)
            .unwrap()
            .contains(&first_grant.token));
        assert!(filter_command_results_for_auth(
            &AuthScope::Agent(same_session_other_grant),
            &plane,
            results.clone(),
        )
        .unwrap()
        .is_empty());

        let second_session = plane
            .create_session(CreateSessionRequest {
                allowed_origins: vec!["https://example.com".to_string()],
                allow_credentials: false,
                allow_interactions: false,
                allow_scripts: false,
                ttl_seconds: None,
            })
            .unwrap();
        plane
            .navigate_tab(
                &tab.id,
                NavigateRequest {
                    url: "https://example.com/dashboard".to_string(),
                    session_id: Some(second_session.id.clone()),
                },
            )
            .unwrap();
        let second_grant = plane
            .create_agent_grant(CreateAgentGrantRequest {
                session_id: second_session.id,
                allowed_tab_ids: vec![tab.id],
                allowed_client_origins: Vec::new(),
                ttl_seconds: None,
            })
            .unwrap();
        let second_visible =
            filter_command_results_for_auth(&AuthScope::Agent(second_grant), &plane, results)
                .unwrap();
        assert!(second_visible.is_empty());
    }

    #[test]
    fn expired_session_invalidates_agent_grant_access() {
        let plane = plane();
        let session = plane
            .create_session(CreateSessionRequest {
                allowed_origins: vec!["https://example.com".to_string()],
                allow_credentials: false,
                allow_interactions: true,
                allow_scripts: false,
                ttl_seconds: None,
            })
            .unwrap();
        let tab = plane
            .register_tab(CreateTabRequest {
                url: Some("https://example.com/dashboard".to_string()),
                session_id: Some(session.id.clone()),
            })
            .unwrap();
        let grant = plane
            .create_agent_grant(CreateAgentGrantRequest {
                session_id: session.id.clone(),
                allowed_tab_ids: vec![tab.id.clone()],
                allowed_client_origins: Vec::new(),
                ttl_seconds: Some(60),
            })
            .unwrap();
        let command = plane
            .queue_agent_action_inner(
                &tab.id,
                AgentActionRequest {
                    session_id: session.id.clone(),
                    action: AgentAction::ExtractText {
                        selector: Some("main".to_string()),
                        element_ref_id: None,
                    },
                },
                Some(&grant.token),
            )
            .unwrap();
        plane
            .record_command_result(
                &command.id,
                &tab.id,
                CommandExecutionStatus::Succeeded,
                Some(
                    r#"{"ok":true,"action":"extract_text","selector":"main","text":"private"}"#
                        .to_string(),
                ),
            )
            .unwrap();

        {
            let mut inner = plane.inner.lock().unwrap();
            inner
                .sessions
                .get_mut(&session.id)
                .unwrap()
                .policy
                .expires_at_unix = Some(now_unix());
        }

        let error = plane.lookup_agent_grant(&grant.token).unwrap_err();
        assert!(error.to_string().contains("expired"));
        let error = filter_command_results_for_auth(
            &AuthScope::Agent(grant),
            &plane,
            plane.list_command_results().unwrap(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("expired"));
    }

    #[test]
    fn bind_control_server_reports_actual_endpoint() {
        let (server, endpoint) = bind_control_server("127.0.0.1:0").unwrap();
        assert!(endpoint.starts_with("http://127.0.0.1:"));
        assert_ne!(endpoint, "http://127.0.0.1:0");
        drop(server);
    }

    #[test]
    fn custom_scripts_require_script_permission() {
        let plane = plane();
        let session = plane
            .create_session(CreateSessionRequest {
                allowed_origins: vec!["https://example.com".to_string()],
                allow_credentials: false,
                allow_interactions: true,
                allow_scripts: false,
                ttl_seconds: None,
            })
            .unwrap();
        let tab = plane
            .register_tab(CreateTabRequest {
                url: Some("https://example.com".to_string()),
                session_id: Some(session.id.clone()),
            })
            .unwrap();

        let denied = plane
            .queue_agent_action(
                &tab.id,
                AgentActionRequest {
                    session_id: session.id,
                    action: AgentAction::ExecuteScript {
                        script: "document.body.remove()".to_string(),
                    },
                },
            )
            .unwrap_err();

        assert!(denied.to_string().contains("cannot execute custom scripts"));
    }

    #[test]
    fn command_results_are_bounded() {
        let plane = plane();

        for index in 0..505 {
            plane
                .record_command_result(
                    &format!("cmd-{index}"),
                    "tab",
                    CommandExecutionStatus::Succeeded,
                    None,
                )
                .unwrap();
        }

        let results = plane.list_command_results().unwrap();
        assert_eq!(results.len(), 500);
        assert_eq!(results[0].command_id, "cmd-5");
        assert_eq!(results[499].command_id, "cmd-504");
    }
}
