use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;
use std::time::{Duration, Instant};
use thiserror::Error;

pub use telescope_control::{
    AgentAction, AgentActionAudit, AgentActionRequest, AgentGrant, AgentPaneConnection,
    AgentPaneState, AuditEvent, AuditEventKind, BookmarkRecord, BrowserCommand, BrowserCommandKind,
    CommandExecutionReport, CommandExecutionStatus, CommandResultIpcRequest, CommandResultRequest,
    CreateAgentGrantRequest, CreateBookmarkRequest, CreateSessionRequest, CreateTabRequest,
    ElementBounds, ElementReference, ElementReferenceInput, FillLoginRequest, HandoffSnapshot,
    ListLoginOptionsRequest, NavigateRequest, OpenAgentPaneRequest, OpenScopedAgentPaneRequest,
    OpenedScopedAgentPane, PageContextRequest, PageContextSnapshot, PageInteractiveElement,
    PanePosition, RevokedAgentGrant, RevokedAgentSession, StoreTabCredentialRequest,
    TabHistoryDirection, TabState,
};
pub use telescope_core::{AgentPolicy, AgentSession, CredentialInput, CredentialRecord};

#[derive(Debug, Error)]
pub enum SdkError {
    #[error("invalid base URL: {0}")]
    InvalidBaseUrl(String),
    #[error("missing environment variable: {0}")]
    MissingEnv(&'static str),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Core(#[from] telescope_core::TelescopeError),
    #[error("HTTP error: {0}")]
    Http(#[from] ureq::Error),
    #[error("timed out waiting for: {0}")]
    Timeout(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("invalid operation: {0}")]
    InvalidOperation(String),
    #[error("command failed: {0}")]
    CommandFailed(String),
    #[error("missing command result message for: {0}")]
    MissingCommandMessage(String),
    #[error("invalid command result message: {0}")]
    InvalidCommandMessage(String),
}

pub type Result<T> = std::result::Result<T, SdkError>;

#[derive(Clone, Debug)]
pub struct TelescopeClient {
    base_url: String,
    bearer_token: String,
    origin_header: Option<String>,
    agent: ureq::Agent,
}

#[derive(Clone, Debug)]
pub struct BrowserTab {
    pub state: TabState,
    pub client: TelescopeClient,
}

#[derive(Clone, Debug)]
pub struct ScopedAgentPane {
    pub pane: AgentPaneState,
    pub grant: AgentGrant,
    pub connection: AgentPaneConnectionDescriptor,
    pub agent: TelescopeClient,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StoppedAgentPane {
    RevokedGrant(RevokedAgentGrant),
    ClosedPane(AgentPaneState),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HandoffRestoreReport {
    pub opened_tabs: Vec<RestoredHandoffTab>,
    pub skipped_tabs: usize,
    pub imported_bookmarks: Vec<RestoredHandoffBookmark>,
    pub active_tab_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RestoredHandoffTab {
    pub source_tab_id: String,
    pub tab_id: String,
    pub url: String,
    pub active: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RestoredHandoffBookmark {
    pub source_bookmark_id: String,
    pub bookmark_id: String,
    pub url: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HandoffRestoreTabPlan {
    source_tab_id: String,
    url: String,
    active: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopedAgentPaneOptions {
    pub url: String,
    pub position: PanePosition,
    pub allow_credentials: bool,
    pub allow_interactions: bool,
    pub allow_scripts: bool,
    pub ttl_seconds: Option<u64>,
}

impl ScopedAgentPaneOptions {
    pub fn interactive(url: impl Into<String>, position: PanePosition) -> Self {
        Self {
            url: url.into(),
            position,
            allow_credentials: true,
            allow_interactions: true,
            allow_scripts: false,
            ttl_seconds: None,
        }
    }

    pub fn read_only(url: impl Into<String>, position: PanePosition) -> Self {
        Self {
            url: url.into(),
            position,
            allow_credentials: false,
            allow_interactions: false,
            allow_scripts: false,
            ttl_seconds: None,
        }
    }

    pub fn ttl_seconds(mut self, ttl_seconds: Option<u64>) -> Self {
        self.ttl_seconds = ttl_seconds;
        self
    }

    pub fn with_ttl_seconds(mut self, ttl_seconds: u64) -> Self {
        self.ttl_seconds = Some(ttl_seconds);
        self
    }

    pub fn with_credentials(mut self, allow_credentials: bool) -> Self {
        self.allow_credentials = allow_credentials;
        self
    }

    pub fn with_interactions(mut self, allow_interactions: bool) -> Self {
        self.allow_interactions = allow_interactions;
        self
    }

    pub fn with_scripts(mut self, allow_scripts: bool) -> Self {
        self.allow_scripts = allow_scripts;
        self
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentPaneConnectionDescriptor {
    pub control_url: String,
    pub pane_id: String,
    pub pane_url: String,
    pub session_id: String,
    pub tab_id: String,
    pub grant_token: String,
    pub session_policy: AgentPolicy,
    pub expires_at_unix: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct InspectedElement {
    pub selector: String,
    #[serde(rename = "tagName")]
    pub tag_name: String,
    pub id: Option<String>,
    #[serde(rename = "className")]
    pub class_name: Option<String>,
    pub role: Option<String>,
    pub label: Option<String>,
    pub text: Option<String>,
    #[serde(rename = "inputType")]
    pub input_type: Option<String>,
    pub disabled: bool,
    pub checked: Option<bool>,
    pub selected: Option<bool>,
    pub editable: bool,
    pub bounds: ElementBounds,
}

impl InspectedElement {
    pub fn from_command_report(report: CommandExecutionReport) -> Result<Self> {
        parse_inspected_element(report)
    }
}

impl TryFrom<CommandExecutionReport> for InspectedElement {
    type Error = SdkError;

    fn try_from(report: CommandExecutionReport) -> Result<Self> {
        parse_inspected_element(report)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExtractedText {
    pub selector: String,
    pub text: String,
}

impl ExtractedText {
    pub fn from_command_report(report: CommandExecutionReport) -> Result<Self> {
        parse_extracted_text(report)
    }
}

impl TryFrom<CommandExecutionReport> for ExtractedText {
    type Error = SdkError;

    fn try_from(report: CommandExecutionReport) -> Result<Self> {
        parse_extracted_text(report)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SelectorWaitResult {
    pub selector: String,
    #[serde(rename = "timeoutMs")]
    pub timeout_ms: Option<u64>,
}

impl SelectorWaitResult {
    pub fn from_command_report(report: CommandExecutionReport) -> Result<Self> {
        parse_selector_wait_result(report)
    }
}

impl TryFrom<CommandExecutionReport> for SelectorWaitResult {
    type Error = SdkError;

    fn try_from(report: CommandExecutionReport) -> Result<Self> {
        parse_selector_wait_result(report)
    }
}

#[derive(Clone, Debug, Deserialize)]
struct InspectElementMessage {
    ok: bool,
    action: String,
    reason: Option<String>,
    selector: Option<String>,
    #[serde(rename = "tagName")]
    tag_name: Option<String>,
    id: Option<String>,
    #[serde(rename = "className")]
    class_name: Option<String>,
    role: Option<String>,
    label: Option<String>,
    text: Option<String>,
    #[serde(rename = "inputType")]
    input_type: Option<String>,
    disabled: Option<bool>,
    checked: Option<bool>,
    selected: Option<bool>,
    editable: Option<bool>,
    bounds: Option<ElementBounds>,
}

impl InspectElementMessage {
    fn into_element(self) -> Result<InspectedElement> {
        if self.action != "inspect_element" {
            return Err(SdkError::InvalidCommandMessage(format!(
                "expected inspect_element action, got {}",
                self.action
            )));
        }

        Ok(InspectedElement {
            selector: required_result_field(self.selector, "inspect_element", "selector")?,
            tag_name: required_result_field(self.tag_name, "inspect_element", "tagName")?,
            id: self.id,
            class_name: self.class_name,
            role: self.role,
            label: self.label,
            text: self.text,
            input_type: self.input_type,
            disabled: required_result_field(self.disabled, "inspect_element", "disabled")?,
            checked: self.checked,
            selected: self.selected,
            editable: required_result_field(self.editable, "inspect_element", "editable")?,
            bounds: required_result_field(self.bounds, "inspect_element", "bounds")?,
        })
    }
}

#[derive(Clone, Debug, Deserialize)]
struct ExtractTextMessage {
    ok: bool,
    action: Option<String>,
    reason: Option<String>,
    selector: Option<String>,
    text: Option<String>,
}

impl ExtractTextMessage {
    fn into_text(self) -> Result<ExtractedText> {
        let action = required_result_field(self.action, "extract_text", "action")?;
        if action != "extract_text" {
            return Err(SdkError::InvalidCommandMessage(format!(
                "expected extract_text action, got {action}"
            )));
        }

        Ok(ExtractedText {
            selector: required_result_field(self.selector, "extract_text", "selector")?,
            text: required_result_field(self.text, "extract_text", "text")?,
        })
    }
}

#[derive(Clone, Debug, Deserialize)]
struct WaitForSelectorMessage {
    ok: bool,
    action: Option<String>,
    reason: Option<String>,
    selector: Option<String>,
    #[serde(rename = "timeoutMs")]
    timeout_ms: Option<u64>,
}

impl WaitForSelectorMessage {
    fn into_result(self) -> Result<SelectorWaitResult> {
        let action = required_result_field(self.action, "wait_for_selector", "action")?;
        if action != "wait_for_selector" {
            return Err(SdkError::InvalidCommandMessage(format!(
                "expected wait_for_selector action, got {action}"
            )));
        }

        Ok(SelectorWaitResult {
            selector: required_result_field(self.selector, "wait_for_selector", "selector")?,
            timeout_ms: self.timeout_ms,
        })
    }
}

fn required_result_field<T>(
    value: Option<T>,
    action: &'static str,
    field: &'static str,
) -> Result<T> {
    value.ok_or_else(|| SdkError::InvalidCommandMessage(format!("{action} result missing {field}")))
}

fn parse_inspected_element(report: CommandExecutionReport) -> Result<InspectedElement> {
    let command_id = report.command_id.clone();
    let message = report
        .message
        .ok_or_else(|| SdkError::MissingCommandMessage(command_id.clone()))?;
    let parsed = serde_json::from_str::<InspectElementMessage>(&message);

    if report.status != CommandExecutionStatus::Succeeded {
        let reason = parsed
            .ok()
            .and_then(|message| message.reason)
            .unwrap_or(message);
        return Err(SdkError::CommandFailed(format!("{command_id}: {reason}")));
    }

    let parsed = parsed?;
    if !parsed.ok {
        let reason = parsed.reason.unwrap_or(message);
        return Err(SdkError::CommandFailed(format!("{command_id}: {reason}")));
    }

    parsed.into_element()
}

fn parse_extracted_text(report: CommandExecutionReport) -> Result<ExtractedText> {
    let command_id = report.command_id.clone();
    let message = report
        .message
        .ok_or_else(|| SdkError::MissingCommandMessage(command_id.clone()))?;
    let parsed = serde_json::from_str::<ExtractTextMessage>(&message);

    if report.status != CommandExecutionStatus::Succeeded {
        let reason = parsed
            .ok()
            .and_then(|message| message.reason)
            .unwrap_or(message);
        return Err(SdkError::CommandFailed(format!("{command_id}: {reason}")));
    }

    let parsed = parsed?;
    if !parsed.ok {
        let reason = parsed.reason.unwrap_or(message);
        return Err(SdkError::CommandFailed(format!("{command_id}: {reason}")));
    }

    parsed.into_text()
}

fn parse_selector_wait_result(report: CommandExecutionReport) -> Result<SelectorWaitResult> {
    let command_id = report.command_id.clone();
    let message = report
        .message
        .ok_or_else(|| SdkError::MissingCommandMessage(command_id.clone()))?;
    let parsed = serde_json::from_str::<WaitForSelectorMessage>(&message);

    if report.status != CommandExecutionStatus::Succeeded {
        let reason = parsed
            .ok()
            .and_then(|message| message.reason)
            .unwrap_or(message);
        return Err(SdkError::CommandFailed(format!("{command_id}: {reason}")));
    }

    let parsed = parsed?;
    if !parsed.ok {
        let reason = parsed.reason.unwrap_or(message);
        return Err(SdkError::CommandFailed(format!("{command_id}: {reason}")));
    }

    parsed.into_result()
}

impl BrowserTab {
    pub fn id(&self) -> &str {
        &self.state.id
    }

    pub fn state(&self) -> &TabState {
        &self.state
    }

    pub fn into_state(self) -> TabState {
        self.state
    }

    pub fn refresh(&mut self) -> Result<&TabState> {
        let tab_id = self.state.id.clone();
        self.state = self.client.get_tab(&tab_id)?;
        Ok(&self.state)
    }

    pub fn activate(&mut self) -> Result<&TabState> {
        let tab_id = self.state.id.clone();
        self.state = self.client.activate_tab(&tab_id)?;
        Ok(&self.state)
    }

    pub fn navigate(&mut self, url: &str) -> Result<&TabState> {
        let tab_id = self.state.id.clone();
        self.state = self.client.navigate(&tab_id, url, None)?;
        Ok(&self.state)
    }

    pub fn navigate_with_session(&mut self, url: &str, session_id: &str) -> Result<&TabState> {
        let tab_id = self.state.id.clone();
        self.state = self.client.navigate(&tab_id, url, Some(session_id))?;
        Ok(&self.state)
    }

    pub fn navigate_and_wait(
        &mut self,
        url: &str,
        timeout: Duration,
    ) -> Result<PageContextSnapshot> {
        let tab_id = self.state.id.clone();
        self.state = self.client.navigate(&tab_id, url, None)?;
        self.client.wait_for_url(&tab_id, url, timeout)
    }

    pub fn navigate_with_session_and_wait(
        &mut self,
        url: &str,
        session_id: &str,
        timeout: Duration,
    ) -> Result<PageContextSnapshot> {
        let tab_id = self.state.id.clone();
        self.state = self.client.navigate(&tab_id, url, Some(session_id))?;
        self.client.wait_for_url(&tab_id, url, timeout)
    }

    pub fn close(self) -> Result<TabState> {
        self.client.close_tab(&self.state.id)
    }

    pub fn go_back(&self) -> Result<BrowserCommand> {
        self.client.go_back(self.id())
    }

    pub fn go_forward(&self) -> Result<BrowserCommand> {
        self.client.go_forward(self.id())
    }

    pub fn reload(&self) -> Result<BrowserCommand> {
        self.client.reload_tab(self.id())
    }

    pub fn bookmark(&self, title: Option<&str>) -> Result<BookmarkRecord> {
        self.client.bookmark_tab(self.id(), title)
    }

    pub fn open_bookmark(&mut self, bookmark_id: &str) -> Result<&TabState> {
        let tab_id = self.state.id.clone();
        self.state = self.client.open_bookmark_for_tab(&tab_id, bookmark_id)?;
        Ok(&self.state)
    }

    pub fn open_bookmark_in_new_tab(&self, bookmark_id: &str) -> Result<BrowserTab> {
        self.client.open_bookmark_in_new_tab(bookmark_id)
    }

    pub fn list_page_contexts(&self) -> Result<Vec<PageContextSnapshot>> {
        self.client.list_page_contexts_for_tab(self.id())
    }

    pub fn current_page_context(&self) -> Result<Option<PageContextSnapshot>> {
        self.client.page_context_for_tab(self.id())
    }

    pub fn wait_for_page_context<F>(
        &self,
        timeout: Duration,
        predicate: F,
    ) -> Result<PageContextSnapshot>
    where
        F: Fn(&PageContextSnapshot) -> bool,
    {
        self.client
            .wait_for_page_context(self.id(), timeout, predicate)
    }

    pub fn wait_for_url(&self, url: &str, timeout: Duration) -> Result<PageContextSnapshot> {
        self.client.wait_for_url(self.id(), url, timeout)
    }

    pub fn wait_for_url_contains(
        &self,
        fragment: &str,
        timeout: Duration,
    ) -> Result<PageContextSnapshot> {
        self.client
            .wait_for_url_contains(self.id(), fragment, timeout)
    }

    pub fn wait_for_title_contains(
        &self,
        text: &str,
        timeout: Duration,
    ) -> Result<PageContextSnapshot> {
        self.client
            .wait_for_title_contains(self.id(), text, timeout)
    }

    pub fn wait_for_text_contains(
        &self,
        text: &str,
        timeout: Duration,
    ) -> Result<PageContextSnapshot> {
        self.client.wait_for_text_contains(self.id(), text, timeout)
    }

    pub fn list_element_references(&self) -> Result<Vec<ElementReference>> {
        self.client.list_element_references_for_tab(self.id())
    }

    pub fn wait_for_next_element_reference(&self, timeout: Duration) -> Result<ElementReference> {
        self.client
            .wait_for_next_element_reference(self.id(), timeout)
    }

    pub fn list_command_results(&self) -> Result<Vec<CommandExecutionReport>> {
        self.client.list_command_results_for_tab(self.id())
    }

    pub fn list_credentials(&self) -> Result<Vec<CredentialRecord>> {
        self.client.list_credentials_for_tab(self.id())
    }

    pub fn store_credential(&self, username: &str, password: &str) -> Result<CredentialRecord> {
        self.client
            .store_credential_for_tab(self.id(), username, password)
    }

    pub fn store_credential_with_options(
        &self,
        username: &str,
        password: &str,
        login_url: Option<&str>,
        label: Option<&str>,
    ) -> Result<CredentialRecord> {
        self.client.store_credential_for_tab_with_options(
            self.id(),
            username,
            password,
            login_url,
            label,
        )
    }

    pub fn fill_credential(&self, credential_id: &str) -> Result<BrowserCommand> {
        self.client
            .fill_credential_for_tab(self.id(), credential_id)
    }

    pub fn default_credential(&self) -> Result<CredentialRecord> {
        self.client.default_credential_for_tab(self.id())
    }

    pub fn fill_default_credential(&self) -> Result<BrowserCommand> {
        self.client.fill_default_credential_for_tab(self.id())
    }

    pub fn delete_credential(&self, credential_id: &str) -> Result<()> {
        self.client
            .delete_credential_for_tab(self.id(), credential_id)
    }

    pub fn fill_credential_and_wait(
        &self,
        credential_id: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        self.client
            .fill_credential_for_tab_and_wait(self.id(), credential_id, timeout)
    }

    pub fn fill_default_credential_and_wait(
        &self,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        let command = self.fill_default_credential()?;
        self.client.wait_for_command_result(&command.id, timeout)
    }

    pub fn open_codex_pane(
        &self,
        url: &str,
        position: PanePosition,
        ttl_seconds: Option<u64>,
    ) -> Result<ScopedAgentPane> {
        self.open_codex_pane_with_options(
            ScopedAgentPaneOptions::interactive(url, position).ttl_seconds(ttl_seconds),
        )
    }

    pub fn open_read_only_codex_pane(
        &self,
        url: &str,
        position: PanePosition,
        ttl_seconds: Option<u64>,
    ) -> Result<ScopedAgentPane> {
        self.open_codex_pane_with_options(
            ScopedAgentPaneOptions::read_only(url, position).ttl_seconds(ttl_seconds),
        )
    }

    pub fn open_codex_pane_with_options(
        &self,
        options: ScopedAgentPaneOptions,
    ) -> Result<ScopedAgentPane> {
        self.client
            .open_scoped_agent_pane_for_tab_with_options(self.id(), options)
    }
}

impl ScopedAgentPane {
    pub fn tab_id(&self) -> &str {
        &self.connection.tab_id
    }

    pub fn session_id(&self) -> &str {
        &self.connection.session_id
    }

    pub fn list_page_contexts(&self) -> Result<Vec<PageContextSnapshot>> {
        self.agent.list_page_contexts_for_tab(self.tab_id())
    }

    pub fn current_page_context(&self) -> Result<Option<PageContextSnapshot>> {
        self.agent.page_context_for_tab(self.tab_id())
    }

    pub fn navigate(&self, url: &str) -> Result<TabState> {
        self.agent
            .navigate(self.tab_id(), url, Some(self.session_id()))
    }

    pub fn navigate_and_wait(&self, url: &str, timeout: Duration) -> Result<PageContextSnapshot> {
        self.navigate(url)?;
        self.wait_for_url(url, timeout)
    }

    pub fn wait_for_page_context<F>(
        &self,
        timeout: Duration,
        predicate: F,
    ) -> Result<PageContextSnapshot>
    where
        F: Fn(&PageContextSnapshot) -> bool,
    {
        self.agent
            .wait_for_page_context(self.tab_id(), timeout, predicate)
    }

    pub fn wait_for_url(&self, url: &str, timeout: Duration) -> Result<PageContextSnapshot> {
        self.agent.wait_for_url(self.tab_id(), url, timeout)
    }

    pub fn wait_for_url_contains(
        &self,
        fragment: &str,
        timeout: Duration,
    ) -> Result<PageContextSnapshot> {
        self.agent
            .wait_for_url_contains(self.tab_id(), fragment, timeout)
    }

    pub fn wait_for_title_contains(
        &self,
        text: &str,
        timeout: Duration,
    ) -> Result<PageContextSnapshot> {
        self.agent
            .wait_for_title_contains(self.tab_id(), text, timeout)
    }

    pub fn wait_for_text_contains(
        &self,
        text: &str,
        timeout: Duration,
    ) -> Result<PageContextSnapshot> {
        self.agent
            .wait_for_text_contains(self.tab_id(), text, timeout)
    }

    pub fn list_element_references(&self) -> Result<Vec<ElementReference>> {
        self.agent.list_element_references_for_tab(self.tab_id())
    }

    pub fn list_command_results(&self) -> Result<Vec<CommandExecutionReport>> {
        self.agent.list_command_results_for_tab(self.tab_id())
    }

    pub fn click(&self, selector: &str) -> Result<BrowserCommand> {
        self.agent.click(self.tab_id(), self.session_id(), selector)
    }

    pub fn click_and_wait(
        &self,
        selector: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        self.agent
            .click_and_wait(self.tab_id(), self.session_id(), selector, timeout)
    }

    pub fn click_ref(&self, element_ref_id: &str) -> Result<BrowserCommand> {
        self.agent
            .click_ref(self.tab_id(), self.session_id(), element_ref_id)
    }

    pub fn click_ref_and_wait(
        &self,
        element_ref_id: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        self.agent
            .click_ref_and_wait(self.tab_id(), self.session_id(), element_ref_id, timeout)
    }

    pub fn double_click(&self, selector: &str) -> Result<BrowserCommand> {
        self.agent
            .double_click(self.tab_id(), self.session_id(), selector)
    }

    pub fn double_click_and_wait(
        &self,
        selector: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        self.agent
            .double_click_and_wait(self.tab_id(), self.session_id(), selector, timeout)
    }

    pub fn double_click_ref(&self, element_ref_id: &str) -> Result<BrowserCommand> {
        self.agent
            .double_click_ref(self.tab_id(), self.session_id(), element_ref_id)
    }

    pub fn double_click_ref_and_wait(
        &self,
        element_ref_id: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        self.agent.double_click_ref_and_wait(
            self.tab_id(),
            self.session_id(),
            element_ref_id,
            timeout,
        )
    }

    pub fn drag_to(&self, source_selector: &str, target_selector: &str) -> Result<BrowserCommand> {
        self.agent.drag_to(
            self.tab_id(),
            self.session_id(),
            source_selector,
            target_selector,
        )
    }

    pub fn drag_to_and_wait(
        &self,
        source_selector: &str,
        target_selector: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        self.agent.drag_to_and_wait(
            self.tab_id(),
            self.session_id(),
            source_selector,
            target_selector,
            timeout,
        )
    }

    pub fn drag_ref_to_ref(
        &self,
        source_element_ref_id: &str,
        target_element_ref_id: &str,
    ) -> Result<BrowserCommand> {
        self.agent.drag_ref_to_ref(
            self.tab_id(),
            self.session_id(),
            source_element_ref_id,
            target_element_ref_id,
        )
    }

    pub fn drag_ref_to_ref_and_wait(
        &self,
        source_element_ref_id: &str,
        target_element_ref_id: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        self.agent.drag_ref_to_ref_and_wait(
            self.tab_id(),
            self.session_id(),
            source_element_ref_id,
            target_element_ref_id,
            timeout,
        )
    }

    pub fn hover(&self, selector: &str) -> Result<BrowserCommand> {
        self.agent.hover(self.tab_id(), self.session_id(), selector)
    }

    pub fn hover_and_wait(
        &self,
        selector: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        self.agent
            .hover_and_wait(self.tab_id(), self.session_id(), selector, timeout)
    }

    pub fn hover_ref(&self, element_ref_id: &str) -> Result<BrowserCommand> {
        self.agent
            .hover_ref(self.tab_id(), self.session_id(), element_ref_id)
    }

    pub fn hover_ref_and_wait(
        &self,
        element_ref_id: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        self.agent
            .hover_ref_and_wait(self.tab_id(), self.session_id(), element_ref_id, timeout)
    }

    pub fn focus(&self, selector: &str) -> Result<BrowserCommand> {
        self.agent.focus(self.tab_id(), self.session_id(), selector)
    }

    pub fn focus_and_wait(
        &self,
        selector: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        self.agent
            .focus_and_wait(self.tab_id(), self.session_id(), selector, timeout)
    }

    pub fn focus_ref(&self, element_ref_id: &str) -> Result<BrowserCommand> {
        self.agent
            .focus_ref(self.tab_id(), self.session_id(), element_ref_id)
    }

    pub fn focus_ref_and_wait(
        &self,
        element_ref_id: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        self.agent
            .focus_ref_and_wait(self.tab_id(), self.session_id(), element_ref_id, timeout)
    }

    pub fn type_text(
        &self,
        selector: &str,
        text: &str,
        clear_first: bool,
    ) -> Result<BrowserCommand> {
        self.agent.type_text(
            self.tab_id(),
            self.session_id(),
            selector,
            text,
            clear_first,
        )
    }

    pub fn type_text_and_wait(
        &self,
        selector: &str,
        text: &str,
        clear_first: bool,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        self.agent.type_text_and_wait(
            self.tab_id(),
            self.session_id(),
            selector,
            text,
            clear_first,
            timeout,
        )
    }

    pub fn type_text_ref(
        &self,
        element_ref_id: &str,
        text: &str,
        clear_first: bool,
    ) -> Result<BrowserCommand> {
        self.agent.type_text_ref(
            self.tab_id(),
            self.session_id(),
            element_ref_id,
            text,
            clear_first,
        )
    }

    pub fn type_text_ref_and_wait(
        &self,
        element_ref_id: &str,
        text: &str,
        clear_first: bool,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        self.agent.type_text_ref_and_wait(
            self.tab_id(),
            self.session_id(),
            element_ref_id,
            text,
            clear_first,
            timeout,
        )
    }

    pub fn select_option(&self, selector: &str, value: &str) -> Result<BrowserCommand> {
        self.agent
            .select_option(self.tab_id(), self.session_id(), selector, value)
    }

    pub fn select_option_and_wait(
        &self,
        selector: &str,
        value: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        self.agent.select_option_and_wait(
            self.tab_id(),
            self.session_id(),
            selector,
            value,
            timeout,
        )
    }

    pub fn select_option_ref(&self, element_ref_id: &str, value: &str) -> Result<BrowserCommand> {
        self.agent
            .select_option_ref(self.tab_id(), self.session_id(), element_ref_id, value)
    }

    pub fn select_option_ref_and_wait(
        &self,
        element_ref_id: &str,
        value: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        self.agent.select_option_ref_and_wait(
            self.tab_id(),
            self.session_id(),
            element_ref_id,
            value,
            timeout,
        )
    }

    pub fn set_checked(&self, selector: &str, checked: bool) -> Result<BrowserCommand> {
        self.agent
            .set_checked(self.tab_id(), self.session_id(), selector, checked)
    }

    pub fn set_checked_and_wait(
        &self,
        selector: &str,
        checked: bool,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        self.agent.set_checked_and_wait(
            self.tab_id(),
            self.session_id(),
            selector,
            checked,
            timeout,
        )
    }

    pub fn set_checked_ref(&self, element_ref_id: &str, checked: bool) -> Result<BrowserCommand> {
        self.agent
            .set_checked_ref(self.tab_id(), self.session_id(), element_ref_id, checked)
    }

    pub fn set_checked_ref_and_wait(
        &self,
        element_ref_id: &str,
        checked: bool,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        self.agent.set_checked_ref_and_wait(
            self.tab_id(),
            self.session_id(),
            element_ref_id,
            checked,
            timeout,
        )
    }

    pub fn scroll_by(&self, delta_x: i32, delta_y: i32) -> Result<BrowserCommand> {
        self.agent
            .scroll_by(self.tab_id(), self.session_id(), delta_x, delta_y)
    }

    pub fn scroll_by_and_wait(
        &self,
        delta_x: i32,
        delta_y: i32,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        self.agent
            .scroll_by_and_wait(self.tab_id(), self.session_id(), delta_x, delta_y, timeout)
    }

    pub fn scroll_into_view(&self, selector: &str) -> Result<BrowserCommand> {
        self.agent
            .scroll_into_view(self.tab_id(), self.session_id(), selector)
    }

    pub fn scroll_into_view_and_wait(
        &self,
        selector: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        self.agent
            .scroll_into_view_and_wait(self.tab_id(), self.session_id(), selector, timeout)
    }

    pub fn scroll_ref_into_view(&self, element_ref_id: &str) -> Result<BrowserCommand> {
        self.agent
            .scroll_ref_into_view(self.tab_id(), self.session_id(), element_ref_id)
    }

    pub fn scroll_ref_into_view_and_wait(
        &self,
        element_ref_id: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        self.agent.scroll_ref_into_view_and_wait(
            self.tab_id(),
            self.session_id(),
            element_ref_id,
            timeout,
        )
    }

    pub fn press_key(&self, key: &str) -> Result<BrowserCommand> {
        self.agent.press_key(self.tab_id(), self.session_id(), key)
    }

    pub fn press_key_and_wait(
        &self,
        key: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        self.agent
            .press_key_and_wait(self.tab_id(), self.session_id(), key, timeout)
    }

    pub fn submit(&self, selector: &str) -> Result<BrowserCommand> {
        self.agent
            .submit(self.tab_id(), self.session_id(), selector)
    }

    pub fn submit_and_wait(
        &self,
        selector: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        self.agent
            .submit_and_wait(self.tab_id(), self.session_id(), selector, timeout)
    }

    pub fn submit_ref(&self, element_ref_id: &str) -> Result<BrowserCommand> {
        self.agent
            .submit_ref(self.tab_id(), self.session_id(), element_ref_id)
    }

    pub fn submit_ref_and_wait(
        &self,
        element_ref_id: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        self.agent
            .submit_ref_and_wait(self.tab_id(), self.session_id(), element_ref_id, timeout)
    }

    pub fn wait_for_selector(
        &self,
        selector: &str,
        timeout: Option<Duration>,
    ) -> Result<BrowserCommand> {
        self.agent
            .wait_for_selector(self.tab_id(), self.session_id(), selector, timeout)
    }

    pub fn wait_for_selector_result(
        &self,
        selector: &str,
        selector_timeout: Option<Duration>,
        result_timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        self.agent.wait_for_selector_and_wait(
            self.tab_id(),
            self.session_id(),
            selector,
            selector_timeout,
            result_timeout,
        )
    }

    pub fn wait_for_selector_details(
        &self,
        selector: &str,
        selector_timeout: Option<Duration>,
        result_timeout: Duration,
    ) -> Result<SelectorWaitResult> {
        self.agent.wait_for_selector_details(
            self.tab_id(),
            self.session_id(),
            selector,
            selector_timeout,
            result_timeout,
        )
    }

    pub fn extract_text(&self, selector: &str) -> Result<BrowserCommand> {
        self.agent
            .extract_text(self.tab_id(), self.session_id(), selector)
    }

    pub fn extract_text_and_wait(
        &self,
        selector: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        self.agent
            .extract_text_and_wait(self.tab_id(), self.session_id(), selector, timeout)
    }

    pub fn extract_text_result(&self, selector: &str, timeout: Duration) -> Result<ExtractedText> {
        self.agent
            .extract_text_result(self.tab_id(), self.session_id(), selector, timeout)
    }

    pub fn extract_text_ref(&self, element_ref_id: &str) -> Result<BrowserCommand> {
        self.agent
            .extract_text_ref(self.tab_id(), self.session_id(), element_ref_id)
    }

    pub fn extract_text_ref_and_wait(
        &self,
        element_ref_id: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        self.agent.extract_text_ref_and_wait(
            self.tab_id(),
            self.session_id(),
            element_ref_id,
            timeout,
        )
    }

    pub fn extract_text_ref_result(
        &self,
        element_ref_id: &str,
        timeout: Duration,
    ) -> Result<ExtractedText> {
        self.agent.extract_text_ref_result(
            self.tab_id(),
            self.session_id(),
            element_ref_id,
            timeout,
        )
    }

    pub fn inspect_element(&self, selector: &str) -> Result<BrowserCommand> {
        self.agent
            .inspect_element(self.tab_id(), self.session_id(), selector)
    }

    pub fn inspect_element_and_wait(
        &self,
        selector: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        self.agent
            .inspect_element_and_wait(self.tab_id(), self.session_id(), selector, timeout)
    }

    pub fn inspect_element_details(
        &self,
        selector: &str,
        timeout: Duration,
    ) -> Result<InspectedElement> {
        self.agent
            .inspect_element_details(self.tab_id(), self.session_id(), selector, timeout)
    }

    pub fn inspect_element_ref(&self, element_ref_id: &str) -> Result<BrowserCommand> {
        self.agent
            .inspect_element_ref(self.tab_id(), self.session_id(), element_ref_id)
    }

    pub fn inspect_element_ref_and_wait(
        &self,
        element_ref_id: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        self.agent.inspect_element_ref_and_wait(
            self.tab_id(),
            self.session_id(),
            element_ref_id,
            timeout,
        )
    }

    pub fn inspect_element_ref_details(
        &self,
        element_ref_id: &str,
        timeout: Duration,
    ) -> Result<InspectedElement> {
        self.agent.inspect_element_ref_details(
            self.tab_id(),
            self.session_id(),
            element_ref_id,
            timeout,
        )
    }

    pub fn start_element_picker(&self) -> Result<BrowserCommand> {
        self.agent
            .start_element_picker(self.tab_id(), self.session_id())
    }

    pub fn pick_element(&self, timeout: Duration) -> Result<ElementReference> {
        let known_ids = self.agent.element_reference_ids_for_tab(self.tab_id())?;
        self.start_element_picker()?;
        self.agent
            .wait_for_new_element_reference(self.tab_id(), &known_ids, timeout)
    }

    pub fn execute_script(&self, script: &str) -> Result<BrowserCommand> {
        self.agent
            .execute_script(self.tab_id(), self.session_id(), script)
    }

    pub fn execute_script_and_wait(
        &self,
        script: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        self.agent
            .execute_script_and_wait(self.tab_id(), self.session_id(), script, timeout)
    }

    pub fn fill_login(&self, credential_id: &str) -> Result<BrowserCommand> {
        self.agent
            .fill_login(self.tab_id(), self.session_id(), credential_id)
    }

    pub fn login_options(&self) -> Result<Vec<CredentialRecord>> {
        self.agent
            .list_login_options(self.tab_id(), self.session_id())
    }

    pub fn default_login_option(&self) -> Result<CredentialRecord> {
        self.login_options()?.into_iter().next().ok_or_else(|| {
            SdkError::InvalidOperation(format!("tab {} has no login options", self.tab_id()))
        })
    }

    pub fn fill_default_login(&self) -> Result<BrowserCommand> {
        let credential = self.default_login_option()?;
        self.fill_login(&credential.id)
    }

    pub fn fill_login_and_wait(
        &self,
        credential_id: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        self.agent
            .fill_login_and_wait(self.tab_id(), self.session_id(), credential_id, timeout)
    }

    pub fn fill_default_login_and_wait(&self, timeout: Duration) -> Result<CommandExecutionReport> {
        let command = self.fill_default_login()?;
        self.agent.wait_for_command_result(&command.id, timeout)
    }

    pub fn agent_action(&self, action: AgentAction) -> Result<BrowserCommand> {
        self.agent
            .agent_action(self.tab_id(), self.session_id(), action)
    }

    pub fn agent_action_and_wait(
        &self,
        action: AgentAction,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        self.agent
            .agent_action_and_wait(self.tab_id(), self.session_id(), action, timeout)
    }

    pub fn command_result(&self, command_id: &str) -> Result<Option<CommandExecutionReport>> {
        self.agent.command_result(command_id)
    }

    pub fn wait_for_command_result(
        &self,
        command_id: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        self.agent.wait_for_command_result(command_id, timeout)
    }

    pub fn close(&self) -> Result<AgentPaneState> {
        self.agent.close_agent_pane(&self.pane.id)
    }

    pub fn stop_with_owner(&self, owner: &TelescopeClient) -> Result<StoppedAgentPane> {
        owner.stop_agent_pane(&self.pane.id)
    }
}

impl TelescopeClient {
    pub fn new(base_url: impl Into<String>, bearer_token: impl Into<String>) -> Result<Self> {
        let base_url = base_url.into().trim_end_matches('/').to_string();
        if !(base_url.starts_with("http://") || base_url.starts_with("https://")) {
            return Err(SdkError::InvalidBaseUrl(base_url));
        }

        Ok(Self {
            base_url,
            bearer_token: bearer_token.into(),
            origin_header: None,
            agent: ureq::Agent::new_with_defaults(),
        })
    }

    pub fn with_request_origin(mut self, origin: impl AsRef<str>) -> Result<Self> {
        let origin = telescope_core::WebOrigin::parse(origin.as_ref())?;
        self.origin_header = Some(origin.display_url());
        Ok(self)
    }

    pub fn from_env() -> Result<Self> {
        let base_url =
            std::env::var("TELESCOPE_URL").map_err(|_| SdkError::MissingEnv("TELESCOPE_URL"))?;
        let token = std::env::var("TELESCOPE_TOKEN")
            .map_err(|_| SdkError::MissingEnv("TELESCOPE_TOKEN"))?;
        Self::new(base_url, token)
    }

    pub fn from_control_file(path: impl AsRef<Path>) -> Result<Self> {
        let data = std::fs::read_to_string(path)?;
        let endpoint: ControlEndpoint = serde_json::from_str(&data)?;
        Self::new(endpoint.url, endpoint.owner_token)
    }

    pub fn create_session<I, S>(
        &self,
        allowed_origins: I,
        allow_credentials: bool,
    ) -> Result<AgentSession>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.post(
            "/v1/sessions",
            &CreateSessionRequest {
                allowed_origins: allowed_origins.into_iter().map(Into::into).collect(),
                allow_credentials,
                allow_interactions: true,
                allow_scripts: false,
                ttl_seconds: None,
            },
        )
    }

    pub fn create_read_only_session<I, S>(&self, allowed_origins: I) -> Result<AgentSession>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.post(
            "/v1/sessions",
            &CreateSessionRequest {
                allowed_origins: allowed_origins.into_iter().map(Into::into).collect(),
                allow_credentials: false,
                allow_interactions: false,
                allow_scripts: false,
                ttl_seconds: None,
            },
        )
    }

    pub fn create_session_with_policy(
        &self,
        request: &CreateSessionRequest,
    ) -> Result<AgentSession> {
        self.post("/v1/sessions", request)
    }

    pub fn list_sessions(&self) -> Result<Vec<AgentSession>> {
        self.get("/v1/sessions")
    }

    pub fn revoke_session(&self, session_id: &str) -> Result<RevokedAgentSession> {
        self.delete(&format!("/v1/sessions/{session_id}"))
    }

    pub fn create_agent_grant<I, S>(
        &self,
        session_id: &str,
        allowed_tab_ids: I,
        ttl_seconds: Option<u64>,
    ) -> Result<AgentGrant>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.post(
            "/v1/agent-grants",
            &CreateAgentGrantRequest {
                session_id: session_id.to_string(),
                allowed_tab_ids: allowed_tab_ids.into_iter().map(Into::into).collect(),
                allowed_client_origins: Vec::new(),
                ttl_seconds,
            },
        )
    }

    pub fn create_agent_grant_with_client_origins<I, S, O, C>(
        &self,
        session_id: &str,
        allowed_tab_ids: I,
        allowed_client_origins: O,
        ttl_seconds: Option<u64>,
    ) -> Result<AgentGrant>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
        O: IntoIterator<Item = C>,
        C: Into<String>,
    {
        self.post(
            "/v1/agent-grants",
            &CreateAgentGrantRequest {
                session_id: session_id.to_string(),
                allowed_tab_ids: allowed_tab_ids.into_iter().map(Into::into).collect(),
                allowed_client_origins: allowed_client_origins
                    .into_iter()
                    .map(Into::into)
                    .collect(),
                ttl_seconds,
            },
        )
    }

    pub fn list_agent_grants(&self) -> Result<Vec<AgentGrant>> {
        self.get("/v1/agent-grants")
    }

    pub fn revoke_agent_grant(&self, token: &str) -> Result<RevokedAgentGrant> {
        self.delete(&format!("/v1/agent-grants/{token}"))
    }

    pub fn scoped_agent_client(&self, grant: &AgentGrant) -> Result<Self> {
        let mut client = Self::new(self.base_url.clone(), grant.token.clone())?;
        if let Some(origin) = grant.allowed_client_origins.first() {
            client.origin_header = Some(origin.display_url());
        }
        Ok(client)
    }

    pub fn create_tab(&self, url: Option<&str>, session_id: Option<&str>) -> Result<TabState> {
        self.post(
            "/v1/tabs",
            &CreateTabRequest {
                url: url.map(str::to_string),
                session_id: session_id.map(str::to_string),
            },
        )
    }

    pub fn create_browser_tab(
        &self,
        url: Option<&str>,
        session_id: Option<&str>,
    ) -> Result<BrowserTab> {
        Ok(self.browser_tab(self.create_tab(url, session_id)?))
    }

    pub fn list_tabs(&self) -> Result<Vec<TabState>> {
        self.get("/v1/tabs")
    }

    pub fn get_tab(&self, tab_id: &str) -> Result<TabState> {
        self.list_tabs()?
            .into_iter()
            .find(|tab| tab.id == tab_id)
            .ok_or_else(|| SdkError::NotFound(format!("tab {tab_id}")))
    }

    pub fn active_tab(&self) -> Result<Option<TabState>> {
        self.get("/v1/tabs/active")
    }

    pub fn active_tab_or_create(
        &self,
        url: Option<&str>,
        session_id: Option<&str>,
    ) -> Result<TabState> {
        match self.active_tab()? {
            Some(tab) => Ok(tab),
            None => self.create_tab(url, session_id),
        }
    }

    pub fn active_browser_tab(&self) -> Result<Option<BrowserTab>> {
        Ok(self.active_tab()?.map(|tab| self.browser_tab(tab)))
    }

    pub fn active_browser_tab_or_create(
        &self,
        url: Option<&str>,
        session_id: Option<&str>,
    ) -> Result<BrowserTab> {
        Ok(self.browser_tab(self.active_tab_or_create(url, session_id)?))
    }

    pub fn browser_tab(&self, state: TabState) -> BrowserTab {
        BrowserTab {
            state,
            client: self.clone(),
        }
    }

    pub fn activate_tab(&self, tab_id: &str) -> Result<TabState> {
        self.post_empty(&format!("/v1/tabs/{tab_id}/activate"))
    }

    pub fn close_tab(&self, tab_id: &str) -> Result<TabState> {
        self.delete(&format!("/v1/tabs/{tab_id}"))
    }

    pub fn navigate(&self, tab_id: &str, url: &str, session_id: Option<&str>) -> Result<TabState> {
        self.post(
            &format!("/v1/tabs/{tab_id}/navigate"),
            &NavigateRequest {
                url: url.to_string(),
                session_id: session_id.map(str::to_string),
            },
        )
    }

    pub fn navigate_and_wait(
        &self,
        tab_id: &str,
        url: &str,
        session_id: Option<&str>,
        timeout: Duration,
    ) -> Result<PageContextSnapshot> {
        self.navigate(tab_id, url, session_id)?;
        self.wait_for_url(tab_id, url, timeout)
    }

    pub fn go_back(&self, tab_id: &str) -> Result<BrowserCommand> {
        self.post_empty(&format!("/v1/tabs/{tab_id}/back"))
    }

    pub fn go_forward(&self, tab_id: &str) -> Result<BrowserCommand> {
        self.post_empty(&format!("/v1/tabs/{tab_id}/forward"))
    }

    pub fn reload_tab(&self, tab_id: &str) -> Result<BrowserCommand> {
        self.post_empty(&format!("/v1/tabs/{tab_id}/reload"))
    }

    pub fn create_bookmark(&self, url: &str, title: Option<&str>) -> Result<BookmarkRecord> {
        self.post(
            "/v1/bookmarks",
            &CreateBookmarkRequest {
                url: url.to_string(),
                title: title.map(str::to_string),
            },
        )
    }

    pub fn bookmark_tab(&self, tab_id: &str, title: Option<&str>) -> Result<BookmarkRecord> {
        let tab = self.get_tab(tab_id)?;
        let url = tab.current_url.as_deref().ok_or_else(|| {
            SdkError::InvalidOperation(format!("tab {tab_id} has no current URL"))
        })?;
        self.create_bookmark(url, title.or(tab.title.as_deref()))
    }

    pub fn list_bookmarks(&self) -> Result<Vec<BookmarkRecord>> {
        self.get("/v1/bookmarks")
    }

    pub fn open_bookmark_for_tab(&self, tab_id: &str, bookmark_id: &str) -> Result<TabState> {
        let bookmark = self.bookmark_by_id(bookmark_id)?;
        self.navigate(tab_id, &bookmark.url, None)
    }

    pub fn open_bookmark_in_new_tab(&self, bookmark_id: &str) -> Result<BrowserTab> {
        let bookmark = self.bookmark_by_id(bookmark_id)?;
        self.create_browser_tab(Some(&bookmark.url), None)
    }

    pub fn delete_bookmark(&self, bookmark_id: &str) -> Result<BookmarkRecord> {
        self.delete(&format!("/v1/bookmarks/{bookmark_id}"))
    }

    fn bookmark_by_id(&self, bookmark_id: &str) -> Result<BookmarkRecord> {
        self.list_bookmarks()?
            .into_iter()
            .find(|bookmark| bookmark.id == bookmark_id)
            .ok_or_else(|| SdkError::NotFound(format!("bookmark {bookmark_id}")))
    }

    pub fn store_credential(
        &self,
        origin: &str,
        username: &str,
        password: &str,
    ) -> Result<CredentialRecord> {
        self.post(
            "/v1/credentials",
            &CredentialInput {
                origin: origin.to_string(),
                username: username.to_string(),
                password: password.to_string(),
                login_url: None,
                label: None,
            },
        )
    }

    pub fn list_credentials(&self) -> Result<Vec<CredentialRecord>> {
        self.get("/v1/credentials")
    }

    pub fn delete_credential(&self, credential_id: &str) -> Result<()> {
        let _: serde_json::Value = self.delete(&format!("/v1/credentials/{credential_id}"))?;
        Ok(())
    }

    pub fn store_credential_for_tab(
        &self,
        tab_id: &str,
        username: &str,
        password: &str,
    ) -> Result<CredentialRecord> {
        self.store_credential_for_tab_with_options(tab_id, username, password, None, None)
    }

    pub fn store_credential_for_tab_with_options(
        &self,
        tab_id: &str,
        username: &str,
        password: &str,
        login_url: Option<&str>,
        label: Option<&str>,
    ) -> Result<CredentialRecord> {
        self.post(
            &format!("/v1/tabs/{tab_id}/credentials"),
            &StoreTabCredentialRequest {
                username: username.to_string(),
                password: password.to_string(),
                login_url: login_url.map(str::to_string),
                label: label.map(str::to_string),
            },
        )
    }

    pub fn list_credentials_for_tab(&self, tab_id: &str) -> Result<Vec<CredentialRecord>> {
        self.get(&format!("/v1/tabs/{tab_id}/credentials"))
    }

    pub fn default_credential_for_tab(&self, tab_id: &str) -> Result<CredentialRecord> {
        self.list_credentials_for_tab(tab_id)?
            .into_iter()
            .next()
            .ok_or_else(|| {
                SdkError::InvalidOperation(format!("tab {tab_id} has no saved credentials"))
            })
    }

    pub fn delete_credential_for_tab(&self, tab_id: &str, credential_id: &str) -> Result<()> {
        let _: serde_json::Value =
            self.delete(&format!("/v1/tabs/{tab_id}/credentials/{credential_id}"))?;
        Ok(())
    }

    pub fn fill_login(
        &self,
        tab_id: &str,
        session_id: &str,
        credential_id: &str,
    ) -> Result<BrowserCommand> {
        self.post(
            &format!("/v1/tabs/{tab_id}/fill-login"),
            &FillLoginRequest {
                session_id: session_id.to_string(),
                credential_id: credential_id.to_string(),
            },
        )
    }

    pub fn list_login_options(
        &self,
        tab_id: &str,
        session_id: &str,
    ) -> Result<Vec<CredentialRecord>> {
        self.post(
            &format!("/v1/tabs/{tab_id}/login-options"),
            &ListLoginOptionsRequest {
                session_id: session_id.to_string(),
            },
        )
    }

    pub fn fill_credential_for_tab(
        &self,
        tab_id: &str,
        credential_id: &str,
    ) -> Result<BrowserCommand> {
        self.post_empty(&format!(
            "/v1/tabs/{tab_id}/credentials/{credential_id}/fill"
        ))
    }

    pub fn fill_default_credential_for_tab(&self, tab_id: &str) -> Result<BrowserCommand> {
        let credential = self.default_credential_for_tab(tab_id)?;
        self.fill_credential_for_tab(tab_id, &credential.id)
    }

    pub fn fill_default_credential_for_tab_and_wait(
        &self,
        tab_id: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        let command = self.fill_default_credential_for_tab(tab_id)?;
        self.wait_for_command_result(&command.id, timeout)
    }

    pub fn fill_credential_for_tab_and_wait(
        &self,
        tab_id: &str,
        credential_id: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        let command = self.fill_credential_for_tab(tab_id, credential_id)?;
        self.wait_for_command_result(&command.id, timeout)
    }

    pub fn fill_login_and_wait(
        &self,
        tab_id: &str,
        session_id: &str,
        credential_id: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        let command = self.fill_login(tab_id, session_id, credential_id)?;
        self.wait_for_command_result(&command.id, timeout)
    }

    pub fn open_agent_pane(
        &self,
        url: &str,
        position: PanePosition,
        attached_tab_id: Option<&str>,
        session_id: Option<&str>,
    ) -> Result<AgentPaneState> {
        self.post(
            "/v1/agent-panes",
            &OpenAgentPaneRequest {
                url: url.to_string(),
                position,
                attached_tab_id: attached_tab_id.map(str::to_string),
                session_id: session_id.map(str::to_string),
                agent_grant_token: None,
            },
        )
    }

    pub fn open_agent_pane_with_grant(
        &self,
        url: &str,
        position: PanePosition,
        tab_id: &str,
        session_id: &str,
        grant: &AgentGrant,
    ) -> Result<AgentPaneState> {
        self.post(
            "/v1/agent-panes",
            &OpenAgentPaneRequest {
                url: url.to_string(),
                position,
                attached_tab_id: Some(tab_id.to_string()),
                session_id: Some(session_id.to_string()),
                agent_grant_token: Some(grant.token.clone()),
            },
        )
    }

    pub fn open_scoped_agent_pane(
        &self,
        url: &str,
        position: PanePosition,
        tab_id: &str,
        session_id: &str,
        ttl_seconds: Option<u64>,
    ) -> Result<ScopedAgentPane> {
        let pane_origin = telescope_core::WebOrigin::from_url_str(url)?;
        let grant = self.create_agent_grant_with_client_origins(
            session_id,
            [tab_id.to_string()],
            [pane_origin.display_url()],
            ttl_seconds,
        )?;
        let pane = self.open_agent_pane_with_grant(url, position, tab_id, session_id, &grant)?;
        let stored_connection = self.agent_pane_connection(&pane.id)?;
        let connection = AgentPaneConnectionDescriptor {
            control_url: self.base_url.clone(),
            pane_id: pane.id.clone(),
            pane_url: pane.url.clone(),
            session_id: stored_connection.session_id,
            tab_id: stored_connection.tab_id,
            grant_token: stored_connection.grant_token,
            session_policy: stored_connection.session_policy,
            expires_at_unix: stored_connection.expires_at_unix,
        };
        let agent = self.scoped_agent_client(&grant)?;

        Ok(ScopedAgentPane {
            pane,
            grant,
            connection,
            agent,
        })
    }

    pub fn open_scoped_agent_pane_for_tab(
        &self,
        url: &str,
        position: PanePosition,
        tab_id: &str,
        ttl_seconds: Option<u64>,
    ) -> Result<ScopedAgentPane> {
        self.open_scoped_agent_pane_for_tab_with_options(
            tab_id,
            ScopedAgentPaneOptions::interactive(url, position).ttl_seconds(ttl_seconds),
        )
    }

    pub fn open_scoped_agent_pane_for_tab_with_options(
        &self,
        tab_id: &str,
        options: ScopedAgentPaneOptions,
    ) -> Result<ScopedAgentPane> {
        self.open_scoped_agent_pane_with_options(Some(tab_id), options)
    }

    pub fn open_codex_pane_for_active_tab(
        &self,
        url: &str,
        position: PanePosition,
        ttl_seconds: Option<u64>,
    ) -> Result<ScopedAgentPane> {
        self.open_scoped_agent_pane_for_active_tab(url, position, ttl_seconds)
    }

    pub fn open_codex_pane_for_active_tab_with_options(
        &self,
        options: ScopedAgentPaneOptions,
    ) -> Result<ScopedAgentPane> {
        self.open_scoped_agent_pane_for_active_tab_with_options(options)
    }

    pub fn open_scoped_agent_pane_for_active_tab(
        &self,
        url: &str,
        position: PanePosition,
        ttl_seconds: Option<u64>,
    ) -> Result<ScopedAgentPane> {
        self.open_scoped_agent_pane_for_active_tab_with_options(
            ScopedAgentPaneOptions::interactive(url, position).ttl_seconds(ttl_seconds),
        )
    }

    pub fn open_scoped_agent_pane_for_active_tab_with_options(
        &self,
        options: ScopedAgentPaneOptions,
    ) -> Result<ScopedAgentPane> {
        self.open_scoped_agent_pane_with_options(None, options)
    }

    fn open_scoped_agent_pane_with_options(
        &self,
        tab_id: Option<&str>,
        options: ScopedAgentPaneOptions,
    ) -> Result<ScopedAgentPane> {
        let opened = self.post(
            "/v1/scoped-agent-panes",
            &OpenScopedAgentPaneRequest {
                url: options.url,
                position: options.position,
                tab_id: tab_id.map(str::to_string),
                allow_credentials: options.allow_credentials,
                allow_interactions: options.allow_interactions,
                allow_scripts: options.allow_scripts,
                ttl_seconds: options.ttl_seconds,
            },
        )?;
        self.scoped_agent_pane_from_opened(opened)
    }

    pub fn list_agent_panes(&self) -> Result<Vec<AgentPaneState>> {
        self.get("/v1/agent-panes")
    }

    pub fn agent_pane_connection(&self, pane_id: &str) -> Result<AgentPaneConnection> {
        self.get(&format!("/v1/agent-panes/{pane_id}/connection"))
    }

    pub fn close_agent_pane(&self, pane_id: &str) -> Result<AgentPaneState> {
        self.delete(&format!("/v1/agent-panes/{pane_id}"))
    }

    pub fn stop_agent_pane(&self, pane_id: &str) -> Result<StoppedAgentPane> {
        match self.agent_pane_connection(pane_id) {
            Ok(connection) => Ok(StoppedAgentPane::RevokedGrant(
                self.revoke_agent_grant(&connection.grant_token)?,
            )),
            Err(error) if sdk_http_status(&error) == Some(404) => Ok(StoppedAgentPane::ClosedPane(
                self.close_agent_pane(pane_id)?,
            )),
            Err(error) => Err(error),
        }
    }

    pub fn stop_scoped_agent_pane(&self, pane: &ScopedAgentPane) -> Result<StoppedAgentPane> {
        self.stop_agent_pane(&pane.pane.id)
    }

    pub fn publish_page_context(
        &self,
        tab_id: &str,
        url: &str,
        title: Option<&str>,
        text_preview: Option<&str>,
        selected_element_id: Option<&str>,
    ) -> Result<PageContextSnapshot> {
        self.post(
            "/v1/page-contexts",
            &PageContextRequest {
                tab_id: tab_id.to_string(),
                url: url.to_string(),
                title: title.map(str::to_string),
                text_preview: text_preview.map(str::to_string),
                selected_element_id: selected_element_id.map(str::to_string),
                interactive_elements: Vec::new(),
            },
        )
    }

    pub fn publish_page_context_with_elements(
        &self,
        tab_id: &str,
        url: &str,
        title: Option<&str>,
        text_preview: Option<&str>,
        selected_element_id: Option<&str>,
        interactive_elements: Vec<PageInteractiveElement>,
    ) -> Result<PageContextSnapshot> {
        self.post(
            "/v1/page-contexts",
            &PageContextRequest {
                tab_id: tab_id.to_string(),
                url: url.to_string(),
                title: title.map(str::to_string),
                text_preview: text_preview.map(str::to_string),
                selected_element_id: selected_element_id.map(str::to_string),
                interactive_elements,
            },
        )
    }

    pub fn list_page_contexts(&self) -> Result<Vec<PageContextSnapshot>> {
        self.get("/v1/page-contexts")
    }

    pub fn list_page_contexts_for_tab(&self, tab_id: &str) -> Result<Vec<PageContextSnapshot>> {
        Ok(self
            .list_page_contexts()?
            .into_iter()
            .filter(|context| context.tab_id == tab_id)
            .collect())
    }

    pub fn page_context_for_tab(&self, tab_id: &str) -> Result<Option<PageContextSnapshot>> {
        Ok(self
            .list_page_contexts_for_tab(tab_id)?
            .into_iter()
            .find(|context| context.tab_id == tab_id))
    }

    pub fn wait_for_page_context<F>(
        &self,
        tab_id: &str,
        timeout: Duration,
        predicate: F,
    ) -> Result<PageContextSnapshot>
    where
        F: Fn(&PageContextSnapshot) -> bool,
    {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(context) = self.page_context_for_tab(tab_id)? {
                if predicate(&context) {
                    return Ok(context);
                }
            }
            if Instant::now() >= deadline {
                return Err(SdkError::Timeout(format!("page context for tab {tab_id}")));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    pub fn wait_for_url(
        &self,
        tab_id: &str,
        url: &str,
        timeout: Duration,
    ) -> Result<PageContextSnapshot> {
        self.wait_for_page_context(tab_id, timeout, |context| context.url == url)
    }

    pub fn wait_for_url_contains(
        &self,
        tab_id: &str,
        fragment: &str,
        timeout: Duration,
    ) -> Result<PageContextSnapshot> {
        self.wait_for_page_context(tab_id, timeout, |context| context.url.contains(fragment))
    }

    pub fn wait_for_title_contains(
        &self,
        tab_id: &str,
        text: &str,
        timeout: Duration,
    ) -> Result<PageContextSnapshot> {
        self.wait_for_page_context(tab_id, timeout, |context| {
            context
                .title
                .as_deref()
                .is_some_and(|title| title.contains(text))
        })
    }

    pub fn wait_for_text_contains(
        &self,
        tab_id: &str,
        text: &str,
        timeout: Duration,
    ) -> Result<PageContextSnapshot> {
        self.wait_for_page_context(tab_id, timeout, |context| {
            context
                .text_preview
                .as_deref()
                .is_some_and(|preview| preview.contains(text))
        })
    }

    pub fn record_element_reference(
        &self,
        input: &ElementReferenceInput,
    ) -> Result<ElementReference> {
        self.post("/v1/element-refs", input)
    }

    pub fn list_element_references(&self) -> Result<Vec<ElementReference>> {
        self.get("/v1/element-refs")
    }

    pub fn list_element_references_for_tab(&self, tab_id: &str) -> Result<Vec<ElementReference>> {
        Ok(self
            .list_element_references()?
            .into_iter()
            .filter(|reference| reference.tab_id == tab_id)
            .collect())
    }

    pub fn wait_for_next_element_reference(
        &self,
        tab_id: &str,
        timeout: Duration,
    ) -> Result<ElementReference> {
        let known_ids = self.element_reference_ids_for_tab(tab_id)?;
        self.wait_for_new_element_reference(tab_id, &known_ids, timeout)
    }

    pub fn click(&self, tab_id: &str, session_id: &str, selector: &str) -> Result<BrowserCommand> {
        self.agent_action(
            tab_id,
            session_id,
            AgentAction::Click {
                selector: Some(selector.to_string()),
                element_ref_id: None,
            },
        )
    }

    pub fn click_and_wait(
        &self,
        tab_id: &str,
        session_id: &str,
        selector: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        let command = self.click(tab_id, session_id, selector)?;
        self.wait_for_command_result(&command.id, timeout)
    }

    pub fn click_ref(
        &self,
        tab_id: &str,
        session_id: &str,
        element_ref_id: &str,
    ) -> Result<BrowserCommand> {
        self.agent_action(
            tab_id,
            session_id,
            AgentAction::Click {
                selector: None,
                element_ref_id: Some(element_ref_id.to_string()),
            },
        )
    }

    pub fn click_ref_and_wait(
        &self,
        tab_id: &str,
        session_id: &str,
        element_ref_id: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        let command = self.click_ref(tab_id, session_id, element_ref_id)?;
        self.wait_for_command_result(&command.id, timeout)
    }

    pub fn double_click(
        &self,
        tab_id: &str,
        session_id: &str,
        selector: &str,
    ) -> Result<BrowserCommand> {
        self.agent_action(
            tab_id,
            session_id,
            AgentAction::DoubleClick {
                selector: Some(selector.to_string()),
                element_ref_id: None,
            },
        )
    }

    pub fn double_click_and_wait(
        &self,
        tab_id: &str,
        session_id: &str,
        selector: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        let command = self.double_click(tab_id, session_id, selector)?;
        self.wait_for_command_result(&command.id, timeout)
    }

    pub fn double_click_ref(
        &self,
        tab_id: &str,
        session_id: &str,
        element_ref_id: &str,
    ) -> Result<BrowserCommand> {
        self.agent_action(
            tab_id,
            session_id,
            AgentAction::DoubleClick {
                selector: None,
                element_ref_id: Some(element_ref_id.to_string()),
            },
        )
    }

    pub fn double_click_ref_and_wait(
        &self,
        tab_id: &str,
        session_id: &str,
        element_ref_id: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        let command = self.double_click_ref(tab_id, session_id, element_ref_id)?;
        self.wait_for_command_result(&command.id, timeout)
    }

    pub fn drag_to(
        &self,
        tab_id: &str,
        session_id: &str,
        source_selector: &str,
        target_selector: &str,
    ) -> Result<BrowserCommand> {
        self.agent_action(
            tab_id,
            session_id,
            AgentAction::DragTo {
                source_selector: Some(source_selector.to_string()),
                source_element_ref_id: None,
                target_selector: Some(target_selector.to_string()),
                target_element_ref_id: None,
            },
        )
    }

    pub fn drag_to_and_wait(
        &self,
        tab_id: &str,
        session_id: &str,
        source_selector: &str,
        target_selector: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        let command = self.drag_to(tab_id, session_id, source_selector, target_selector)?;
        self.wait_for_command_result(&command.id, timeout)
    }

    pub fn drag_ref_to_ref(
        &self,
        tab_id: &str,
        session_id: &str,
        source_element_ref_id: &str,
        target_element_ref_id: &str,
    ) -> Result<BrowserCommand> {
        self.agent_action(
            tab_id,
            session_id,
            AgentAction::DragTo {
                source_selector: None,
                source_element_ref_id: Some(source_element_ref_id.to_string()),
                target_selector: None,
                target_element_ref_id: Some(target_element_ref_id.to_string()),
            },
        )
    }

    pub fn drag_ref_to_ref_and_wait(
        &self,
        tab_id: &str,
        session_id: &str,
        source_element_ref_id: &str,
        target_element_ref_id: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        let command = self.drag_ref_to_ref(
            tab_id,
            session_id,
            source_element_ref_id,
            target_element_ref_id,
        )?;
        self.wait_for_command_result(&command.id, timeout)
    }

    pub fn hover(&self, tab_id: &str, session_id: &str, selector: &str) -> Result<BrowserCommand> {
        self.agent_action(
            tab_id,
            session_id,
            AgentAction::Hover {
                selector: Some(selector.to_string()),
                element_ref_id: None,
            },
        )
    }

    pub fn hover_and_wait(
        &self,
        tab_id: &str,
        session_id: &str,
        selector: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        let command = self.hover(tab_id, session_id, selector)?;
        self.wait_for_command_result(&command.id, timeout)
    }

    pub fn hover_ref(
        &self,
        tab_id: &str,
        session_id: &str,
        element_ref_id: &str,
    ) -> Result<BrowserCommand> {
        self.agent_action(
            tab_id,
            session_id,
            AgentAction::Hover {
                selector: None,
                element_ref_id: Some(element_ref_id.to_string()),
            },
        )
    }

    pub fn hover_ref_and_wait(
        &self,
        tab_id: &str,
        session_id: &str,
        element_ref_id: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        let command = self.hover_ref(tab_id, session_id, element_ref_id)?;
        self.wait_for_command_result(&command.id, timeout)
    }

    pub fn focus(&self, tab_id: &str, session_id: &str, selector: &str) -> Result<BrowserCommand> {
        self.agent_action(
            tab_id,
            session_id,
            AgentAction::Focus {
                selector: Some(selector.to_string()),
                element_ref_id: None,
            },
        )
    }

    pub fn focus_and_wait(
        &self,
        tab_id: &str,
        session_id: &str,
        selector: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        let command = self.focus(tab_id, session_id, selector)?;
        self.wait_for_command_result(&command.id, timeout)
    }

    pub fn focus_ref(
        &self,
        tab_id: &str,
        session_id: &str,
        element_ref_id: &str,
    ) -> Result<BrowserCommand> {
        self.agent_action(
            tab_id,
            session_id,
            AgentAction::Focus {
                selector: None,
                element_ref_id: Some(element_ref_id.to_string()),
            },
        )
    }

    pub fn focus_ref_and_wait(
        &self,
        tab_id: &str,
        session_id: &str,
        element_ref_id: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        let command = self.focus_ref(tab_id, session_id, element_ref_id)?;
        self.wait_for_command_result(&command.id, timeout)
    }

    pub fn type_text(
        &self,
        tab_id: &str,
        session_id: &str,
        selector: &str,
        text: &str,
        clear_first: bool,
    ) -> Result<BrowserCommand> {
        self.agent_action(
            tab_id,
            session_id,
            AgentAction::TypeText {
                selector: Some(selector.to_string()),
                element_ref_id: None,
                text: text.to_string(),
                clear_first,
            },
        )
    }

    pub fn type_text_and_wait(
        &self,
        tab_id: &str,
        session_id: &str,
        selector: &str,
        text: &str,
        clear_first: bool,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        let command = self.type_text(tab_id, session_id, selector, text, clear_first)?;
        self.wait_for_command_result(&command.id, timeout)
    }

    pub fn type_text_ref(
        &self,
        tab_id: &str,
        session_id: &str,
        element_ref_id: &str,
        text: &str,
        clear_first: bool,
    ) -> Result<BrowserCommand> {
        self.agent_action(
            tab_id,
            session_id,
            AgentAction::TypeText {
                selector: None,
                element_ref_id: Some(element_ref_id.to_string()),
                text: text.to_string(),
                clear_first,
            },
        )
    }

    pub fn type_text_ref_and_wait(
        &self,
        tab_id: &str,
        session_id: &str,
        element_ref_id: &str,
        text: &str,
        clear_first: bool,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        let command = self.type_text_ref(tab_id, session_id, element_ref_id, text, clear_first)?;
        self.wait_for_command_result(&command.id, timeout)
    }

    pub fn select_option(
        &self,
        tab_id: &str,
        session_id: &str,
        selector: &str,
        value: &str,
    ) -> Result<BrowserCommand> {
        self.agent_action(
            tab_id,
            session_id,
            AgentAction::SelectOption {
                selector: Some(selector.to_string()),
                element_ref_id: None,
                value: value.to_string(),
            },
        )
    }

    pub fn select_option_and_wait(
        &self,
        tab_id: &str,
        session_id: &str,
        selector: &str,
        value: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        let command = self.select_option(tab_id, session_id, selector, value)?;
        self.wait_for_command_result(&command.id, timeout)
    }

    pub fn select_option_ref(
        &self,
        tab_id: &str,
        session_id: &str,
        element_ref_id: &str,
        value: &str,
    ) -> Result<BrowserCommand> {
        self.agent_action(
            tab_id,
            session_id,
            AgentAction::SelectOption {
                selector: None,
                element_ref_id: Some(element_ref_id.to_string()),
                value: value.to_string(),
            },
        )
    }

    pub fn select_option_ref_and_wait(
        &self,
        tab_id: &str,
        session_id: &str,
        element_ref_id: &str,
        value: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        let command = self.select_option_ref(tab_id, session_id, element_ref_id, value)?;
        self.wait_for_command_result(&command.id, timeout)
    }

    pub fn set_checked(
        &self,
        tab_id: &str,
        session_id: &str,
        selector: &str,
        checked: bool,
    ) -> Result<BrowserCommand> {
        self.agent_action(
            tab_id,
            session_id,
            AgentAction::SetChecked {
                selector: Some(selector.to_string()),
                element_ref_id: None,
                checked,
            },
        )
    }

    pub fn set_checked_and_wait(
        &self,
        tab_id: &str,
        session_id: &str,
        selector: &str,
        checked: bool,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        let command = self.set_checked(tab_id, session_id, selector, checked)?;
        self.wait_for_command_result(&command.id, timeout)
    }

    pub fn set_checked_ref(
        &self,
        tab_id: &str,
        session_id: &str,
        element_ref_id: &str,
        checked: bool,
    ) -> Result<BrowserCommand> {
        self.agent_action(
            tab_id,
            session_id,
            AgentAction::SetChecked {
                selector: None,
                element_ref_id: Some(element_ref_id.to_string()),
                checked,
            },
        )
    }

    pub fn set_checked_ref_and_wait(
        &self,
        tab_id: &str,
        session_id: &str,
        element_ref_id: &str,
        checked: bool,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        let command = self.set_checked_ref(tab_id, session_id, element_ref_id, checked)?;
        self.wait_for_command_result(&command.id, timeout)
    }

    pub fn scroll_by(
        &self,
        tab_id: &str,
        session_id: &str,
        delta_x: i32,
        delta_y: i32,
    ) -> Result<BrowserCommand> {
        self.agent_action(
            tab_id,
            session_id,
            AgentAction::ScrollBy { delta_x, delta_y },
        )
    }

    pub fn scroll_by_and_wait(
        &self,
        tab_id: &str,
        session_id: &str,
        delta_x: i32,
        delta_y: i32,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        let command = self.scroll_by(tab_id, session_id, delta_x, delta_y)?;
        self.wait_for_command_result(&command.id, timeout)
    }

    pub fn scroll_into_view(
        &self,
        tab_id: &str,
        session_id: &str,
        selector: &str,
    ) -> Result<BrowserCommand> {
        self.agent_action(
            tab_id,
            session_id,
            AgentAction::ScrollIntoView {
                selector: Some(selector.to_string()),
                element_ref_id: None,
            },
        )
    }

    pub fn scroll_into_view_and_wait(
        &self,
        tab_id: &str,
        session_id: &str,
        selector: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        let command = self.scroll_into_view(tab_id, session_id, selector)?;
        self.wait_for_command_result(&command.id, timeout)
    }

    pub fn scroll_ref_into_view(
        &self,
        tab_id: &str,
        session_id: &str,
        element_ref_id: &str,
    ) -> Result<BrowserCommand> {
        self.agent_action(
            tab_id,
            session_id,
            AgentAction::ScrollIntoView {
                selector: None,
                element_ref_id: Some(element_ref_id.to_string()),
            },
        )
    }

    pub fn scroll_ref_into_view_and_wait(
        &self,
        tab_id: &str,
        session_id: &str,
        element_ref_id: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        let command = self.scroll_ref_into_view(tab_id, session_id, element_ref_id)?;
        self.wait_for_command_result(&command.id, timeout)
    }

    pub fn press_key(&self, tab_id: &str, session_id: &str, key: &str) -> Result<BrowserCommand> {
        self.agent_action(
            tab_id,
            session_id,
            AgentAction::PressKey {
                key: key.to_string(),
            },
        )
    }

    pub fn press_key_and_wait(
        &self,
        tab_id: &str,
        session_id: &str,
        key: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        let command = self.press_key(tab_id, session_id, key)?;
        self.wait_for_command_result(&command.id, timeout)
    }

    pub fn submit(&self, tab_id: &str, session_id: &str, selector: &str) -> Result<BrowserCommand> {
        self.agent_action(
            tab_id,
            session_id,
            AgentAction::Submit {
                selector: Some(selector.to_string()),
                element_ref_id: None,
            },
        )
    }

    pub fn submit_and_wait(
        &self,
        tab_id: &str,
        session_id: &str,
        selector: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        let command = self.submit(tab_id, session_id, selector)?;
        self.wait_for_command_result(&command.id, timeout)
    }

    pub fn submit_ref(
        &self,
        tab_id: &str,
        session_id: &str,
        element_ref_id: &str,
    ) -> Result<BrowserCommand> {
        self.agent_action(
            tab_id,
            session_id,
            AgentAction::Submit {
                selector: None,
                element_ref_id: Some(element_ref_id.to_string()),
            },
        )
    }

    pub fn submit_ref_and_wait(
        &self,
        tab_id: &str,
        session_id: &str,
        element_ref_id: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        let command = self.submit_ref(tab_id, session_id, element_ref_id)?;
        self.wait_for_command_result(&command.id, timeout)
    }

    pub fn wait_for_selector(
        &self,
        tab_id: &str,
        session_id: &str,
        selector: &str,
        timeout: Option<Duration>,
    ) -> Result<BrowserCommand> {
        self.agent_action(
            tab_id,
            session_id,
            AgentAction::WaitForSelector {
                selector: selector.to_string(),
                timeout_ms: timeout.map(duration_millis),
            },
        )
    }

    pub fn wait_for_selector_and_wait(
        &self,
        tab_id: &str,
        session_id: &str,
        selector: &str,
        selector_timeout: Option<Duration>,
        result_timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        let command = self.wait_for_selector(tab_id, session_id, selector, selector_timeout)?;
        self.wait_for_command_result(&command.id, result_timeout)
    }

    pub fn wait_for_selector_details(
        &self,
        tab_id: &str,
        session_id: &str,
        selector: &str,
        selector_timeout: Option<Duration>,
        result_timeout: Duration,
    ) -> Result<SelectorWaitResult> {
        SelectorWaitResult::from_command_report(self.wait_for_selector_and_wait(
            tab_id,
            session_id,
            selector,
            selector_timeout,
            result_timeout,
        )?)
    }

    pub fn extract_text(
        &self,
        tab_id: &str,
        session_id: &str,
        selector: &str,
    ) -> Result<BrowserCommand> {
        self.agent_action(
            tab_id,
            session_id,
            AgentAction::ExtractText {
                selector: Some(selector.to_string()),
                element_ref_id: None,
            },
        )
    }

    pub fn extract_text_and_wait(
        &self,
        tab_id: &str,
        session_id: &str,
        selector: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        let command = self.extract_text(tab_id, session_id, selector)?;
        self.wait_for_command_result(&command.id, timeout)
    }

    pub fn extract_text_result(
        &self,
        tab_id: &str,
        session_id: &str,
        selector: &str,
        timeout: Duration,
    ) -> Result<ExtractedText> {
        ExtractedText::from_command_report(
            self.extract_text_and_wait(tab_id, session_id, selector, timeout)?,
        )
    }

    pub fn extract_text_ref(
        &self,
        tab_id: &str,
        session_id: &str,
        element_ref_id: &str,
    ) -> Result<BrowserCommand> {
        self.agent_action(
            tab_id,
            session_id,
            AgentAction::ExtractText {
                selector: None,
                element_ref_id: Some(element_ref_id.to_string()),
            },
        )
    }

    pub fn extract_text_ref_and_wait(
        &self,
        tab_id: &str,
        session_id: &str,
        element_ref_id: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        let command = self.extract_text_ref(tab_id, session_id, element_ref_id)?;
        self.wait_for_command_result(&command.id, timeout)
    }

    pub fn extract_text_ref_result(
        &self,
        tab_id: &str,
        session_id: &str,
        element_ref_id: &str,
        timeout: Duration,
    ) -> Result<ExtractedText> {
        ExtractedText::from_command_report(self.extract_text_ref_and_wait(
            tab_id,
            session_id,
            element_ref_id,
            timeout,
        )?)
    }

    pub fn inspect_element(
        &self,
        tab_id: &str,
        session_id: &str,
        selector: &str,
    ) -> Result<BrowserCommand> {
        self.agent_action(
            tab_id,
            session_id,
            AgentAction::InspectElement {
                selector: Some(selector.to_string()),
                element_ref_id: None,
            },
        )
    }

    pub fn inspect_element_and_wait(
        &self,
        tab_id: &str,
        session_id: &str,
        selector: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        let command = self.inspect_element(tab_id, session_id, selector)?;
        self.wait_for_command_result(&command.id, timeout)
    }

    pub fn inspect_element_details(
        &self,
        tab_id: &str,
        session_id: &str,
        selector: &str,
        timeout: Duration,
    ) -> Result<InspectedElement> {
        InspectedElement::from_command_report(
            self.inspect_element_and_wait(tab_id, session_id, selector, timeout)?,
        )
    }

    pub fn inspect_element_ref(
        &self,
        tab_id: &str,
        session_id: &str,
        element_ref_id: &str,
    ) -> Result<BrowserCommand> {
        self.agent_action(
            tab_id,
            session_id,
            AgentAction::InspectElement {
                selector: None,
                element_ref_id: Some(element_ref_id.to_string()),
            },
        )
    }

    pub fn inspect_element_ref_and_wait(
        &self,
        tab_id: &str,
        session_id: &str,
        element_ref_id: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        let command = self.inspect_element_ref(tab_id, session_id, element_ref_id)?;
        self.wait_for_command_result(&command.id, timeout)
    }

    pub fn inspect_element_ref_details(
        &self,
        tab_id: &str,
        session_id: &str,
        element_ref_id: &str,
        timeout: Duration,
    ) -> Result<InspectedElement> {
        InspectedElement::from_command_report(self.inspect_element_ref_and_wait(
            tab_id,
            session_id,
            element_ref_id,
            timeout,
        )?)
    }

    pub fn start_element_picker(&self, tab_id: &str, session_id: &str) -> Result<BrowserCommand> {
        self.agent_action(tab_id, session_id, AgentAction::StartElementPicker)
    }

    pub fn execute_script(
        &self,
        tab_id: &str,
        session_id: &str,
        script: &str,
    ) -> Result<BrowserCommand> {
        self.agent_action(
            tab_id,
            session_id,
            AgentAction::ExecuteScript {
                script: script.to_string(),
            },
        )
    }

    pub fn execute_script_and_wait(
        &self,
        tab_id: &str,
        session_id: &str,
        script: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        let command = self.execute_script(tab_id, session_id, script)?;
        self.wait_for_command_result(&command.id, timeout)
    }

    pub fn agent_action(
        &self,
        tab_id: &str,
        session_id: &str,
        action: AgentAction,
    ) -> Result<BrowserCommand> {
        self.post(
            &format!("/v1/tabs/{tab_id}/actions"),
            &AgentActionRequest {
                session_id: session_id.to_string(),
                action,
            },
        )
    }

    pub fn agent_action_and_wait(
        &self,
        tab_id: &str,
        session_id: &str,
        action: AgentAction,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        let command = self.agent_action(tab_id, session_id, action)?;
        self.wait_for_command_result(&command.id, timeout)
    }

    pub fn list_command_results(&self) -> Result<Vec<CommandExecutionReport>> {
        self.get("/v1/command-results")
    }

    pub fn list_command_results_for_tab(
        &self,
        tab_id: &str,
    ) -> Result<Vec<CommandExecutionReport>> {
        Ok(self
            .list_command_results()?
            .into_iter()
            .filter(|result| result.tab_id == tab_id)
            .collect())
    }

    pub fn list_audit_events(&self) -> Result<Vec<AuditEvent>> {
        self.get("/v1/audit-events")
    }

    pub fn handoff_snapshot(&self) -> Result<HandoffSnapshot> {
        self.get("/v1/handoff")
    }

    pub fn restore_handoff_snapshot(
        &self,
        snapshot: &HandoffSnapshot,
    ) -> Result<HandoffRestoreReport> {
        let (tab_plan, skipped_tabs) = handoff_restore_tab_plan(snapshot);
        let mut imported_bookmarks = Vec::new();
        for bookmark in &snapshot.bookmarks {
            let restored = self.create_bookmark(&bookmark.url, bookmark.title.as_deref())?;
            imported_bookmarks.push(RestoredHandoffBookmark {
                source_bookmark_id: bookmark.id.clone(),
                bookmark_id: restored.id,
                url: restored.url,
            });
        }

        let mut opened_tabs = Vec::new();
        let mut active_tab_id = None;
        for planned in tab_plan {
            let tab = self.create_tab(Some(&planned.url), None)?;
            if planned.active {
                active_tab_id = Some(tab.id.clone());
            }
            opened_tabs.push(RestoredHandoffTab {
                source_tab_id: planned.source_tab_id,
                tab_id: tab.id,
                url: planned.url,
                active: planned.active,
            });
        }

        if let Some(tab_id) = active_tab_id.as_deref() {
            self.activate_tab(tab_id)?;
        }
        let active_tab_id = self.active_tab()?.map(|tab| tab.id).or(active_tab_id);

        Ok(HandoffRestoreReport {
            opened_tabs,
            skipped_tabs,
            imported_bookmarks,
            active_tab_id,
        })
    }

    pub fn command_result(&self, command_id: &str) -> Result<Option<CommandExecutionReport>> {
        Ok(self
            .list_command_results()?
            .into_iter()
            .rev()
            .find(|result| result.command_id == command_id))
    }

    pub fn wait_for_command_result(
        &self,
        command_id: &str,
        timeout: Duration,
    ) -> Result<CommandExecutionReport> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(result) = self.command_result(command_id)? {
                return Ok(result);
            }
            if Instant::now() >= deadline {
                return Err(SdkError::Timeout(command_id.to_string()));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn scoped_agent_pane_from_opened(
        &self,
        opened: OpenedScopedAgentPane,
    ) -> Result<ScopedAgentPane> {
        let connection = AgentPaneConnectionDescriptor {
            control_url: self.base_url.clone(),
            pane_id: opened.pane.id.clone(),
            pane_url: opened.pane.url.clone(),
            session_id: opened.connection.session_id.clone(),
            tab_id: opened.connection.tab_id.clone(),
            grant_token: opened.connection.grant_token.clone(),
            session_policy: opened.connection.session_policy.clone(),
            expires_at_unix: opened.connection.expires_at_unix,
        };
        let agent = self.scoped_agent_client(&opened.grant)?;

        Ok(ScopedAgentPane {
            pane: opened.pane,
            grant: opened.grant,
            connection,
            agent,
        })
    }

    fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        Ok(self
            .authorized(self.agent.get(format!("{}{}", self.base_url, path)))
            .call()?
            .body_mut()
            .read_json::<T>()?)
    }

    fn post<T: serde::Serialize, R: DeserializeOwned>(&self, path: &str, body: &T) -> Result<R> {
        Ok(self
            .authorized(self.agent.post(format!("{}{}", self.base_url, path)))
            .send_json(body)?
            .body_mut()
            .read_json::<R>()?)
    }

    fn post_empty<R: DeserializeOwned>(&self, path: &str) -> Result<R> {
        Ok(self
            .authorized(self.agent.post(format!("{}{}", self.base_url, path)))
            .send_empty()?
            .body_mut()
            .read_json::<R>()?)
    }

    fn delete<R: DeserializeOwned>(&self, path: &str) -> Result<R> {
        Ok(self
            .authorized(self.agent.delete(format!("{}{}", self.base_url, path)))
            .call()?
            .body_mut()
            .read_json::<R>()?)
    }

    fn authorized<B>(&self, request: ureq::RequestBuilder<B>) -> ureq::RequestBuilder<B> {
        let request = request.header("Authorization", format!("Bearer {}", self.bearer_token));
        if let Some(origin) = &self.origin_header {
            request.header("Origin", origin)
        } else {
            request
        }
    }

    fn element_reference_ids_for_tab(&self, tab_id: &str) -> Result<BTreeSet<String>> {
        Ok(self
            .list_element_references_for_tab(tab_id)?
            .into_iter()
            .map(|reference| reference.id)
            .collect())
    }

    fn wait_for_new_element_reference(
        &self,
        tab_id: &str,
        known_ids: &BTreeSet<String>,
        timeout: Duration,
    ) -> Result<ElementReference> {
        let deadline = Instant::now() + timeout;
        loop {
            let mut new_refs = self
                .list_element_references_for_tab(tab_id)?
                .into_iter()
                .filter(|reference| !known_ids.contains(&reference.id))
                .collect::<Vec<_>>();
            new_refs.sort_by(|left, right| {
                left.created_at_unix
                    .cmp(&right.created_at_unix)
                    .then_with(|| left.id.cmp(&right.id))
            });
            if let Some(reference) = new_refs.into_iter().next() {
                return Ok(reference);
            }
            if Instant::now() >= deadline {
                return Err(SdkError::Timeout(format!(
                    "next element reference for tab {tab_id}"
                )));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

fn handoff_restore_tab_plan(snapshot: &HandoffSnapshot) -> (Vec<HandoffRestoreTabPlan>, usize) {
    let active_source_id = snapshot.active_tab.as_ref().map(|tab| tab.id.as_str());
    let mut skipped_tabs = 0;
    let mut planned = snapshot
        .tabs
        .iter()
        .filter_map(|tab| match tab.current_url.as_deref() {
            Some(url) => Some(HandoffRestoreTabPlan {
                source_tab_id: tab.id.clone(),
                url: url.to_string(),
                active: active_source_id == Some(tab.id.as_str()),
            }),
            None => {
                skipped_tabs += 1;
                None
            }
        })
        .collect::<Vec<_>>();

    if let Some(active_tab) = &snapshot.active_tab {
        let active_already_planned = planned.iter().any(|tab| tab.source_tab_id == active_tab.id);
        if !active_already_planned {
            if let Some(url) = active_tab.current_url.as_deref() {
                planned.push(HandoffRestoreTabPlan {
                    source_tab_id: active_tab.id.clone(),
                    url: url.to_string(),
                    active: true,
                });
            }
        }
    }

    (planned, skipped_tabs)
}

#[derive(Debug, Deserialize)]
struct ControlEndpoint {
    url: String,
    owner_token: String,
}

fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

fn sdk_http_status(error: &SdkError) -> Option<u16> {
    match error {
        SdkError::Http(ureq::Error::StatusCode(status)) => Some(*status),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};
    use telescope_control::{serve_server, ControlPlane};
    use telescope_core::{CredentialVault, MemorySecretStore};

    #[test]
    fn sdk_parses_inspect_element_command_report() {
        let report = CommandExecutionReport {
            command_id: "inspect-1".to_string(),
            tab_id: "tab-1".to_string(),
            session_id: None,
            target_origin: None,
            grant_token: None,
            status: CommandExecutionStatus::Succeeded,
            message: Some(
                r#"{"ok":true,"action":"inspect_element","selector":"button[type=\"submit\"]","tagName":"button","id":"submit","className":"primary","role":"button","label":"Sign in","text":"Sign in","inputType":null,"disabled":false,"checked":null,"selected":null,"editable":false,"bounds":{"x":1.0,"y":2.0,"width":3.0,"height":4.0}}"#
                    .to_string(),
            ),
            completed_at_unix: 0,
        };

        let element = InspectedElement::from_command_report(report).unwrap();
        assert_eq!(element.selector, "button[type=\"submit\"]");
        assert_eq!(element.tag_name, "button");
        assert_eq!(element.id.as_deref(), Some("submit"));
        assert_eq!(element.class_name.as_deref(), Some("primary"));
        assert_eq!(element.label.as_deref(), Some("Sign in"));
        assert!(!element.disabled);
        assert_eq!(element.bounds.width, 3.0);
    }

    #[test]
    fn sdk_reports_failed_inspect_element_command() {
        let report = CommandExecutionReport {
            command_id: "inspect-2".to_string(),
            tab_id: "tab-1".to_string(),
            session_id: None,
            target_origin: None,
            grant_token: None,
            status: CommandExecutionStatus::Failed,
            message: Some(
                r##"{"ok":false,"action":"inspect_element","reason":"missing_element","selector":"#missing"}"##
                    .to_string(),
            ),
            completed_at_unix: 0,
        };

        let error = InspectedElement::from_command_report(report).unwrap_err();
        assert!(matches!(
            error,
            SdkError::CommandFailed(message) if message.contains("inspect-2: missing_element")
        ));
    }

    #[test]
    fn sdk_parses_extract_text_command_report() {
        let report = CommandExecutionReport {
            command_id: "extract-1".to_string(),
            tab_id: "tab-1".to_string(),
            session_id: None,
            target_origin: None,
            grant_token: None,
            status: CommandExecutionStatus::Succeeded,
            message: Some(
                r#"{"ok":true,"action":"extract_text","selector":"main","text":"Welcome"}"#
                    .to_string(),
            ),
            completed_at_unix: 0,
        };

        let extracted = ExtractedText::from_command_report(report).unwrap();
        assert_eq!(extracted.selector, "main");
        assert_eq!(extracted.text, "Welcome");
    }

    #[test]
    fn sdk_reports_failed_extract_text_command() {
        let report = CommandExecutionReport {
            command_id: "extract-2".to_string(),
            tab_id: "tab-1".to_string(),
            session_id: None,
            target_origin: None,
            grant_token: None,
            status: CommandExecutionStatus::Failed,
            message: Some(
                r##"{"ok":false,"action":"extract_text","reason":"missing_element","selector":"#missing"}"##
                    .to_string(),
            ),
            completed_at_unix: 0,
        };

        let error = ExtractedText::from_command_report(report).unwrap_err();
        assert!(matches!(
            error,
            SdkError::CommandFailed(message) if message.contains("extract-2: missing_element")
        ));
    }

    #[test]
    fn sdk_parses_wait_for_selector_command_report() {
        let report = CommandExecutionReport {
            command_id: "wait-1".to_string(),
            tab_id: "tab-1".to_string(),
            session_id: None,
            target_origin: None,
            grant_token: None,
            status: CommandExecutionStatus::Succeeded,
            message: Some(
                r#"{"ok":true,"action":"wait_for_selector","selector":"main"}"#.to_string(),
            ),
            completed_at_unix: 0,
        };

        let result = SelectorWaitResult::from_command_report(report).unwrap();
        assert_eq!(result.selector, "main");
        assert_eq!(result.timeout_ms, None);
    }

    #[test]
    fn sdk_reports_failed_wait_for_selector_command() {
        let report = CommandExecutionReport {
            command_id: "wait-2".to_string(),
            tab_id: "tab-1".to_string(),
            session_id: None,
            target_origin: None,
            grant_token: None,
            status: CommandExecutionStatus::Failed,
            message: Some(
                r##"{"ok":false,"reason":"timeout","selector":"#missing","timeoutMs":250}"##
                    .to_string(),
            ),
            completed_at_unix: 0,
        };

        let error = SelectorWaitResult::from_command_report(report).unwrap_err();
        assert!(matches!(
            error,
            SdkError::CommandFailed(message) if message.contains("wait-2: timeout")
        ));
    }

    #[test]
    fn sdk_round_trips_against_local_control_server() {
        let plane = ControlPlane::new(CredentialVault::ephemeral(
            "sdk-test",
            Arc::new(MemorySecretStore::new()),
        ));
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let addr = server.server_addr().to_ip().unwrap();
        let token = "sdk-test-token";
        let server_plane = plane.clone();
        thread::spawn(move || {
            let _ = serve_server(server, token.to_string(), server_plane);
        });

        let client = TelescopeClient::new(format!("http://{addr}"), token).unwrap();
        let preflight = ureq::Agent::new_with_defaults()
            .options(format!("http://{addr}/v1/page-contexts"))
            .header("Access-Control-Request-Method", "GET")
            .header(
                "Access-Control-Request-Headers",
                "authorization, content-type",
            )
            .call()
            .unwrap();
        assert_eq!(preflight.status().as_u16(), 204);
        assert_eq!(
            preflight
                .headers()
                .get("access-control-allow-origin")
                .unwrap()
                .to_str()
                .unwrap(),
            "*"
        );
        assert!(preflight
            .headers()
            .get("access-control-allow-headers")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("Authorization"));
        let session = client
            .create_session(["https://example.com"], true)
            .unwrap();
        assert!(client.active_tab().unwrap().is_none());
        let mut initial_browser_tab = client
            .active_browser_tab_or_create(Some("https://example.com/start"), Some(&session.id))
            .unwrap();
        assert_eq!(
            initial_browser_tab.state().current_url.as_deref(),
            Some("https://example.com/start")
        );
        let reused_initial_tab = client
            .active_tab_or_create(Some("https://example.com/ignored"), None)
            .unwrap();
        assert_eq!(reused_initial_tab.id, initial_browser_tab.id());
        assert_eq!(client.list_tabs().unwrap().len(), 1);
        assert_eq!(
            initial_browser_tab
                .navigate("https://example.com/login")
                .unwrap()
                .current_url
                .as_deref(),
            Some("https://example.com/login")
        );
        let tab = initial_browser_tab.into_state();
        assert_eq!(client.list_tabs().unwrap().len(), 1);
        assert_eq!(client.active_tab().unwrap().unwrap().id, tab.id);
        let second_tab = client
            .create_tab(Some("https://example.com/other"), Some(&session.id))
            .unwrap();
        assert_eq!(client.active_tab().unwrap().unwrap().id, second_tab.id);
        assert_eq!(client.activate_tab(&tab.id).unwrap().id, tab.id);
        assert_eq!(client.active_tab().unwrap().unwrap().id, tab.id);
        assert_eq!(client.close_tab(&second_tab.id).unwrap().id, second_tab.id);
        assert_eq!(client.list_tabs().unwrap().len(), 1);
        let mut browser_tab = client.active_browser_tab().unwrap().unwrap();
        assert_eq!(browser_tab.id(), tab.id);
        assert_eq!(
            browser_tab.state().session_id.as_deref(),
            Some(session.id.as_str())
        );
        assert_eq!(
            browser_tab
                .navigate("https://example.com/login")
                .unwrap()
                .current_url
                .as_deref(),
            Some("https://example.com/login")
        );
        assert!(matches!(
            browser_tab.go_back().unwrap().kind,
            BrowserCommandKind::GoBack
        ));
        assert!(matches!(
            browser_tab.go_forward().unwrap().kind,
            BrowserCommandKind::GoForward
        ));
        assert!(matches!(
            browser_tab.reload().unwrap().kind,
            BrowserCommandKind::Reload
        ));
        let bookmark = browser_tab.bookmark(Some("Login")).unwrap();
        assert_eq!(bookmark.url, "https://example.com/login");
        assert_eq!(bookmark.title.as_deref(), Some("Login"));
        let bookmark = client.bookmark_tab(&tab.id, None).unwrap();
        assert_eq!(bookmark.url, "https://example.com/login");
        assert_eq!(bookmark.title.as_deref(), Some("Login"));
        assert_eq!(client.list_bookmarks().unwrap(), vec![bookmark.clone()]);
        let docs_bookmark = client
            .create_bookmark("https://example.com/docs", Some("Docs"))
            .unwrap();
        assert_eq!(
            browser_tab
                .open_bookmark(&docs_bookmark.id)
                .unwrap()
                .current_url
                .as_deref(),
            Some("https://example.com/docs")
        );
        assert_eq!(
            client
                .open_bookmark_for_tab(&tab.id, &bookmark.id)
                .unwrap()
                .current_url
                .as_deref(),
            Some("https://example.com/login")
        );
        let docs_tab = browser_tab
            .open_bookmark_in_new_tab(&docs_bookmark.id)
            .unwrap();
        assert_ne!(docs_tab.id(), browser_tab.id());
        assert_eq!(
            docs_tab.state().current_url.as_deref(),
            Some("https://example.com/docs")
        );
        let login_tab = client.open_bookmark_in_new_tab(&bookmark.id).unwrap();
        assert_ne!(login_tab.id(), tab.id);
        assert_eq!(
            login_tab.state().current_url.as_deref(),
            Some("https://example.com/login")
        );
        assert!(matches!(
            client.open_bookmark_for_tab(&tab.id, "missing-bookmark"),
            Err(SdkError::NotFound(message)) if message.contains("missing-bookmark")
        ));
        assert!(matches!(
            client.open_bookmark_in_new_tab("missing-bookmark"),
            Err(SdkError::NotFound(message)) if message.contains("missing-bookmark")
        ));
        assert!(matches!(
            client.bookmark_tab("missing-tab", None),
            Err(SdkError::NotFound(message)) if message.contains("missing-tab")
        ));
        let empty_tab = client.create_tab(None, None).unwrap();
        assert!(matches!(
            client.bookmark_tab(&empty_tab.id, None),
            Err(SdkError::InvalidOperation(message)) if message.contains("has no current URL")
        ));
        assert_eq!(client.close_tab(&empty_tab.id).unwrap().id, empty_tab.id);
        let no_credential_tab = client
            .create_tab(Some("https://no-creds.example"), None)
            .unwrap();
        assert!(matches!(
            client.default_credential_for_tab(&no_credential_tab.id),
            Err(SdkError::InvalidOperation(message)) if message.contains("has no saved credentials")
        ));
        assert_eq!(
            client.close_tab(&no_credential_tab.id).unwrap().id,
            no_credential_tab.id
        );
        assert_eq!(client.activate_tab(&tab.id).unwrap().id, tab.id);
        let credential = client
            .store_credential("https://example.com", "me", "secret")
            .unwrap();
        let command = client
            .fill_login(&tab.id, &session.id, &credential.id)
            .unwrap();

        let command_json = serde_json::to_string(&command).unwrap();
        assert!(command_json.contains("me"));
        assert!(!command_json.contains("secret"));

        let tab_credential = browser_tab
            .store_credential("tab-me", "tab-secret")
            .unwrap();
        assert_eq!(
            tab_credential.login_url.as_deref(),
            Some("https://example.com/login")
        );
        assert_eq!(browser_tab.list_credentials().unwrap().len(), 2);
        let updated_tab_credential = browser_tab
            .store_credential("tab-me", "tab-secret-updated")
            .unwrap();
        assert_eq!(updated_tab_credential.id, tab_credential.id);
        assert_eq!(
            updated_tab_credential.created_at_unix,
            tab_credential.created_at_unix
        );
        assert_eq!(browser_tab.list_credentials().unwrap().len(), 2);
        let default_credential = browser_tab.default_credential().unwrap();
        assert_eq!(
            client.default_credential_for_tab(&tab.id).unwrap().id,
            default_credential.id
        );
        let default_fill_command = browser_tab.fill_default_credential().unwrap();
        let default_fill_json = serde_json::to_string(&default_fill_command).unwrap();
        assert!(default_fill_json.contains(&default_credential.username));
        assert!(!default_fill_json.contains("secret"));
        let tab_fill_command = browser_tab.fill_credential(&tab_credential.id).unwrap();
        let tab_fill_json = serde_json::to_string(&tab_fill_command).unwrap();
        assert!(tab_fill_json.contains("tab-me"));
        assert!(!tab_fill_json.contains("tab-secret"));

        let results = client.list_command_results().unwrap();
        assert!(results.is_empty());
        plane
            .record_command_result(
                &tab_fill_command.id,
                &tab.id,
                CommandExecutionStatus::Succeeded,
                Some(r#"{"ok":true,"action":"fill_login"}"#.to_string()),
            )
            .unwrap();
        plane
            .record_command_result(
                "other-command",
                "other-tab",
                CommandExecutionStatus::Failed,
                Some(r#"{"ok":false}"#.to_string()),
            )
            .unwrap();
        let tab_results = browser_tab.list_command_results().unwrap();
        assert_eq!(tab_results.len(), 1);
        assert_eq!(tab_results[0].command_id, tab_fill_command.id);
        assert_eq!(
            tab_results,
            client.list_command_results_for_tab(&tab.id).unwrap()
        );
        assert_eq!(
            client
                .list_command_results_for_tab("other-tab")
                .unwrap()
                .len(),
            1
        );
        let audit_events = client.list_audit_events().unwrap();
        assert!(audit_events
            .iter()
            .any(|event| matches!(event.kind, AuditEventKind::CredentialFillQueued { .. })));
        assert!(!serde_json::to_string(&audit_events)
            .unwrap()
            .contains("tab-secret"));

        let grant = client
            .create_agent_grant(&session.id, [tab.id.clone()], Some(60))
            .unwrap();
        let grants = client.list_agent_grants().unwrap();
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].token, grant.token);
        assert_eq!(grants[0].session_id, session.id);
        let agent_client = client.scoped_agent_client(&grant).unwrap();
        client
            .publish_page_context_with_elements(
                &tab.id,
                "https://example.com/login",
                Some("Example Login"),
                Some("Sign in to continue"),
                None,
                vec![PageInteractiveElement {
                    selector: "button[type=\"submit\"]".to_string(),
                    tag_name: "button".to_string(),
                    role: Some("button".to_string()),
                    label: Some("Sign in".to_string()),
                    text: Some("Sign in".to_string()),
                    input_type: None,
                    bounds: None,
                    disabled: false,
                }],
            )
            .unwrap();
        assert_eq!(
            client.get_tab(&tab.id).unwrap().title.as_deref(),
            Some("Example Login")
        );
        assert_eq!(
            browser_tab.refresh().unwrap().title.as_deref(),
            Some("Example Login")
        );
        assert_eq!(browser_tab.list_page_contexts().unwrap().len(), 1);
        assert_eq!(
            browser_tab
                .current_page_context()
                .unwrap()
                .unwrap()
                .interactive_elements[0]
                .selector,
            "button[type=\"submit\"]"
        );
        assert_eq!(
            browser_tab
                .wait_for_url("https://example.com/login", Duration::from_millis(250))
                .unwrap()
                .title
                .as_deref(),
            Some("Example Login")
        );
        assert_eq!(
            browser_tab
                .wait_for_url_contains("/login", Duration::from_millis(250))
                .unwrap()
                .url,
            "https://example.com/login"
        );
        assert_eq!(
            browser_tab
                .wait_for_title_contains("Login", Duration::from_millis(250))
                .unwrap()
                .url,
            "https://example.com/login"
        );
        assert_eq!(
            browser_tab
                .wait_for_text_contains("Sign in", Duration::from_millis(250))
                .unwrap()
                .url,
            "https://example.com/login"
        );
        let agent_contexts = agent_client.list_page_contexts().unwrap();
        assert_eq!(agent_contexts.len(), 1);
        assert_eq!(agent_contexts[0].interactive_elements.len(), 1);
        assert_eq!(
            agent_contexts[0].interactive_elements[0].selector,
            "button[type=\"submit\"]"
        );
        let mut wait_navigation_tab = browser_tab.clone();
        let wait_navigation_handle = thread::spawn(move || {
            wait_navigation_tab
                .navigate_and_wait("https://example.com/profile", Duration::from_secs(2))
                .unwrap()
        });
        thread::sleep(Duration::from_millis(50));
        client
            .publish_page_context(
                &tab.id,
                "https://example.com/profile",
                Some("Profile"),
                Some("Account profile"),
                None,
            )
            .unwrap();
        let browser_navigation_context = wait_navigation_handle.join().unwrap();
        assert_eq!(
            browser_navigation_context.url,
            "https://example.com/profile"
        );

        let wait_client = client.clone();
        let wait_tab_id = tab.id.clone();
        let wait_session_id = session.id.clone();
        let wait_client_handle = thread::spawn(move || {
            wait_client
                .navigate_and_wait(
                    &wait_tab_id,
                    "https://example.com/reports",
                    Some(&wait_session_id),
                    Duration::from_secs(2),
                )
                .unwrap()
        });
        thread::sleep(Duration::from_millis(50));
        client
            .publish_page_context(
                &tab.id,
                "https://example.com/reports",
                Some("Reports"),
                Some("Usage reports"),
                None,
            )
            .unwrap();
        let client_navigation_context = wait_client_handle.join().unwrap();
        assert_eq!(client_navigation_context.url, "https://example.com/reports");
        client
            .publish_page_context_with_elements(
                &tab.id,
                "https://example.com/login",
                Some("Example Login"),
                Some("Sign in to continue"),
                None,
                vec![PageInteractiveElement {
                    selector: "button[type=\"submit\"]".to_string(),
                    tag_name: "button".to_string(),
                    role: Some("button".to_string()),
                    label: Some("Sign in".to_string()),
                    text: Some("Sign in".to_string()),
                    input_type: None,
                    bounds: None,
                    disabled: false,
                }],
            )
            .unwrap();
        assert!(agent_client
            .store_credential("https://example.com", "blocked", "blocked")
            .is_err());
        assert!(agent_client.list_credentials_for_tab(&tab.id).is_err());
        assert!(agent_client.list_audit_events().is_err());
        assert!(agent_client.list_bookmarks().is_err());
        assert!(agent_client.handoff_snapshot().is_err());
        assert!(agent_client
            .create_bookmark("https://example.com/login", Some("blocked"))
            .is_err());
        assert!(agent_client
            .create_session(["https://attacker.example"], true)
            .is_err());
        assert!(agent_client.close_tab(&tab.id).is_err());
        assert!(agent_client.list_agent_grants().is_err());

        let scoped_pane = browser_tab
            .open_codex_pane("https://codex.example/login", PanePosition::Left, Some(60))
            .unwrap();
        assert_eq!(scoped_pane.pane.position, PanePosition::Left);
        let handoff = client.handoff_snapshot().unwrap();
        assert_eq!(
            handoff.active_tab.as_ref().map(|tab| tab.id.as_str()),
            Some(tab.id.as_str())
        );
        assert_eq!(handoff.bookmarks.len(), 2);
        assert!(handoff.bookmarks.iter().any(|item| item.id == bookmark.id));
        assert!(handoff
            .bookmarks
            .iter()
            .any(|item| item.id == docs_bookmark.id));
        assert!(handoff
            .agent_panes
            .iter()
            .any(|pane| pane.id == scoped_pane.pane.id));
        let handoff_json = serde_json::to_string(&handoff).unwrap();
        assert!(!handoff_json.contains(&scoped_pane.grant.token));
        assert!(!handoff_json.contains("tab-secret"));
        assert_eq!(scoped_pane.grant.allowed_tab_ids, vec![tab.id.clone()]);
        assert_eq!(scoped_pane.grant.allowed_client_origins.len(), 1);
        assert_eq!(
            scoped_pane.grant.allowed_client_origins[0].display_url(),
            "https://codex.example"
        );
        assert_eq!(scoped_pane.connection.control_url, format!("http://{addr}"));
        assert_eq!(scoped_pane.connection.tab_id, tab.id.as_str());
        assert_eq!(scoped_pane.connection.session_id, session.id.as_str());
        assert_eq!(
            scoped_pane.connection.grant_token,
            scoped_pane.grant.token.as_str()
        );
        assert_eq!(
            scoped_pane.connection.session_policy,
            session.policy.clone()
        );
        assert!(scoped_pane.connection.session_policy.allow_credentials);
        assert!(scoped_pane.connection.session_policy.allow_interactions);
        assert!(!scoped_pane.connection.session_policy.allow_scripts);
        let owner_connection = client.agent_pane_connection(&scoped_pane.pane.id).unwrap();
        assert_eq!(
            owner_connection.grant_token,
            scoped_pane.grant.token.as_str()
        );
        assert_eq!(
            owner_connection.session_policy,
            scoped_pane.connection.session_policy
        );
        let agent_connection = scoped_pane
            .agent
            .agent_pane_connection(&scoped_pane.pane.id)
            .unwrap();
        assert_eq!(agent_connection.tab_id, tab.id.as_str());
        assert_eq!(
            agent_connection.session_policy,
            scoped_pane.connection.session_policy
        );
        assert_eq!(scoped_pane.tab_id(), tab.id.as_str());
        assert_eq!(scoped_pane.session_id(), session.id.as_str());
        assert_eq!(scoped_pane.list_page_contexts().unwrap().len(), 1);
        assert_eq!(
            scoped_pane
                .current_page_context()
                .unwrap()
                .unwrap()
                .title
                .as_deref(),
            Some("Example Login")
        );
        let wait_context_pane = scoped_pane.clone();
        let wait_context_handle = thread::spawn(move || {
            wait_context_pane
                .wait_for_url_contains("/dashboard", Duration::from_secs(2))
                .unwrap()
        });
        thread::sleep(Duration::from_millis(50));
        client
            .publish_page_context(
                &tab.id,
                "https://example.com/dashboard",
                Some("Dashboard"),
                Some("Welcome back"),
                None,
            )
            .unwrap();
        let observed_context = wait_context_handle.join().unwrap();
        assert_eq!(observed_context.url, "https://example.com/dashboard");
        assert_eq!(observed_context.title.as_deref(), Some("Dashboard"));
        assert_eq!(
            scoped_pane
                .wait_for_url("https://example.com/dashboard", Duration::from_secs(1))
                .unwrap()
                .text_preview
                .as_deref(),
            Some("Welcome back")
        );
        assert_eq!(
            scoped_pane
                .wait_for_title_contains("Dash", Duration::from_secs(1))
                .unwrap()
                .url,
            "https://example.com/dashboard"
        );
        assert_eq!(
            scoped_pane
                .wait_for_text_contains("Welcome", Duration::from_secs(1))
                .unwrap()
                .url,
            "https://example.com/dashboard"
        );
        let navigation_pane = scoped_pane.clone();
        let navigation_handle = thread::spawn(move || {
            navigation_pane
                .navigate_and_wait("https://example.com/settings", Duration::from_secs(2))
                .unwrap()
        });
        thread::sleep(Duration::from_millis(50));
        client
            .publish_page_context(
                &tab.id,
                "https://example.com/settings",
                Some("Settings"),
                Some("Account preferences"),
                None,
            )
            .unwrap();
        let navigation_context = navigation_handle.join().unwrap();
        assert_eq!(navigation_context.url, "https://example.com/settings");
        assert_eq!(navigation_context.title.as_deref(), Some("Settings"));
        assert_eq!(client.list_agent_panes().unwrap().len(), 1);
        let login_options = scoped_pane.login_options().unwrap();
        assert_eq!(login_options.len(), 2);
        let login_options_json = serde_json::to_string(&login_options).unwrap();
        assert!(login_options_json.contains("me"));
        assert!(login_options_json.contains("tab-me"));
        assert!(!login_options_json.contains("secret"));
        assert!(!login_options_json.contains("tab-secret"));
        let default_login = scoped_pane.default_login_option().unwrap();
        assert_eq!(default_login.id, login_options[0].id);
        let default_pane_fill = scoped_pane.fill_default_login().unwrap();
        let default_pane_fill_json = serde_json::to_string(&default_pane_fill).unwrap();
        assert!(default_pane_fill_json.contains(&default_login.username));
        assert!(!default_pane_fill_json.contains("secret"));
        browser_tab.delete_credential(&tab_credential.id).unwrap();
        let remaining_credentials = browser_tab.list_credentials().unwrap();
        assert!(!remaining_credentials
            .iter()
            .any(|item| item.id == tab_credential.id));
        let contexts_from_allowed_origin: Vec<PageContextSnapshot> =
            ureq::Agent::new_with_defaults()
                .get(format!("http://{addr}/v1/page-contexts"))
                .header(
                    "Authorization",
                    format!("Bearer {}", scoped_pane.grant.token),
                )
                .header("Origin", "https://codex.example")
                .call()
                .unwrap()
                .body_mut()
                .read_json()
                .unwrap();
        assert_eq!(contexts_from_allowed_origin.len(), 1);
        assert!(ureq::Agent::new_with_defaults()
            .get(format!("http://{addr}/v1/page-contexts"))
            .header(
                "Authorization",
                format!("Bearer {}", scoped_pane.grant.token),
            )
            .call()
            .is_err());
        assert!(ureq::Agent::new_with_defaults()
            .get(format!("http://{addr}/v1/page-contexts"))
            .header(
                "Authorization",
                format!("Bearer {}", scoped_pane.grant.token),
            )
            .header("Origin", "https://evil.example")
            .call()
            .is_err());

        let waiting_browser_tab = browser_tab.clone();
        let owner_ref_handle = thread::spawn(move || {
            waiting_browser_tab
                .wait_for_next_element_reference(Duration::from_secs(2))
                .unwrap()
        });
        thread::sleep(Duration::from_millis(50));
        let reference = client
            .record_element_reference(&ElementReferenceInput {
                tab_id: tab.id.clone(),
                url: "https://example.com/login".to_string(),
                selector: "button[type=\"submit\"]".to_string(),
                label: Some("Sign in".to_string()),
                role: Some("button".to_string()),
                text: Some("Sign in".to_string()),
                bounds: Some(ElementBounds {
                    x: 1.0,
                    y: 2.0,
                    width: 3.0,
                    height: 4.0,
                }),
            })
            .unwrap();
        assert_eq!(owner_ref_handle.join().unwrap().id, reference.id);
        let select_reference = client
            .record_element_reference(&ElementReferenceInput {
                tab_id: tab.id.clone(),
                url: "https://example.com/login".to_string(),
                selector: "select[name=\"timezone\"]".to_string(),
                label: Some("Timezone".to_string()),
                role: Some("combobox".to_string()),
                text: None,
                bounds: None,
            })
            .unwrap();
        let checkbox_reference = client
            .record_element_reference(&ElementReferenceInput {
                tab_id: tab.id.clone(),
                url: "https://example.com/login".to_string(),
                selector: "input[name=\"email_updates\"]".to_string(),
                label: Some("Email updates".to_string()),
                role: Some("checkbox".to_string()),
                text: None,
                bounds: None,
            })
            .unwrap();
        let drop_reference = client
            .record_element_reference(&ElementReferenceInput {
                tab_id: tab.id.clone(),
                url: "https://example.com/login".to_string(),
                selector: "[data-drop-target=\"done\"]".to_string(),
                label: Some("Done".to_string()),
                role: Some("list".to_string()),
                text: Some("Done".to_string()),
                bounds: None,
            })
            .unwrap();
        assert_eq!(client.list_element_references().unwrap().len(), 4);
        assert_eq!(agent_client.list_element_references().unwrap().len(), 4);
        assert_eq!(scoped_pane.list_element_references().unwrap().len(), 4);
        assert_eq!(browser_tab.list_element_references().unwrap().len(), 4);
        let command = scoped_pane.click_ref(&reference.id).unwrap();
        assert!(serde_json::to_string(&command)
            .unwrap()
            .contains("button[type=\\\"submit\\\"]"));
        let double_clicked = scoped_pane.double_click("[data-card=\"todo-1\"]").unwrap();
        assert!(serde_json::to_string(&double_clicked)
            .unwrap()
            .contains("double_click"));
        let double_clicked_ref = scoped_pane.double_click_ref(&reference.id).unwrap();
        assert!(serde_json::to_string(&double_clicked_ref)
            .unwrap()
            .contains("button[type=\\\"submit\\\"]"));
        let dragged = scoped_pane
            .drag_to("[data-card=\"todo-1\"]", "[data-drop-target=\"done\"]")
            .unwrap();
        assert!(serde_json::to_string(&dragged).unwrap().contains("drag_to"));
        let dragged_ref = scoped_pane
            .drag_ref_to_ref(&reference.id, &drop_reference.id)
            .unwrap();
        assert!(serde_json::to_string(&dragged_ref)
            .unwrap()
            .contains("[data-drop-target=\\\"done\\\"]"));
        let hovered = scoped_pane.hover("button[data-menu=\"account\"]").unwrap();
        assert!(serde_json::to_string(&hovered).unwrap().contains("hover"));
        let hovered_ref = scoped_pane.hover_ref(&reference.id).unwrap();
        assert!(serde_json::to_string(&hovered_ref)
            .unwrap()
            .contains("button[type=\\\"submit\\\"]"));
        let focused = scoped_pane.focus("input[name=\"email\"]").unwrap();
        assert!(serde_json::to_string(&focused).unwrap().contains("focus"));
        let focused_ref = scoped_pane.focus_ref(&reference.id).unwrap();
        assert!(serde_json::to_string(&focused_ref)
            .unwrap()
            .contains("button[type=\\\"submit\\\"]"));
        let typed = scoped_pane
            .type_text("input[name=\"email\"]", "me@example.com", true)
            .unwrap();
        assert!(serde_json::to_string(&typed).unwrap().contains("type_text"));
        let typed_ref = scoped_pane
            .type_text_ref(&reference.id, "typed by ref", false)
            .unwrap();
        assert!(serde_json::to_string(&typed_ref)
            .unwrap()
            .contains("typed by ref"));
        let selected = scoped_pane
            .select_option("select[name=\"timezone\"]", "UTC")
            .unwrap();
        assert!(serde_json::to_string(&selected)
            .unwrap()
            .contains("select_option"));
        let selected_ref = scoped_pane
            .select_option_ref(&select_reference.id, "UTC")
            .unwrap();
        assert!(serde_json::to_string(&selected_ref)
            .unwrap()
            .contains("select[name=\\\"timezone\\\"]"));
        let checked = scoped_pane
            .set_checked("input[name=\"email_updates\"]", true)
            .unwrap();
        assert!(serde_json::to_string(&checked)
            .unwrap()
            .contains("set_checked"));
        let checked_ref = scoped_pane
            .set_checked_ref(&checkbox_reference.id, true)
            .unwrap();
        assert!(serde_json::to_string(&checked_ref)
            .unwrap()
            .contains("input[name=\\\"email_updates\\\"]"));
        let scrolled = scoped_pane.scroll_by(0, 600).unwrap();
        assert!(serde_json::to_string(&scrolled)
            .unwrap()
            .contains("scroll_by"));
        let scrolled_into_view = scoped_pane.scroll_into_view("main").unwrap();
        assert!(serde_json::to_string(&scrolled_into_view)
            .unwrap()
            .contains("scroll_into_view"));
        let scrolled_ref = scoped_pane.scroll_ref_into_view(&reference.id).unwrap();
        assert!(serde_json::to_string(&scrolled_ref)
            .unwrap()
            .contains("button[type=\\\"submit\\\"]"));
        let pressed = scoped_pane.press_key("Enter").unwrap();
        assert!(serde_json::to_string(&pressed)
            .unwrap()
            .contains("press_key"));
        let submitted = scoped_pane.submit("form").unwrap();
        assert!(serde_json::to_string(&submitted)
            .unwrap()
            .contains("submit"));
        let submitted_ref = scoped_pane.submit_ref(&reference.id).unwrap();
        assert!(serde_json::to_string(&submitted_ref)
            .unwrap()
            .contains("button[type=\\\"submit\\\"]"));
        let waited = scoped_pane
            .wait_for_selector("main", Some(Duration::from_millis(250)))
            .unwrap();
        assert!(serde_json::to_string(&waited)
            .unwrap()
            .contains("wait_for_selector"));
        let picker = scoped_pane.start_element_picker().unwrap();
        assert!(serde_json::to_string(&picker)
            .unwrap()
            .contains("start_element_picker"));
        plane.poll_commands(Some(&tab.id)).unwrap();
        let pick_pane = scoped_pane.clone();
        let pick_tab_id = tab.id.clone();
        let pick_handle =
            thread::spawn(move || pick_pane.pick_element(Duration::from_secs(2)).unwrap());
        let picker_deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let commands = plane.poll_commands(Some(&pick_tab_id)).unwrap();
            if commands.iter().any(|command| {
                matches!(
                    command.kind,
                    BrowserCommandKind::AgentAction {
                        action: AgentAction::StartElementPicker,
                        ..
                    }
                )
            }) {
                break;
            }
            assert!(
                Instant::now() < picker_deadline,
                "picker command was not queued"
            );
            thread::sleep(Duration::from_millis(10));
        }
        let picked_reference = client
            .record_element_reference(&ElementReferenceInput {
                tab_id: tab.id.clone(),
                url: "https://example.com/login".to_string(),
                selector: "input[name=\"email\"]".to_string(),
                label: Some("Email".to_string()),
                role: Some("textbox".to_string()),
                text: None,
                bounds: Some(ElementBounds {
                    x: 5.0,
                    y: 6.0,
                    width: 120.0,
                    height: 24.0,
                }),
            })
            .unwrap();
        let picked = pick_handle.join().unwrap();
        assert_eq!(picked.id, picked_reference.id);
        let wait_ref_id = reference.id.clone();
        let wait_pane = scoped_pane.clone();
        let wait_tab_id = tab.id.clone();
        let wait_handle = thread::spawn(move || {
            wait_pane
                .click_ref_and_wait(&wait_ref_id, Duration::from_secs(2))
                .unwrap()
        });
        let click_deadline = Instant::now() + Duration::from_secs(1);
        let wait_command_id = loop {
            let commands = plane.poll_commands(Some(&wait_tab_id)).unwrap();
            if let Some(command) = commands.into_iter().find(|command| {
                matches!(
                    command.kind,
                    BrowserCommandKind::AgentAction {
                        action: AgentAction::Click { .. },
                        ..
                    }
                )
            }) {
                break command.id;
            }
            assert!(
                Instant::now() < click_deadline,
                "click-and-wait command was not queued"
            );
            thread::sleep(Duration::from_millis(10));
        };
        plane
            .record_command_result(
                &wait_command_id,
                &tab.id,
                CommandExecutionStatus::Succeeded,
                Some(r#"{"ok":true,"action":"click_and_wait"}"#.to_string()),
            )
            .unwrap();
        let waited_click = wait_handle.join().unwrap();
        assert_eq!(waited_click.command_id, wait_command_id);
        assert_eq!(waited_click.status, CommandExecutionStatus::Succeeded);
        let pane_fill = scoped_pane.fill_login(&credential.id).unwrap();
        let pane_fill_json = serde_json::to_string(&pane_fill).unwrap();
        assert!(pane_fill_json.contains("me"));
        assert!(!pane_fill_json.contains("secret"));
        plane
            .record_command_result(
                &command.id,
                &tab.id,
                CommandExecutionStatus::Succeeded,
                Some(r#"{"ok":true,"action":"click"}"#.to_string()),
            )
            .unwrap();
        let result = scoped_pane
            .wait_for_command_result(&command.id, std::time::Duration::from_secs(1))
            .unwrap();
        assert_eq!(result.status, CommandExecutionStatus::Succeeded);
        assert!(scoped_pane
            .list_command_results()
            .unwrap()
            .iter()
            .any(|result| result.command_id == command.id));
        assert_eq!(
            scoped_pane
                .command_result(&command.id)
                .unwrap()
                .unwrap()
                .command_id,
            command.id
        );

        let extract = scoped_pane.extract_text("main").unwrap();
        assert!(serde_json::to_string(&extract)
            .unwrap()
            .contains("extract_text"));
        let extract_ref = scoped_pane.extract_text_ref(&reference.id).unwrap();
        assert!(serde_json::to_string(&extract_ref)
            .unwrap()
            .contains("extract_text"));
        let extract_result_pane = scoped_pane.clone();
        let extract_result_tab_id = tab.id.clone();
        let ignored_extract_ids = [extract.id.clone(), extract_ref.id.clone()];
        let extract_result_handle = thread::spawn(move || {
            extract_result_pane
                .extract_text_result("main", Duration::from_secs(2))
                .unwrap()
        });
        let extract_result_deadline = Instant::now() + Duration::from_secs(1);
        let extract_result_command_id = loop {
            let commands = plane.poll_commands(Some(&extract_result_tab_id)).unwrap();
            if let Some(command) = commands.into_iter().find(|command| {
                !ignored_extract_ids.iter().any(|id| id == &command.id)
                    && matches!(
                        command.kind,
                        BrowserCommandKind::AgentAction {
                            action: AgentAction::ExtractText { .. },
                            ..
                        }
                    )
            }) {
                break command.id;
            }
            assert!(
                Instant::now() < extract_result_deadline,
                "extract-text-result command was not queued"
            );
            thread::sleep(Duration::from_millis(10));
        };
        plane
            .record_command_result(
                &extract_result_command_id,
                &tab.id,
                CommandExecutionStatus::Succeeded,
                Some(
                    r#"{"ok":true,"action":"extract_text","selector":"main","text":"Hello from Telescope"}"#
                        .to_string(),
                ),
            )
            .unwrap();
        let extracted = extract_result_handle.join().unwrap();
        assert_eq!(extracted.selector, "main");
        assert_eq!(extracted.text, "Hello from Telescope");
        let inspected = scoped_pane
            .inspect_element("button[type=\"submit\"]")
            .unwrap();
        assert!(serde_json::to_string(&inspected)
            .unwrap()
            .contains("inspect_element"));
        let inspected_ref = scoped_pane.inspect_element_ref(&reference.id).unwrap();
        assert!(serde_json::to_string(&inspected_ref)
            .unwrap()
            .contains("button[type=\\\"submit\\\"]"));
        let detail_pane = scoped_pane.clone();
        let detail_tab_id = tab.id.clone();
        let ignored_inspect_ids = [inspected.id.clone(), inspected_ref.id.clone()];
        let detail_handle = thread::spawn(move || {
            detail_pane
                .inspect_element_details("button[type=\"submit\"]", Duration::from_secs(2))
                .unwrap()
        });
        let detail_deadline = Instant::now() + Duration::from_secs(1);
        let detail_command_id = loop {
            let commands = plane.poll_commands(Some(&detail_tab_id)).unwrap();
            if let Some(command) = commands.into_iter().find(|command| {
                !ignored_inspect_ids.iter().any(|id| id == &command.id)
                    && matches!(
                        command.kind,
                        BrowserCommandKind::AgentAction {
                            action: AgentAction::InspectElement { .. },
                            ..
                        }
                    )
            }) {
                break command.id;
            }
            assert!(
                Instant::now() < detail_deadline,
                "inspect-element-details command was not queued"
            );
            thread::sleep(Duration::from_millis(10));
        };
        plane
            .record_command_result(
                &detail_command_id,
                &tab.id,
                CommandExecutionStatus::Succeeded,
                Some(
                    r#"{"ok":true,"action":"inspect_element","selector":"button[type=\"submit\"]","tagName":"button","id":"submit","className":"primary","role":"button","label":"Sign in","text":"Sign in","inputType":null,"disabled":false,"checked":null,"selected":null,"editable":false,"bounds":{"x":1.0,"y":2.0,"width":3.0,"height":4.0}}"#
                        .to_string(),
                ),
            )
            .unwrap();
        let details = detail_handle.join().unwrap();
        assert_eq!(details.selector, "button[type=\"submit\"]");
        assert_eq!(details.tag_name, "button");
        assert_eq!(details.id.as_deref(), Some("submit"));
        assert_eq!(details.bounds.height, 4.0);

        let read_only_pane = browser_tab
            .open_read_only_codex_pane("https://codex.example/login", PanePosition::Right, Some(60))
            .unwrap();
        assert_ne!(
            read_only_pane.connection.session_id,
            scoped_pane.connection.session_id
        );
        assert!(!read_only_pane.connection.session_policy.allow_credentials);
        assert!(!read_only_pane.connection.session_policy.allow_interactions);
        assert!(!read_only_pane.connection.session_policy.allow_scripts);
        assert!(read_only_pane
            .navigate("https://example.com/read-only")
            .is_err());
        assert!(read_only_pane.click("button").is_err());
        assert!(read_only_pane.double_click("button").is_err());
        assert!(read_only_pane.drag_to("#source", "#target").is_err());
        assert!(read_only_pane.hover("button").is_err());
        assert!(read_only_pane.focus("input").is_err());
        assert!(read_only_pane.select_option("select", "UTC").is_err());
        assert!(read_only_pane
            .set_checked("input[type=checkbox]", true)
            .is_err());
        assert!(read_only_pane.scroll_by(0, 600).is_err());
        assert!(read_only_pane.scroll_into_view("main").is_err());
        assert!(read_only_pane.submit("form").is_err());
        assert!(read_only_pane.login_options().is_err());
        assert!(read_only_pane.fill_login(&credential.id).is_err());
        let read_only_extract = read_only_pane.extract_text("main").unwrap();
        assert!(serde_json::to_string(&read_only_extract)
            .unwrap()
            .contains("extract_text"));
        let read_only_inspect = read_only_pane.inspect_element("button").unwrap();
        assert!(serde_json::to_string(&read_only_inspect)
            .unwrap()
            .contains("inspect_element"));
        read_only_pane.close().unwrap();

        let closed = scoped_pane.close().unwrap();
        assert_eq!(closed.id, scoped_pane.pane.id);
        assert_eq!(client.list_agent_panes().unwrap().len(), 0);
        assert!(client.agent_pane_connection(&scoped_pane.pane.id).is_err());

        let revoked = client.revoke_agent_grant(&scoped_pane.grant.token).unwrap();
        assert_eq!(revoked.token, scoped_pane.grant.token);
        assert!(revoked.closed_pane_ids.is_empty());
        assert!(scoped_pane.agent.list_page_contexts().is_err());

        let active_scoped_pane = client
            .open_scoped_agent_pane_for_active_tab(
                "https://codex-active.example/login",
                PanePosition::Bottom,
                Some(60),
            )
            .unwrap();
        assert_eq!(active_scoped_pane.pane.position, PanePosition::Bottom);
        assert_eq!(active_scoped_pane.connection.tab_id, tab.id);
        assert_eq!(
            active_scoped_pane.grant.allowed_client_origins[0].display_url(),
            "https://codex-active.example"
        );
        assert_eq!(
            active_scoped_pane.agent.list_page_contexts().unwrap().len(),
            1
        );
        assert_eq!(client.list_agent_panes().unwrap().len(), 1);
        let stopped_active = client.stop_scoped_agent_pane(&active_scoped_pane).unwrap();
        match stopped_active {
            StoppedAgentPane::RevokedGrant(revoked) => {
                assert_eq!(revoked.token, active_scoped_pane.grant.token);
                assert_eq!(
                    revoked.closed_pane_ids,
                    vec![active_scoped_pane.pane.id.clone()]
                );
            }
            other => panic!("unexpected stopped pane result: {other:?}"),
        }
        assert_eq!(client.list_agent_panes().unwrap().len(), 0);
        assert!(active_scoped_pane.agent.list_page_contexts().is_err());

        let unscoped_pane = client
            .open_agent_pane(
                "https://codex-unscoped.example/login",
                PanePosition::Right,
                None,
                None,
            )
            .unwrap();
        let stopped_unscoped = client.stop_agent_pane(&unscoped_pane.id).unwrap();
        match stopped_unscoped {
            StoppedAgentPane::ClosedPane(pane) => assert_eq!(pane.id, unscoped_pane.id),
            other => panic!("unexpected stopped pane result: {other:?}"),
        }
        assert_eq!(client.list_agent_panes().unwrap().len(), 0);

        let script_only_pane = client
            .open_codex_pane_for_active_tab_with_options(
                ScopedAgentPaneOptions::interactive(
                    "https://codex-script.example/login",
                    PanePosition::Right,
                )
                .with_credentials(false)
                .with_interactions(false)
                .with_scripts(true)
                .with_ttl_seconds(60),
            )
            .unwrap();
        assert_eq!(script_only_pane.connection.tab_id, tab.id);
        assert!(!script_only_pane.connection.session_policy.allow_credentials);
        assert!(
            !script_only_pane
                .connection
                .session_policy
                .allow_interactions
        );
        assert!(script_only_pane.connection.session_policy.allow_scripts);
        assert!(script_only_pane.click("button").is_err());
        assert!(script_only_pane.login_options().is_err());
        let script_command = script_only_pane.execute_script("document.title").unwrap();
        assert!(serde_json::to_string(&script_command)
            .unwrap()
            .contains("execute_script"));
        script_only_pane.close().unwrap();
        client
            .revoke_agent_grant(&script_only_pane.grant.token)
            .unwrap();

        let session_revoke_pane = client
            .open_codex_pane_for_active_tab(
                "https://codex-revoke.example/login",
                PanePosition::Right,
                Some(60),
            )
            .unwrap();
        let session_to_revoke = session_revoke_pane.connection.session_id.clone();
        assert!(client
            .list_sessions()
            .unwrap()
            .iter()
            .any(|item| item.id == session_to_revoke));
        let pending_command = session_revoke_pane.extract_text("main").unwrap();
        let revoked_session = client.revoke_session(&session_to_revoke).unwrap();
        assert_eq!(revoked_session.session_id, session_to_revoke);
        assert_eq!(revoked_session.revoked_grant_count, 1);
        assert_eq!(
            revoked_session.closed_pane_ids,
            vec![session_revoke_pane.pane.id.clone()]
        );
        assert!(revoked_session
            .detached_tab_ids
            .iter()
            .any(|item| item == &tab.id));
        assert!(revoked_session
            .purged_command_ids
            .iter()
            .any(|item| item == &pending_command.id));
        assert!(!client
            .list_sessions()
            .unwrap()
            .iter()
            .any(|item| item.id == revoked_session.session_id));
        assert_eq!(client.list_agent_panes().unwrap().len(), 0);
        assert!(session_revoke_pane.agent.list_page_contexts().is_err());
        assert_eq!(
            client.active_tab().unwrap().unwrap().session_id.as_deref(),
            None
        );
        assert_eq!(
            client.delete_bookmark(&bookmark.id).unwrap().id,
            bookmark.id
        );
        assert_eq!(
            client.delete_bookmark(&docs_bookmark.id).unwrap().id,
            docs_bookmark.id
        );
        assert!(client.list_bookmarks().unwrap().is_empty());

        client.close_tab(login_tab.id()).unwrap();
        client.close_tab(docs_tab.id()).unwrap();
        let closed_tab = client.close_tab(&tab.id).unwrap();
        assert_eq!(closed_tab.id, tab.id);
        assert!(client.list_tabs().unwrap().is_empty());
    }

    #[test]
    fn sdk_restore_handoff_plan_uses_tabs_with_urls_and_preserves_active_tab() {
        let snapshot = HandoffSnapshot {
            generated_at_unix: 1,
            active_tab: Some(tab_state("tab-2", Some("https://two.example"))),
            tabs: vec![
                tab_state("tab-1", Some("https://one.example")),
                tab_state("tab-blank", None),
                tab_state("tab-2", Some("https://two.example")),
            ],
            sessions: Vec::new(),
            bookmarks: Vec::new(),
            agent_panes: Vec::new(),
            page_contexts: Vec::new(),
            element_refs: Vec::new(),
            command_results: Vec::new(),
            audit_events: Vec::new(),
        };

        let (plan, skipped) = handoff_restore_tab_plan(&snapshot);

        assert_eq!(skipped, 1);
        assert_eq!(
            plan,
            vec![
                HandoffRestoreTabPlan {
                    source_tab_id: "tab-1".to_string(),
                    url: "https://one.example".to_string(),
                    active: false,
                },
                HandoffRestoreTabPlan {
                    source_tab_id: "tab-2".to_string(),
                    url: "https://two.example".to_string(),
                    active: true,
                }
            ]
        );
    }

    #[test]
    fn sdk_restore_handoff_plan_falls_back_to_active_tab_not_in_tab_list() {
        let snapshot = HandoffSnapshot {
            generated_at_unix: 1,
            active_tab: Some(tab_state("active", Some("https://active.example"))),
            tabs: Vec::new(),
            sessions: Vec::new(),
            bookmarks: Vec::new(),
            agent_panes: Vec::new(),
            page_contexts: Vec::new(),
            element_refs: Vec::new(),
            command_results: Vec::new(),
            audit_events: Vec::new(),
        };

        let (plan, skipped) = handoff_restore_tab_plan(&snapshot);

        assert_eq!(skipped, 0);
        assert_eq!(
            plan,
            vec![HandoffRestoreTabPlan {
                source_tab_id: "active".to_string(),
                url: "https://active.example".to_string(),
                active: true,
            }]
        );
    }

    #[test]
    fn sdk_restores_handoff_snapshot_tabs_and_bookmarks() {
        let plane = ControlPlane::new(CredentialVault::ephemeral(
            "sdk-handoff-restore-test",
            Arc::new(MemorySecretStore::new()),
        ));
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let addr = server.server_addr().to_ip().unwrap();
        let token = "sdk-handoff-restore-token";
        let server_plane = plane.clone();
        thread::spawn(move || {
            let _ = serve_server(server, token.to_string(), server_plane);
        });
        let client = TelescopeClient::new(format!("http://{addr}"), token).unwrap();
        let snapshot = HandoffSnapshot {
            generated_at_unix: 1,
            active_tab: Some(tab_state("old-2", Some("https://two.example"))),
            tabs: vec![
                tab_state("old-1", Some("https://one.example")),
                tab_state("old-2", Some("https://two.example")),
                tab_state("old-empty", None),
            ],
            sessions: Vec::new(),
            bookmarks: vec![BookmarkRecord {
                id: "bookmark-1".to_string(),
                url: "https://docs.example".to_string(),
                title: Some("Docs".to_string()),
                created_at_unix: 1,
                updated_at_unix: 1,
            }],
            agent_panes: Vec::new(),
            page_contexts: Vec::new(),
            element_refs: Vec::new(),
            command_results: Vec::new(),
            audit_events: Vec::new(),
        };

        let report = client.restore_handoff_snapshot(&snapshot).unwrap();

        assert_eq!(report.opened_tabs.len(), 2);
        assert_eq!(report.skipped_tabs, 1);
        assert_eq!(report.imported_bookmarks.len(), 1);
        assert!(serde_json::to_string(&report)
            .unwrap()
            .contains("imported_bookmarks"));
        let tabs = client.list_tabs().unwrap();
        assert_eq!(tabs.len(), 2);
        assert!(tabs
            .iter()
            .any(|tab| tab.current_url.as_deref() == Some("https://one.example")));
        let active = client.active_tab().unwrap().unwrap();
        assert_eq!(active.current_url.as_deref(), Some("https://two.example"));
        let bookmarks = client.list_bookmarks().unwrap();
        assert_eq!(bookmarks.len(), 1);
        assert_eq!(bookmarks[0].url, "https://docs.example");
        assert_eq!(bookmarks[0].title.as_deref(), Some("Docs"));
    }

    #[test]
    fn client_loads_desktop_control_file() {
        let mut path = std::env::temp_dir();
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!("telescope-control-{nonce}.json"));
        std::fs::write(
            &path,
            r#"{"url":"http://127.0.0.1:47639","owner_token":"owner"}"#,
        )
        .unwrap();

        let client = TelescopeClient::from_control_file(&path).unwrap();
        assert_eq!(client.base_url, "http://127.0.0.1:47639");
        assert_eq!(client.bearer_token, "owner");
        let _ = std::fs::remove_file(path);
    }

    fn tab_state(id: &str, current_url: Option<&str>) -> TabState {
        TabState {
            id: id.to_string(),
            current_url: current_url.map(str::to_string),
            session_id: None,
            title: None,
            created_at_unix: 1,
            updated_at_unix: 1,
        }
    }
}
