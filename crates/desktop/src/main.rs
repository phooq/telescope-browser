#[cfg(feature = "control-server")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DesktopShortcut {
    FocusAddress,
    NewTab,
    CloseTab,
    Back,
    Forward,
    Reload,
}

#[cfg(feature = "control-server")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct DesktopShortcutModifiers {
    ctrl: bool,
    meta: bool,
    alt: bool,
    shift: bool,
}

#[cfg(feature = "control-server")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DesktopShortcutKey {
    L,
    R,
    T,
    W,
    F5,
    ArrowLeft,
    ArrowRight,
}

#[cfg(feature = "control-server")]
fn desktop_shortcut_for_key(
    modifiers: DesktopShortcutModifiers,
    key: DesktopShortcutKey,
) -> Option<DesktopShortcut> {
    let command = (modifiers.ctrl || modifiers.meta) && !modifiers.alt && !modifiers.shift;
    if command {
        return match key {
            DesktopShortcutKey::L => Some(DesktopShortcut::FocusAddress),
            DesktopShortcutKey::R => Some(DesktopShortcut::Reload),
            DesktopShortcutKey::T => Some(DesktopShortcut::NewTab),
            DesktopShortcutKey::W => Some(DesktopShortcut::CloseTab),
            _ => None,
        };
    }

    let alt_history = modifiers.alt && !modifiers.ctrl && !modifiers.meta && !modifiers.shift;
    if alt_history {
        return match key {
            DesktopShortcutKey::ArrowLeft => Some(DesktopShortcut::Back),
            DesktopShortcutKey::ArrowRight => Some(DesktopShortcut::Forward),
            _ => None,
        };
    }

    if !modifiers.ctrl && !modifiers.meta && !modifiers.alt {
        return match key {
            DesktopShortcutKey::F5 => Some(DesktopShortcut::Reload),
            _ => None,
        };
    }

    None
}

#[cfg(all(feature = "control-server", feature = "webview"))]
struct AssistantCliManager {
    sessions: std::collections::BTreeMap<String, AssistantCliSession>,
}

#[cfg(all(feature = "control-server", feature = "webview"))]
struct AssistantCliSession {
    command: String,
    output: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    writer: Option<Box<dyn std::io::Write + Send>>,
    child: Option<Box<dyn portable_pty::Child + Send + Sync>>,
    _master: Option<Box<dyn portable_pty::MasterPty + Send>>,
    pending_pick: Option<PendingCliElementPick>,
    selection: Option<AssistantCliSelection>,
}

#[cfg(all(feature = "control-server", feature = "webview"))]
struct PendingCliElementPick {
    tab_id: String,
    seen_ref_ids: std::collections::BTreeSet<String>,
}

#[cfg(all(feature = "control-server", feature = "webview"))]
#[derive(Clone, Debug)]
struct AssistantCliSelection {
    id: String,
    tab_id: String,
    url: String,
    selector: String,
    role: Option<String>,
    label: Option<String>,
    text: Option<String>,
    bounds: Option<telescope_control::ElementBounds>,
}

#[cfg(all(feature = "control-server", feature = "webview"))]
impl AssistantCliManager {
    fn new() -> Self {
        Self {
            sessions: std::collections::BTreeMap::new(),
        }
    }

    fn open_session(&mut self, command: &str) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let command = command.trim();
        let command = if command.is_empty() { "codex" } else { command }.to_string();
        let output = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        push_terminal_output(&output, &format!("$ {command}\r\n"));

        let (writer, child, master) = match spawn_assistant_cli_process(&command, output.clone()) {
            Ok(parts) => parts,
            Err(error) => {
                push_terminal_output(
                    &output,
                    &format!(
                        "Failed to start `{command}`: {error}\r\nSet a different command in the CLI field, such as `claude`.\r\n"
                    ),
                );
                (None, None, None)
            }
        };

        self.sessions.insert(
            id.clone(),
            AssistantCliSession {
                command,
                output,
                writer,
                child,
                _master: master,
                pending_pick: None,
                selection: None,
            },
        );
        id
    }

    fn close_session(&mut self, pane_id: &str) {
        if let Some(mut session) = self.sessions.remove(pane_id) {
            if let Some(child) = session.child.as_mut() {
                let _ = child.kill();
            }
        }
    }

    fn send_input(&mut self, pane_id: &str, text: &str) -> Result<(), String> {
        let session = self
            .sessions
            .get_mut(pane_id)
            .ok_or_else(|| format!("CLI pane `{pane_id}` is not open"))?;
        let writer = session
            .writer
            .as_mut()
            .ok_or_else(|| format!("CLI command `{}` is not running", session.command))?;
        writer
            .write_all(text.as_bytes())
            .and_then(|()| writer.flush())
            .map_err(|error| error.to_string())
    }

    fn note(&mut self, pane_id: &str, message: &str) {
        if let Some(session) = self.sessions.get(pane_id) {
            push_terminal_output(&session.output, message);
        }
    }

    fn start_pick(
        &mut self,
        pane_id: &str,
        tab_id: String,
        seen_ref_ids: std::collections::BTreeSet<String>,
    ) -> Result<(), String> {
        let session = self
            .sessions
            .get_mut(pane_id)
            .ok_or_else(|| format!("CLI pane `{pane_id}` is not open"))?;
        session.pending_pick = Some(PendingCliElementPick {
            tab_id,
            seen_ref_ids,
        });
        push_terminal_output(
            &session.output,
            "\r\n[Telescope] Click an element in the page, then use Add selection.\r\n",
        );
        Ok(())
    }

    fn observe_element_references(&mut self, refs: &[telescope_control::ElementReference]) {
        for session in self.sessions.values_mut() {
            let Some(pending) = &session.pending_pick else {
                continue;
            };
            let selected = refs
                .iter()
                .filter(|reference| {
                    reference.tab_id == pending.tab_id
                        && !pending.seen_ref_ids.contains(&reference.id)
                })
                .max_by(|left, right| {
                    left.created_at_unix
                        .cmp(&right.created_at_unix)
                        .then_with(|| left.id.cmp(&right.id))
                })
                .cloned();
            let Some(reference) = selected else {
                continue;
            };
            let selection = AssistantCliSelection::from(reference);
            let summary = selection.summary();
            session.selection = Some(selection);
            session.pending_pick = None;
            push_terminal_output(
                &session.output,
                &format!("[Telescope] Selected {summary}. Click Add selection to send it into the CLI.\r\n"),
            );
        }
    }

    fn add_selection_to_chat(&mut self, pane_id: &str) -> Result<(), String> {
        let prompt = self
            .sessions
            .get(pane_id)
            .and_then(|session| session.selection.as_ref())
            .ok_or_else(|| "no selected element for this CLI pane".to_string())?
            .prompt();
        self.send_input(pane_id, &format!("{prompt}\r"))
    }

    fn add_page_context_to_chat(
        &mut self,
        pane_id: &str,
        context: Option<telescope_control::PageContextSnapshot>,
    ) -> Result<(), String> {
        let context = context.ok_or_else(|| "no page context captured yet".to_string())?;
        let mut prompt = format!(
            "Telescope page context:\nURL: {}\nTitle: {}\nText preview: {}\n",
            context.url,
            context.title.unwrap_or_default(),
            context.text_preview.unwrap_or_default()
        );
        if !context.interactive_elements.is_empty() {
            prompt.push_str("Visible interactive elements:\n");
            for element in context.interactive_elements.iter().take(12) {
                prompt.push_str(&format!(
                    "- selector: {}; role: {}; label: {}; text: {}\n",
                    element.selector,
                    element.role.clone().unwrap_or_default(),
                    element.label.clone().unwrap_or_default(),
                    element.text.clone().unwrap_or_default()
                ));
            }
        }
        self.send_input(pane_id, &format!("{prompt}\r"))
    }

    fn drain_output(&mut self, pane_id: &str) -> String {
        let Some(session) = self.sessions.get(pane_id) else {
            return String::new();
        };
        let Ok(mut chunks) = session.output.lock() else {
            return String::new();
        };
        if chunks.is_empty() {
            return String::new();
        }
        let output = chunks.concat();
        chunks.clear();
        output
    }

    fn state_json(&self, pane_id: &str) -> serde_json::Value {
        let Some(session) = self.sessions.get(pane_id) else {
            return serde_json::json!({
                "pane_id": pane_id,
                "running": false,
                "pending_pick": false,
                "selection": null,
            });
        };
        serde_json::json!({
            "pane_id": pane_id,
            "command": session.command,
            "running": session.writer.is_some(),
            "pending_pick": session.pending_pick.is_some(),
            "selection": session.selection.as_ref().map(AssistantCliSelection::json),
        })
    }
}

#[cfg(all(feature = "control-server", feature = "webview"))]
impl From<telescope_control::ElementReference> for AssistantCliSelection {
    fn from(reference: telescope_control::ElementReference) -> Self {
        Self {
            id: reference.id,
            tab_id: reference.tab_id,
            url: reference.url,
            selector: reference.selector,
            role: reference.role,
            label: reference.label,
            text: reference.text,
            bounds: reference.bounds,
        }
    }
}

#[cfg(all(feature = "control-server", feature = "webview"))]
impl AssistantCliSelection {
    fn summary(&self) -> String {
        self.label
            .clone()
            .or_else(|| self.text.clone())
            .or_else(|| self.role.clone())
            .unwrap_or_else(|| self.selector.clone())
    }

    fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "tab_id": self.tab_id,
            "url": self.url,
            "selector": self.selector,
            "role": self.role,
            "label": self.label,
            "text": self.text,
            "bounds": self.bounds,
            "summary": self.summary(),
        })
    }

    fn prompt(&self) -> String {
        let bounds = self
            .bounds
            .as_ref()
            .map(|bounds| {
                format!(
                    "x={}, y={}, width={}, height={}",
                    bounds.x, bounds.y, bounds.width, bounds.height
                )
            })
            .unwrap_or_default();
        format!(
            "Telescope selected this page element.\nURL: {}\nTab ID: {}\nElement ref ID: {}\nSelector: {}\nRole: {}\nLabel: {}\nText: {}\nBounds: {}\nWhen I say \"this element\", use the selector and element_ref_id above.",
            self.url,
            self.tab_id,
            self.id,
            self.selector,
            self.role.clone().unwrap_or_default(),
            self.label.clone().unwrap_or_default(),
            self.text.clone().unwrap_or_default(),
            bounds
        )
    }
}

#[cfg(all(feature = "control-server", feature = "webview"))]
fn spawn_assistant_cli_process(
    command: &str,
    output: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
) -> Result<
    (
        Option<Box<dyn std::io::Write + Send>>,
        Option<Box<dyn portable_pty::Child + Send + Sync>>,
        Option<Box<dyn portable_pty::MasterPty + Send>>,
    ),
    String,
> {
    let pty_system = portable_pty::native_pty_system();
    let pair = pty_system
        .openpty(portable_pty::PtySize {
            rows: 32,
            cols: 120,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|error| error.to_string())?;
    let mut builder = assistant_cli_command_builder(command);
    builder.env("TERM", "xterm-256color");
    let child = pair
        .slave
        .spawn_command(builder)
        .map_err(|error| error.to_string())?;
    let reader = pair
        .master
        .try_clone_reader()
        .map_err(|error| error.to_string())?;
    let writer = pair
        .master
        .take_writer()
        .map_err(|error| error.to_string())?;
    spawn_terminal_reader(reader, output);
    Ok((Some(writer), Some(child), Some(pair.master)))
}

#[cfg(all(feature = "control-server", feature = "webview"))]
fn assistant_cli_command_builder(command: &str) -> portable_pty::CommandBuilder {
    #[cfg(windows)]
    {
        let mut builder = portable_pty::CommandBuilder::new("cmd.exe");
        builder.args(["/C", command]);
        builder
    }

    #[cfg(not(windows))]
    {
        let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
        let mut builder = portable_pty::CommandBuilder::new(shell);
        builder.args(["-lc", command]);
        builder
    }
}

#[cfg(all(feature = "control-server", feature = "webview"))]
fn spawn_terminal_reader(
    mut reader: Box<dyn std::io::Read + Send>,
    output: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
) {
    std::thread::spawn(move || {
        let mut buffer = [0_u8; 8192];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => {
                    let chunk = String::from_utf8_lossy(&buffer[..count]).to_string();
                    push_terminal_output(&output, &chunk);
                }
                Err(error) => {
                    push_terminal_output(&output, &format!("\r\n[read error: {error}]\r\n"));
                    break;
                }
            }
        }
        push_terminal_output(&output, "\r\n[process ended]\r\n");
    });
}

#[cfg(all(feature = "control-server", feature = "webview"))]
fn push_terminal_output(output: &std::sync::Arc<std::sync::Mutex<Vec<String>>>, text: &str) {
    if let Ok(mut chunks) = output.lock() {
        chunks.push(text.to_string());
    }
}

#[cfg(feature = "webview")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::collections::BTreeSet;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use tao::event::{ElementState, Event, WindowEvent};
    use tao::event_loop::{ControlFlow, EventLoop};
    use tao::window::{Window, WindowBuilder};
    use telescope_control::{
        AgentAction, AgentActionRequest, AgentPaneConnection, AgentPaneState,
        CommandResultIpcRequest, ControlPlane, CreateSessionRequest, CreateTabRequest,
        ElementReferenceInput, NavigateRequest, OpenScopedAgentPaneRequest, PageContextRequest,
        PanePosition, StoreTabCredentialRequest, TabState,
    };
    use telescope_core::{CredentialVault, OsKeyringStore};
    use telescope_runtime::{
        page_context_script, BrowserActionSink, BrowserRuntime, Result as RuntimeResult,
    };
    use wry::{WebContext, WebView, WebViewBuilder};

    struct AgentPaneView {
        id: String,
        position: PanePosition,
        webview: WebView,
    }

    struct AssistantCliPaneView {
        id: String,
        position: PanePosition,
        webview: WebView,
    }

    #[derive(Clone)]
    struct PendingAssistantCliOpen {
        command: String,
        position: PanePosition,
    }

    struct BrowserTabView {
        id: String,
        webview: WebView,
    }

    struct WebViewSink<'a> {
        main_tab_id: &'a str,
        active_tab_id: &'a mut String,
        webview: &'a WebView,
        main_window: &'a Window,
        browser_context: &'a mut WebContext,
        agent_context: &'a mut WebContext,
        plane: &'a ControlPlane,
        control_endpoint: &'a str,
        workspace_host: &'a DesktopWorkspaceHost,
        browser_tabs: &'a mut Vec<BrowserTabView>,
        agent_panes: &'a mut Vec<AgentPaneView>,
        assistant_cli_panes: &'a [AssistantCliPaneView],
    }

    impl WebViewSink<'_> {
        fn webview_for_tab(&self, tab_id: &str) -> RuntimeResult<&WebView> {
            if tab_id == self.main_tab_id {
                return Ok(self.webview);
            }
            self.browser_tabs
                .iter()
                .find(|item| item.id == tab_id)
                .map(|item| &item.webview)
                .ok_or_else(|| {
                    telescope_runtime::RuntimeError::Adapter(format!(
                        "browser tab `{tab_id}` is not open"
                    ))
                })
        }
    }

    impl BrowserActionSink for WebViewSink<'_> {
        fn open_tab(&mut self, tab: &TabState) -> RuntimeResult<()> {
            if tab.id == self.main_tab_id {
                if let Some(url) = &tab.current_url {
                    self.navigate(&tab.id, url)?;
                }
                return self.activate_tab(&tab.id);
            }

            if let Some(existing) = self.browser_tabs.iter().find(|item| item.id == tab.id) {
                if let Some(url) = &tab.current_url {
                    existing
                        .webview
                        .evaluate_script(&format!(
                            "window.location.href = {};",
                            serde_json_string(url)
                        ))
                        .map_err(|err| telescope_runtime::RuntimeError::Adapter(err.to_string()))?;
                }
                return self.activate_tab(&tab.id);
            }

            let initial_bounds = browser_bounds_for_tabs(
                self.main_window,
                self.agent_panes,
                self.assistant_cli_panes,
            );
            let webview = build_browser_tab_webview(
                self.browser_context,
                self.plane,
                self.main_window,
                self.workspace_host,
                tab,
                initial_bounds,
            )?;

            self.browser_tabs.push(BrowserTabView {
                id: tab.id.clone(),
                webview,
            });
            self.activate_tab(&tab.id)
        }

        fn close_tab(&mut self, tab_id: &str) -> RuntimeResult<()> {
            let was_active = self.active_tab_id.as_str() == tab_id;
            if tab_id == self.main_tab_id {
                self.webview
                    .evaluate_script("window.location.href = 'about:blank';")
                    .map_err(|err| telescope_runtime::RuntimeError::Adapter(err.to_string()))?;
                set_webview_visible(self.webview, false)?;
            } else if let Some(index) = self.browser_tabs.iter().position(|item| item.id == tab_id)
            {
                self.browser_tabs.remove(index);
            }

            if was_active {
                *self.active_tab_id = self
                    .browser_tabs
                    .first()
                    .map(|tab| tab.id.clone())
                    .unwrap_or_else(|| self.main_tab_id.to_string());
                relayout_workspace(
                    self.main_window,
                    self.active_tab_id.as_str(),
                    self.main_tab_id,
                    self.webview,
                    self.browser_tabs,
                    self.agent_panes,
                    self.assistant_cli_panes,
                )?;
            }
            Ok(())
        }

        fn activate_tab(&mut self, tab_id: &str) -> RuntimeResult<()> {
            self.webview_for_tab(tab_id)?;
            *self.active_tab_id = tab_id.to_string();
            relayout_workspace(
                self.main_window,
                self.active_tab_id.as_str(),
                self.main_tab_id,
                self.webview,
                self.browser_tabs,
                self.agent_panes,
                self.assistant_cli_panes,
            )
        }

        fn navigate(&mut self, tab_id: &str, url: &str) -> RuntimeResult<()> {
            self.webview_for_tab(tab_id)?
                .evaluate_script(&format!(
                    "window.location.href = {};",
                    serde_json_string(url)
                ))
                .map_err(|err| telescope_runtime::RuntimeError::Adapter(err.to_string()))
        }

        fn go_back(&mut self, tab_id: &str) -> RuntimeResult<()> {
            self.webview_for_tab(tab_id)?
                .evaluate_script("window.history.back();")
                .map_err(|err| telescope_runtime::RuntimeError::Adapter(err.to_string()))
        }

        fn go_forward(&mut self, tab_id: &str) -> RuntimeResult<()> {
            self.webview_for_tab(tab_id)?
                .evaluate_script("window.history.forward();")
                .map_err(|err| telescope_runtime::RuntimeError::Adapter(err.to_string()))
        }

        fn reload(&mut self, tab_id: &str) -> RuntimeResult<()> {
            self.webview_for_tab(tab_id)?
                .evaluate_script("window.location.reload();")
                .map_err(|err| telescope_runtime::RuntimeError::Adapter(err.to_string()))
        }

        fn evaluate_script(&mut self, tab_id: &str, script: &str) -> RuntimeResult<()> {
            self.webview_for_tab(tab_id)?
                .evaluate_script(script)
                .map_err(|err| telescope_runtime::RuntimeError::Adapter(err.to_string()))
        }

        fn open_agent_pane(
            &mut self,
            pane: &AgentPaneState,
            connection: Option<&AgentPaneConnection>,
        ) -> RuntimeResult<()> {
            if let Some(index) = self.agent_panes.iter().position(|item| item.id == pane.id) {
                self.agent_panes[index].position = pane.position.clone();
                let result = self.agent_panes[index]
                    .webview
                    .evaluate_script(&format!(
                        "window.location.href = {};",
                        serde_json_string(&pane.url)
                    ))
                    .map_err(|err| telescope_runtime::RuntimeError::Adapter(err.to_string()));
                relayout_workspace(
                    self.main_window,
                    self.active_tab_id.as_str(),
                    self.main_tab_id,
                    self.webview,
                    self.browser_tabs,
                    self.agent_panes,
                    self.assistant_cli_panes,
                )?;
                return result;
            }

            let initial_bounds = layout_for_new_pane(
                self.main_window,
                self.agent_panes,
                self.assistant_cli_panes,
                pane,
            )
            .pane_bounds(&pane.id)
            .unwrap_or_else(|| workspace_surface(self.main_window.inner_size()).into());
            let builder = WebViewBuilder::new_with_web_context(self.agent_context)
                .with_user_agent("Telescope/0.1")
                .with_initialization_script(agent_connection_script(
                    self.control_endpoint,
                    pane,
                    connection,
                )?)
                .with_url(&pane.url)
                .with_general_autofill_enabled(true);
            let webview = build_workspace_webview(
                builder,
                self.main_window,
                self.workspace_host,
                initial_bounds,
            )
            .map_err(|err| telescope_runtime::RuntimeError::Adapter(err.to_string()))?;

            self.agent_panes.push(AgentPaneView {
                id: pane.id.clone(),
                position: pane.position.clone(),
                webview,
            });
            relayout_workspace(
                self.main_window,
                self.active_tab_id.as_str(),
                self.main_tab_id,
                self.webview,
                self.browser_tabs,
                self.agent_panes,
                self.assistant_cli_panes,
            )
        }

        fn close_agent_pane(&mut self, pane_id: &str) -> RuntimeResult<()> {
            if let Some(index) = self.agent_panes.iter().position(|item| item.id == pane_id) {
                self.agent_panes.remove(index);
                relayout_workspace(
                    self.main_window,
                    self.active_tab_id.as_str(),
                    self.main_tab_id,
                    self.webview,
                    self.browser_tabs,
                    self.agent_panes,
                    self.assistant_cli_panes,
                )?;
            }
            Ok(())
        }
    }

    let requested_url = std::env::args()
        .nth(1)
        .and_then(|url| normalize_chrome_url(&url));
    let profile = std::env::var("TELESCOPE_PROFILE").unwrap_or_else(|_| "default".to_string());
    let profile_dir = profile_dir(&profile)?;
    ensure_private_profile_dir(&profile_dir)?;

    let credential_index = profile_dir.join("credentials.json");
    let vault = CredentialVault::open(
        &profile,
        credential_index,
        Arc::new(OsKeyringStore::default()),
    )?;
    let plane = ControlPlane::with_profile_storage(
        vault,
        profile_dir.join("audit.jsonl"),
        profile_dir.join("bookmarks.json"),
    )?;
    let control_endpoint = start_control_server(&profile_dir, plane.clone())?;
    let startup_tabs =
        load_desktop_startup_tabs_with_home(&profile_dir, requested_url, default_home_url());
    let registered_tabs = register_desktop_startup_tabs(&plane, &startup_tabs)?;
    let tab = registered_tabs
        .first()
        .cloned()
        .ok_or("desktop startup did not create a browser tab")?;
    let restored_active_tab_id = startup_tabs
        .iter()
        .zip(registered_tabs.iter())
        .find_map(|(startup, tab)| startup.active.then(|| tab.id.clone()))
        .unwrap_or_else(|| tab.id.clone());
    let runtime = BrowserRuntime::new(plane.clone());

    let event_loop = EventLoop::new();
    let window = WindowBuilder::new()
        .with_title("Telescope")
        .build(&event_loop)?;
    let workspace_host = DesktopWorkspaceHost::new(&window)?;
    let mut browser_context = WebContext::new(Some(profile_dir.join("webview")));
    let mut agent_context = WebContext::new(Some(profile_dir.join("agent-webview")));
    let assistant_cli_manager = Arc::new(Mutex::new(AssistantCliManager::new()));
    let pending_assistant_cli_opens = Arc::new(Mutex::new(Vec::<PendingAssistantCliOpen>::new()));
    let pending_assistant_cli_closes = Arc::new(Mutex::new(Vec::<String>::new()));
    let plane_for_chrome_ipc = plane.clone();
    let pending_cli_opens_for_chrome = pending_assistant_cli_opens.clone();
    let chrome_builder = WebViewBuilder::new()
        .with_user_agent("Telescope/0.1")
        .with_ipc_handler(move |request| {
            handle_chrome_ipc_request(
                &plane_for_chrome_ipc,
                &pending_cli_opens_for_chrome,
                request.body(),
            );
        })
        .with_html(browser_chrome_html())
        .with_general_autofill_enabled(false);
    let chrome_webview = build_workspace_webview(
        chrome_builder,
        &window,
        &workspace_host,
        chrome_bounds_for_window(&window),
    )?;
    let webview = build_browser_tab_webview(
        &mut browser_context,
        &plane,
        &window,
        &workspace_host,
        &tab,
        workspace_surface(window.inner_size()).into(),
    )?;
    let mut active_tab_id = restored_active_tab_id;
    let mut last_context_capture = Instant::now() - Duration::from_secs(2);
    let mut last_tab_snapshot_json = None;
    let mut browser_tabs = Vec::new();
    let mut agent_panes = Vec::new();
    let mut assistant_cli_panes = Vec::new();
    let mut keyboard_modifiers = tao::keyboard::ModifiersState::empty();
    for restored_tab in registered_tabs.iter().skip(1) {
        let bounds = browser_bounds_for_tabs(&window, &agent_panes, &assistant_cli_panes);
        let webview = build_browser_tab_webview(
            &mut browser_context,
            &plane,
            &window,
            &workspace_host,
            restored_tab,
            bounds,
        )?;
        browser_tabs.push(BrowserTabView {
            id: restored_tab.id.clone(),
            webview,
        });
    }
    relayout_workspace(
        &window,
        &active_tab_id,
        &tab.id,
        &webview,
        &browser_tabs,
        &agent_panes,
        &assistant_cli_panes,
    )?;

    event_loop.run(move |event, _event_loop, control_flow| {
        *control_flow = ControlFlow::WaitUntil(Instant::now() + Duration::from_millis(100));
        match event {
            Event::MainEventsCleared => {
                let cli_closes = drain_pending_cli_closes(&pending_assistant_cli_closes);
                if !cli_closes.is_empty() {
                    if let Ok(mut manager) = assistant_cli_manager.lock() {
                        for pane_id in &cli_closes {
                            manager.close_session(pane_id);
                        }
                    }
                    assistant_cli_panes.retain(|pane| !cli_closes.iter().any(|id| id == &pane.id));
                    if let Err(error) = relayout_workspace(
                        &window,
                        &active_tab_id,
                        &tab.id,
                        &webview,
                        &browser_tabs,
                        &agent_panes,
                        &assistant_cli_panes,
                    ) {
                        eprintln!("telescope workspace layout error: {error}");
                    }
                }

                let mut sink = WebViewSink {
                    main_tab_id: &tab.id,
                    active_tab_id: &mut active_tab_id,
                    webview: &webview,
                    main_window: &window,
                    browser_context: &mut browser_context,
                    agent_context: &mut agent_context,
                    plane: &plane,
                    control_endpoint: &control_endpoint,
                    workspace_host: &workspace_host,
                    browser_tabs: &mut browser_tabs,
                    agent_panes: &mut agent_panes,
                    assistant_cli_panes: &assistant_cli_panes,
                };
                if let Err(error) = runtime.apply_pending(None, &mut sink) {
                    eprintln!("telescope runtime error: {error}");
                }
                drop(sink);
                let cli_opens = drain_pending_cli_opens(&pending_assistant_cli_opens);
                let mut opened_cli_pane = false;
                for request in cli_opens {
                    match open_assistant_cli_pane(
                        &window,
                        &workspace_host,
                        &plane,
                        assistant_cli_manager.clone(),
                        pending_assistant_cli_closes.clone(),
                        request,
                        &agent_panes,
                        &assistant_cli_panes,
                    ) {
                        Ok(pane) => {
                            assistant_cli_panes.push(pane);
                            opened_cli_pane = true;
                        }
                        Err(error) => eprintln!("telescope CLI pane open error: {error}"),
                    }
                }
                if opened_cli_pane {
                    if let Err(error) = relayout_workspace(
                        &window,
                        &active_tab_id,
                        &tab.id,
                        &webview,
                        &browser_tabs,
                        &agent_panes,
                        &assistant_cli_panes,
                    ) {
                        eprintln!("telescope workspace layout error: {error}");
                    }
                }
                if let Ok(refs) = plane.list_element_references() {
                    if let Ok(mut manager) = assistant_cli_manager.lock() {
                        manager.observe_element_references(&refs);
                    }
                }
                sync_assistant_cli_panes(&assistant_cli_manager, &assistant_cli_panes);
                sync_chrome_state(&plane, &chrome_webview, &active_tab_id);
                if let Err(error) =
                    save_desktop_tabs_if_changed(&profile_dir, &plane, &mut last_tab_snapshot_json)
                {
                    eprintln!("telescope tab snapshot save error: {error}");
                }
                if last_context_capture.elapsed() >= Duration::from_secs(2) {
                    capture_tab_context(&plane, &tab.id, &webview);
                    for browser_tab in &browser_tabs {
                        capture_tab_context(&plane, &browser_tab.id, &browser_tab.webview);
                    }
                    last_context_capture = Instant::now();
                }
            }
            Event::WindowEvent {
                window_id,
                event: WindowEvent::Resized(_),
                ..
            } if window_id == window.id() => {
                if let Err(error) =
                    set_webview_bounds(&chrome_webview, chrome_bounds_for_window(&window))
                {
                    eprintln!("telescope chrome layout error: {error}");
                }
                if let Err(error) = relayout_workspace(
                    &window,
                    &active_tab_id,
                    &tab.id,
                    &webview,
                    &browser_tabs,
                    &agent_panes,
                    &assistant_cli_panes,
                ) {
                    eprintln!("telescope workspace layout error: {error}");
                }
            }
            Event::WindowEvent {
                window_id,
                event: WindowEvent::ModifiersChanged(modifiers),
                ..
            } if window_id == window.id() => {
                keyboard_modifiers = modifiers;
            }
            Event::WindowEvent {
                window_id,
                event:
                    WindowEvent::KeyboardInput {
                        event,
                        is_synthetic,
                        ..
                    },
                ..
            } if window_id == window.id()
                && !is_synthetic
                && !event.repeat
                && event.state == ElementState::Pressed =>
            {
                if let Some(key) = desktop_shortcut_key_for_event(&event) {
                    if let Some(shortcut) = desktop_shortcut_for_key(
                        desktop_shortcut_modifiers(keyboard_modifiers),
                        key,
                    ) {
                        if let Err(error) =
                            run_desktop_shortcut(shortcut, &plane, &active_tab_id, &chrome_webview)
                        {
                            eprintln!("telescope shortcut error: {error}");
                        }
                    }
                }
            }
            Event::WindowEvent {
                window_id,
                event: WindowEvent::CloseRequested,
                ..
            } => {
                if window_id == window.id() {
                    if let Err(error) = save_desktop_tabs_if_changed(
                        &profile_dir,
                        &plane,
                        &mut last_tab_snapshot_json,
                    ) {
                        eprintln!("telescope tab snapshot save error: {error}");
                    }
                    *control_flow = ControlFlow::Exit;
                }
            }
            _ => {}
        }
    });

    fn handle_chrome_ipc_request(
        plane: &ControlPlane,
        pending_cli_opens: &Arc<Mutex<Vec<PendingAssistantCliOpen>>>,
        body: &str,
    ) {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
            return;
        };
        match value.get("type").and_then(|item| item.as_str()) {
            Some("telescope.chrome.activate_tab") => {
                let Some(tab_id) = value.get("tab_id").and_then(|item| item.as_str()) else {
                    return;
                };
                if let Err(error) = plane.activate_tab(tab_id) {
                    eprintln!("telescope chrome activate tab error: {error}");
                }
            }
            Some("telescope.chrome.close_tab") => {
                let Some(tab_id) = value.get("tab_id").and_then(|item| item.as_str()) else {
                    return;
                };
                if let Err(error) = plane.close_tab(tab_id) {
                    eprintln!("telescope chrome close tab error: {error}");
                }
            }
            Some("telescope.chrome.new_tab") => {
                let url = value
                    .get("url")
                    .and_then(|item| item.as_str())
                    .and_then(normalize_chrome_address);
                if let Err(error) = plane.create_tab(CreateTabRequest {
                    url,
                    session_id: None,
                }) {
                    eprintln!("telescope chrome new tab error: {error}");
                }
            }
            Some("telescope.chrome.navigate_tab") => {
                let Some(tab_id) = value.get("tab_id").and_then(|item| item.as_str()) else {
                    return;
                };
                let Some(url) = value
                    .get("url")
                    .and_then(|item| item.as_str())
                    .and_then(normalize_chrome_address)
                else {
                    return;
                };
                if let Err(error) = plane.navigate_tab(
                    tab_id,
                    NavigateRequest {
                        url,
                        session_id: None,
                    },
                ) {
                    eprintln!("telescope chrome navigate tab error: {error}");
                }
            }
            Some("telescope.chrome.go_back") => {
                let Some(tab_id) = value.get("tab_id").and_then(|item| item.as_str()) else {
                    return;
                };
                if let Err(error) = plane.go_back(tab_id) {
                    eprintln!("telescope chrome back error: {error}");
                }
            }
            Some("telescope.chrome.go_forward") => {
                let Some(tab_id) = value.get("tab_id").and_then(|item| item.as_str()) else {
                    return;
                };
                if let Err(error) = plane.go_forward(tab_id) {
                    eprintln!("telescope chrome forward error: {error}");
                }
            }
            Some("telescope.chrome.reload_tab") => {
                let Some(tab_id) = value.get("tab_id").and_then(|item| item.as_str()) else {
                    return;
                };
                if let Err(error) = plane.reload_tab(tab_id) {
                    eprintln!("telescope chrome reload error: {error}");
                }
            }
            Some("telescope.chrome.bookmark_tab") => {
                let Some(tab_id) = value.get("tab_id").and_then(|item| item.as_str()) else {
                    return;
                };
                if let Err(error) = bookmark_tab_from_chrome(plane, tab_id) {
                    eprintln!("telescope chrome bookmark error: {error}");
                }
            }
            Some("telescope.chrome.save_credential") => {
                let Some(tab_id) = value.get("tab_id").and_then(|item| item.as_str()) else {
                    return;
                };
                let Some(username) = value.get("username").and_then(|item| item.as_str()) else {
                    return;
                };
                let Some(password) = value.get("password").and_then(|item| item.as_str()) else {
                    return;
                };
                let username = username.trim();
                if username.is_empty() || password.is_empty() {
                    return;
                }
                let label = value
                    .get("label")
                    .and_then(|item| item.as_str())
                    .map(str::trim)
                    .filter(|item| !item.is_empty())
                    .map(str::to_string);
                if let Err(error) = plane.store_credential_for_tab(
                    tab_id,
                    StoreTabCredentialRequest {
                        username: username.to_string(),
                        password: password.to_string(),
                        login_url: None,
                        label,
                    },
                ) {
                    eprintln!("telescope chrome save credential error: {error}");
                }
            }
            Some("telescope.chrome.fill_credential") => {
                let Some(tab_id) = value.get("tab_id").and_then(|item| item.as_str()) else {
                    return;
                };
                let Some(credential_id) = value.get("credential_id").and_then(|item| item.as_str())
                else {
                    return;
                };
                if let Err(error) = plane.fill_credential_for_tab(tab_id, credential_id) {
                    eprintln!("telescope chrome fill credential error: {error}");
                }
            }
            Some("telescope.chrome.delete_credential") => {
                let Some(tab_id) = value.get("tab_id").and_then(|item| item.as_str()) else {
                    return;
                };
                let Some(credential_id) = value.get("credential_id").and_then(|item| item.as_str())
                else {
                    return;
                };
                if let Err(error) = plane.delete_credential_for_tab(tab_id, credential_id) {
                    eprintln!("telescope chrome delete credential error: {error}");
                }
            }
            Some("telescope.chrome.open_agent_pane") => {
                let Some(tab_id) = value.get("tab_id").and_then(|item| item.as_str()) else {
                    return;
                };
                let Some(url) = value
                    .get("url")
                    .and_then(|item| item.as_str())
                    .and_then(normalize_codex_url)
                else {
                    return;
                };
                let Some(position) = value
                    .get("position")
                    .and_then(|item| item.as_str())
                    .and_then(parse_pane_position)
                else {
                    return;
                };
                let (allow_credentials, allow_interactions, allow_scripts) =
                    chrome_agent_permissions(&value);
                if let Err(error) = plane.open_scoped_agent_pane(OpenScopedAgentPaneRequest {
                    url,
                    position,
                    tab_id: Some(tab_id.to_string()),
                    allow_credentials,
                    allow_interactions,
                    allow_scripts,
                    ttl_seconds: Some(60 * 60),
                }) {
                    eprintln!("telescope chrome open agent pane error: {error}");
                }
            }
            Some("telescope.chrome.open_cli_pane") => {
                let Some(command) = value
                    .get("command")
                    .and_then(|item| item.as_str())
                    .and_then(sanitize_cli_command)
                else {
                    return;
                };
                let Some(position) = value
                    .get("position")
                    .and_then(|item| item.as_str())
                    .and_then(parse_pane_position)
                else {
                    return;
                };
                if let Ok(mut pending) = pending_cli_opens.lock() {
                    pending.push(PendingAssistantCliOpen { command, position });
                }
            }
            Some("telescope.chrome.stop_agent_pane") => {
                let Some(pane_id) = value.get("pane_id").and_then(|item| item.as_str()) else {
                    return;
                };
                if let Err(error) = stop_agent_pane_from_chrome(plane, pane_id) {
                    eprintln!("telescope chrome stop agent pane error: {error}");
                }
            }
            _ => {}
        }
    }

    fn handle_ipc_request(plane: &ControlPlane, body: &str) {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
            return;
        };
        match value.get("type").and_then(|item| item.as_str()) {
            Some("telescope.element_reference") => {
                match serde_json::from_value::<ElementReferenceInput>(value) {
                    Ok(input) => {
                        if let Err(error) = plane.record_element_reference(input) {
                            eprintln!("telescope ipc element reference error: {error}");
                        }
                    }
                    Err(error) => {
                        eprintln!("telescope ipc element reference parse error: {error}");
                    }
                }
            }
            Some("telescope.page_context") => {
                match serde_json::from_value::<PageContextRequest>(value) {
                    Ok(input) => {
                        if let Err(error) = plane.publish_page_context(input) {
                            eprintln!("telescope ipc page context error: {error}");
                        }
                    }
                    Err(error) => {
                        eprintln!("telescope ipc page context parse error: {error}");
                    }
                }
            }
            Some("telescope.command_result") => {
                match serde_json::from_value::<CommandResultIpcRequest>(value) {
                    Ok(input) => {
                        if let Err(error) = plane.record_command_result(
                            &input.command_id,
                            &input.tab_id,
                            input.status,
                            input.message,
                        ) {
                            eprintln!("telescope ipc command result error: {error}");
                        }
                    }
                    Err(error) => {
                        eprintln!("telescope ipc command result parse error: {error}");
                    }
                }
            }
            _ => {}
        }
    }

    fn capture_tab_context(plane: &ControlPlane, tab_id: &str, webview: &WebView) {
        let Ok(tabs) = plane.list_tabs() else {
            return;
        };
        let Some(tab) = tabs.iter().find(|tab| tab.id == tab_id) else {
            return;
        };
        if tab
            .current_url
            .as_deref()
            .is_none_or(|url| url == "about:blank")
        {
            return;
        }
        match page_context_script(tab_id, 8_000) {
            Ok(script) => {
                if let Err(error) = webview.evaluate_script(script.expose_for_webview()) {
                    eprintln!("telescope page context capture error: {error}");
                }
            }
            Err(error) => {
                eprintln!("telescope page context script error: {error}");
            }
        }
    }

    fn drain_pending_cli_opens(
        pending: &Arc<Mutex<Vec<PendingAssistantCliOpen>>>,
    ) -> Vec<PendingAssistantCliOpen> {
        pending
            .lock()
            .map(|mut pending| std::mem::take(&mut *pending))
            .unwrap_or_default()
    }

    fn drain_pending_cli_closes(pending: &Arc<Mutex<Vec<String>>>) -> Vec<String> {
        pending
            .lock()
            .map(|mut pending| std::mem::take(&mut *pending))
            .unwrap_or_default()
    }

    fn open_assistant_cli_pane(
        window: &Window,
        workspace_host: &DesktopWorkspaceHost,
        plane: &ControlPlane,
        manager: Arc<Mutex<AssistantCliManager>>,
        pending_closes: Arc<Mutex<Vec<String>>>,
        request: PendingAssistantCliOpen,
        agent_panes: &[AgentPaneView],
        assistant_cli_panes: &[AssistantCliPaneView],
    ) -> RuntimeResult<AssistantCliPaneView> {
        let pane_id = manager
            .lock()
            .map_err(|_| {
                telescope_runtime::RuntimeError::Adapter(
                    "assistant CLI manager lock poisoned".to_string(),
                )
            })?
            .open_session(&request.command);
        let bounds = layout_for_new_cli_pane(
            window,
            agent_panes,
            assistant_cli_panes,
            &pane_id,
            request.position.clone(),
        )
        .pane_bounds(&pane_id)
        .unwrap_or_else(|| workspace_surface(window.inner_size()).into());
        let plane_for_ipc = plane.clone();
        let manager_for_ipc = manager.clone();
        let pending_closes_for_ipc = pending_closes.clone();
        let builder = WebViewBuilder::new()
            .with_user_agent("Telescope/0.1")
            .with_ipc_handler(move |request| {
                handle_assistant_cli_ipc_request(
                    &plane_for_ipc,
                    &manager_for_ipc,
                    &pending_closes_for_ipc,
                    request.body(),
                );
            })
            .with_html(assistant_cli_pane_html(&pane_id, &request.command))
            .with_general_autofill_enabled(false);
        let webview = build_workspace_webview(builder, window, workspace_host, bounds)
            .map_err(|err| telescope_runtime::RuntimeError::Adapter(err.to_string()))?;
        Ok(AssistantCliPaneView {
            id: pane_id,
            position: request.position,
            webview,
        })
    }

    fn handle_assistant_cli_ipc_request(
        plane: &ControlPlane,
        manager: &Arc<Mutex<AssistantCliManager>>,
        pending_closes: &Arc<Mutex<Vec<String>>>,
        body: &str,
    ) {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
            return;
        };
        let Some(pane_id) = value.get("pane_id").and_then(|item| item.as_str()) else {
            return;
        };
        let result = match value.get("type").and_then(|item| item.as_str()) {
            Some("telescope.cli.input") => {
                let Some(text) = value.get("text").and_then(|item| item.as_str()) else {
                    return;
                };
                manager
                    .lock()
                    .map_err(|_| "assistant CLI manager lock poisoned".to_string())
                    .and_then(|mut manager| manager.send_input(pane_id, text))
            }
            Some("telescope.cli.pick_element") => start_cli_element_pick(plane, manager, pane_id),
            Some("telescope.cli.add_selection") => manager
                .lock()
                .map_err(|_| "assistant CLI manager lock poisoned".to_string())
                .and_then(|mut manager| manager.add_selection_to_chat(pane_id)),
            Some("telescope.cli.add_page_context") => {
                let context = active_page_context(plane);
                manager
                    .lock()
                    .map_err(|_| "assistant CLI manager lock poisoned".to_string())
                    .and_then(|mut manager| manager.add_page_context_to_chat(pane_id, context))
            }
            Some("telescope.cli.close") => {
                if let Ok(mut pending) = pending_closes.lock() {
                    pending.push(pane_id.to_string());
                }
                Ok(())
            }
            _ => Ok(()),
        };
        if let Err(error) = result {
            if let Ok(mut manager) = manager.lock() {
                manager.note(pane_id, &format!("\r\n[Telescope] {error}\r\n"));
            }
        }
    }

    fn start_cli_element_pick(
        plane: &ControlPlane,
        manager: &Arc<Mutex<AssistantCliManager>>,
        pane_id: &str,
    ) -> Result<(), String> {
        let tab = plane
            .active_tab()
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "no active tab".to_string())?;
        let url = tab
            .current_url
            .as_deref()
            .ok_or_else(|| "active tab has no URL".to_string())?;
        let origin = telescope_core::WebOrigin::from_url_str(url).map_err(|error| error.to_string())?;
        let seen_ref_ids = plane
            .list_element_references()
            .map_err(|error| error.to_string())?
            .into_iter()
            .filter(|reference| reference.tab_id == tab.id)
            .map(|reference| reference.id)
            .collect::<BTreeSet<_>>();
        let session = plane
            .create_session(CreateSessionRequest {
                allowed_origins: vec![origin.display_url()],
                allow_credentials: false,
                allow_interactions: true,
                allow_scripts: false,
                ttl_seconds: Some(60 * 60),
            })
            .map_err(|error| error.to_string())?;
        plane
            .queue_agent_action(
                &tab.id,
                AgentActionRequest {
                    session_id: session.id,
                    action: AgentAction::StartElementPicker,
                },
            )
            .map_err(|error| error.to_string())?;
        manager
            .lock()
            .map_err(|_| "assistant CLI manager lock poisoned".to_string())?
            .start_pick(pane_id, tab.id, seen_ref_ids)
    }

    fn active_page_context(plane: &ControlPlane) -> Option<telescope_control::PageContextSnapshot> {
        let active_tab_id = plane.active_tab().ok().flatten()?.id;
        plane
            .list_page_contexts()
            .ok()?
            .into_iter()
            .find(|context| context.tab_id == active_tab_id)
    }

    fn sync_assistant_cli_panes(
        manager: &Arc<Mutex<AssistantCliManager>>,
        panes: &[AssistantCliPaneView],
    ) {
        let Ok(mut manager) = manager.lock() else {
            return;
        };
        for pane in panes {
            let output = manager.drain_output(&pane.id);
            if !output.is_empty() {
                let script = format!(
                    "window.__TELESCOPE_TERMINAL_APPEND && window.__TELESCOPE_TERMINAL_APPEND({});",
                    serde_json_string(&output)
                );
                if let Err(error) = pane.webview.evaluate_script(&script) {
                    eprintln!("telescope CLI pane output error: {error}");
                }
            }
            let state = manager.state_json(&pane.id);
            let Ok(state) = serde_json::to_string(&state) else {
                continue;
            };
            let script = format!(
                "window.__TELESCOPE_TERMINAL_SET_STATE && window.__TELESCOPE_TERMINAL_SET_STATE({state});"
            );
            if let Err(error) = pane.webview.evaluate_script(&script) {
                eprintln!("telescope CLI pane state error: {error}");
            }
        }
    }

    fn layout_for_new_cli_pane(
        window: &Window,
        agent_panes: &[AgentPaneView],
        assistant_cli_panes: &[AssistantCliPaneView],
        pane_id: &str,
        position: PanePosition,
    ) -> WorkspaceLayout {
        let mut panes = pane_layout_inputs(agent_panes, assistant_cli_panes);
        panes.push(PaneLayoutInput {
            id: pane_id.to_string(),
            position,
        });
        compute_desktop_layout(workspace_surface(window.inner_size()), panes).workspace
    }

    fn build_browser_tab_webview(
        browser_context: &mut WebContext,
        plane: &ControlPlane,
        window: &Window,
        workspace_host: &DesktopWorkspaceHost,
        tab: &TabState,
        bounds: WorkspaceRect,
    ) -> RuntimeResult<WebView> {
        let plane_for_ipc = plane.clone();
        let builder = WebViewBuilder::new_with_web_context(browser_context)
            .with_user_agent("Telescope/0.1")
            .with_ipc_handler(move |request| {
                handle_ipc_request(&plane_for_ipc, request.body());
            })
            .with_url(tab.current_url.as_deref().unwrap_or("about:blank"))
            .with_general_autofill_enabled(false);
        build_workspace_webview(builder, window, workspace_host, bounds)
            .map_err(|err| telescope_runtime::RuntimeError::Adapter(err.to_string()))
    }

    fn layout_for_new_pane(
        window: &Window,
        agent_panes: &[AgentPaneView],
        assistant_cli_panes: &[AssistantCliPaneView],
        pane: &AgentPaneState,
    ) -> WorkspaceLayout {
        let mut panes = pane_layout_inputs(agent_panes, assistant_cli_panes);
        panes.push(PaneLayoutInput {
            id: pane.id.clone(),
            position: pane.position.clone(),
        });
        compute_desktop_layout(workspace_surface(window.inner_size()), panes).workspace
    }

    fn relayout_workspace(
        window: &Window,
        active_tab_id: &str,
        main_tab_id: &str,
        browser_webview: &WebView,
        browser_tabs: &[BrowserTabView],
        agent_panes: &[AgentPaneView],
        assistant_cli_panes: &[AssistantCliPaneView],
    ) -> RuntimeResult<()> {
        let layout = compute_desktop_layout(
            workspace_surface(window.inner_size()),
            pane_layout_inputs(agent_panes, assistant_cli_panes),
        )
        .workspace;
        apply_browser_tab_layout(
            browser_webview,
            active_tab_id == main_tab_id,
            layout.browser,
        )?;

        for browser_tab in browser_tabs {
            apply_browser_tab_layout(
                &browser_tab.webview,
                active_tab_id == browser_tab.id,
                layout.browser,
            )?;
        }

        for pane in agent_panes {
            if let Some(bounds) = layout.pane_bounds(&pane.id) {
                set_webview_bounds(&pane.webview, bounds)?;
            }
        }
        for pane in assistant_cli_panes {
            if let Some(bounds) = layout.pane_bounds(&pane.id) {
                set_webview_bounds(&pane.webview, bounds)?;
            }
        }

        Ok(())
    }

    fn browser_bounds_for_tabs(
        window: &Window,
        agent_panes: &[AgentPaneView],
        assistant_cli_panes: &[AssistantCliPaneView],
    ) -> WorkspaceRect {
        compute_desktop_layout(
            workspace_surface(window.inner_size()),
            pane_layout_inputs(agent_panes, assistant_cli_panes),
        )
        .workspace
        .browser
    }

    fn apply_browser_tab_layout(
        webview: &WebView,
        is_active: bool,
        bounds: WorkspaceRect,
    ) -> RuntimeResult<()> {
        set_webview_visible(webview, is_active)?;
        if is_active {
            set_webview_bounds(webview, bounds)?;
        }
        Ok(())
    }

    fn pane_layout_inputs(
        agent_panes: &[AgentPaneView],
        assistant_cli_panes: &[AssistantCliPaneView],
    ) -> Vec<PaneLayoutInput> {
        agent_panes
            .iter()
            .map(|pane| PaneLayoutInput {
                id: pane.id.clone(),
                position: pane.position.clone(),
            })
            .chain(assistant_cli_panes.iter().map(|pane| PaneLayoutInput {
                id: pane.id.clone(),
                position: pane.position.clone(),
            }))
            .collect()
    }

    fn set_webview_bounds(webview: &WebView, bounds: WorkspaceRect) -> RuntimeResult<()> {
        webview
            .set_bounds(workspace_rect_to_wry(bounds))
            .map_err(|err| telescope_runtime::RuntimeError::Adapter(err.to_string()))
    }

    fn set_webview_visible(webview: &WebView, visible: bool) -> RuntimeResult<()> {
        webview
            .set_visible(visible)
            .map_err(|err| telescope_runtime::RuntimeError::Adapter(err.to_string()))
    }

    fn chrome_bounds_for_window(window: &Window) -> WorkspaceRect {
        compute_desktop_layout(workspace_surface(window.inner_size()), Vec::new()).chrome
    }

    fn sync_chrome_state(plane: &ControlPlane, chrome_webview: &WebView, active_tab_id: &str) {
        let Ok(tabs) = plane.list_tabs() else {
            return;
        };
        let active_tab_id = plane
            .active_tab()
            .ok()
            .flatten()
            .map(|tab| tab.id)
            .unwrap_or_else(|| active_tab_id.to_string());
        let tabs = tabs
            .into_iter()
            .map(|tab| {
                let is_active = tab.id == active_tab_id;
                serde_json::json!({
                    "id": tab.id,
                    "title": tab.title,
                    "url": tab.current_url,
                    "active": is_active,
                })
            })
            .collect::<Vec<_>>();
        let credentials = plane
            .list_credentials_for_tab(&active_tab_id)
            .unwrap_or_default()
            .into_iter()
            .map(|credential| {
                serde_json::json!({
                    "id": credential.id,
                    "origin": credential.origin.display_url(),
                    "username": credential.username,
                    "label": credential.label,
                    "login_url": credential.login_url,
                    "updated_at_unix": credential.updated_at_unix,
                })
            })
            .collect::<Vec<_>>();
        let panes = plane
            .list_agent_panes()
            .unwrap_or_default()
            .into_iter()
            .map(|pane| {
                let connection = plane.agent_pane_connection(&pane.id).ok();
                let connected = connection.is_some();
                let expires_at_unix = connection
                    .as_ref()
                    .and_then(|connection| connection.expires_at_unix);
                let permission_summary = connection.as_ref().map(|connection| {
                    policy_flags(
                        connection.session_policy.allow_credentials,
                        connection.session_policy.allow_interactions,
                        connection.session_policy.allow_scripts,
                    )
                });
                serde_json::json!({
                    "id": pane.id,
                    "url": pane.url,
                    "position": pane.position,
                    "attached_tab_id": pane.attached_tab_id,
                    "session_id": pane.session_id,
                    "connected": connected,
                    "expires_at_unix": expires_at_unix,
                    "permission_summary": permission_summary,
                })
            })
            .collect::<Vec<_>>();
        let bookmarks = plane
            .list_bookmarks()
            .unwrap_or_default()
            .into_iter()
            .map(|bookmark| {
                serde_json::json!({
                    "id": bookmark.id,
                    "url": bookmark.url,
                    "title": bookmark.title,
                    "updated_at_unix": bookmark.updated_at_unix,
                })
            })
            .collect::<Vec<_>>();
        let audit_events = chrome_audit_events(plane, 5);
        let state = serde_json::json!({
            "active_tab_id": active_tab_id,
            "tabs": tabs,
            "credentials": credentials,
            "panes": panes,
            "bookmarks": bookmarks,
            "audit_events": audit_events,
        });
        let Ok(state) = serde_json::to_string(&state) else {
            return;
        };
        let script = format!(
            "window.__TELESCOPE_SET_CHROME_STATE && window.__TELESCOPE_SET_CHROME_STATE({state});"
        );
        if let Err(error) = chrome_webview.evaluate_script(&script) {
            eprintln!("telescope chrome state sync error: {error}");
        }
    }

    fn parse_pane_position(input: &str) -> Option<PanePosition> {
        match input {
            "left" => Some(PanePosition::Left),
            "right" => Some(PanePosition::Right),
            "bottom" => Some(PanePosition::Bottom),
            _ => None,
        }
    }

    fn agent_connection_script(
        control_endpoint: &str,
        pane: &AgentPaneState,
        connection: Option<&AgentPaneConnection>,
    ) -> RuntimeResult<String> {
        let Some(connection) = connection else {
            return Ok(String::new());
        };
        let payload = serde_json::to_string(&agent_connection_payload(
            control_endpoint,
            pane,
            connection,
        ))?;
        Ok(agent_connection_script_source(&payload))
    }

    fn assistant_cli_pane_html(pane_id: &str, command: &str) -> String {
        let pane_id = serde_json::to_string(pane_id).unwrap_or_else(|_| "\"\"".to_string());
        let command = serde_json::to_string(command).unwrap_or_else(|_| "\"codex\"".to_string());
        format!(
            r#"<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root {{
  color-scheme: dark;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
  font-size: 12px;
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0;
  height: 100vh;
  display: grid;
  grid-template-rows: 34px minmax(0, 1fr) 34px;
  background: #11161d;
  color: #d8dee9;
}}
.bar {{
  display: flex;
  align-items: center;
  gap: 6px;
  min-width: 0;
  padding: 4px 6px;
  border-bottom: 1px solid #2c3440;
  background: #171d25;
}}
.title {{
  flex: 1 1 auto;
  overflow: hidden;
  white-space: nowrap;
  text-overflow: ellipsis;
  color: #f0f3f7;
  font-weight: 600;
}}
button {{
  flex: 0 0 auto;
  height: 26px;
  border: 1px solid #3a4654;
  border-radius: 5px;
  padding: 0 8px;
  background: #202833;
  color: #e6edf3;
  font: inherit;
}}
button:disabled {{
  color: #798493;
  background: #171d25;
}}
button:hover:not(:disabled) {{ background: #2a3441; }}
#terminal-output {{
  margin: 0;
  padding: 8px;
  overflow: auto;
  white-space: pre-wrap;
  word-break: break-word;
  line-height: 1.35;
}}
.input {{
  display: grid;
  grid-template-columns: minmax(0, 1fr) 54px;
  gap: 6px;
  padding: 4px 6px;
  border-top: 1px solid #2c3440;
  background: #171d25;
}}
#terminal-input {{
  min-width: 0;
  height: 26px;
  border: 1px solid #3a4654;
  border-radius: 5px;
  padding: 0 8px;
  background: #0d1117;
  color: #e6edf3;
  font: inherit;
}}
.selection {{
  flex: 0 1 220px;
  overflow: hidden;
  white-space: nowrap;
  text-overflow: ellipsis;
  color: #9fb3c8;
}}
</style>
</head>
<body>
  <div class="bar">
    <div id="title" class="title"></div>
    <div id="selection" class="selection"></div>
    <button id="pick" type="button">Pick</button>
    <button id="add-selection" type="button" disabled>Add selection</button>
    <button id="add-page" type="button">Add page</button>
    <button id="close" type="button">Close</button>
  </div>
  <pre id="terminal-output"></pre>
  <form id="input-form" class="input">
    <input id="terminal-input" autocomplete="off" spellcheck="false">
    <button type="submit">Send</button>
  </form>
<script>
const paneId = {pane_id};
const command = {command};
const titleEl = document.getElementById('title');
const selectionEl = document.getElementById('selection');
const outputEl = document.getElementById('terminal-output');
const formEl = document.getElementById('input-form');
const inputEl = document.getElementById('terminal-input');
const pickEl = document.getElementById('pick');
const addSelectionEl = document.getElementById('add-selection');
const addPageEl = document.getElementById('add-page');
const closeEl = document.getElementById('close');
titleEl.textContent = `CLI: ${{command}}`;

function post(type, payload = {{}}) {{
  window.ipc.postMessage(JSON.stringify({{ type, pane_id: paneId, ...payload }}));
}}

function cleanTerminalText(text) {{
  return String(text || '')
    .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, '')
    .replace(/\x1b\][^\x07]*(\x07|\x1b\\)/g, '');
}}

function appendOutput(text) {{
  outputEl.textContent += cleanTerminalText(text);
  if (outputEl.textContent.length > 180000) {{
    outputEl.textContent = outputEl.textContent.slice(-140000);
  }}
  outputEl.scrollTop = outputEl.scrollHeight;
}}

window.__TELESCOPE_TERMINAL_APPEND = appendOutput;
window.__TELESCOPE_TERMINAL_SET_STATE = (state) => {{
  if (state?.selection) {{
    selectionEl.textContent = state.selection.summary || state.selection.selector || 'selected';
    selectionEl.title = state.selection.selector || '';
    addSelectionEl.disabled = false;
  }} else {{
    selectionEl.textContent = state?.pending_pick ? 'Picking...' : '';
    selectionEl.title = '';
    addSelectionEl.disabled = true;
  }}
  pickEl.disabled = Boolean(state?.pending_pick);
}};

formEl.addEventListener('submit', (event) => {{
  event.preventDefault();
  const text = inputEl.value;
  if (!text) return;
  post('telescope.cli.input', {{ text: `${{text}}\r` }});
  inputEl.value = '';
}});

inputEl.addEventListener('keydown', (event) => {{
  if (event.key === 'Escape') {{
    event.preventDefault();
    post('telescope.cli.input', {{ text: '\x03' }});
  }}
}});

pickEl.addEventListener('click', () => post('telescope.cli.pick_element'));
addSelectionEl.addEventListener('click', () => post('telescope.cli.add_selection'));
addPageEl.addEventListener('click', () => post('telescope.cli.add_page_context'));
closeEl.addEventListener('click', () => post('telescope.cli.close'));
inputEl.focus();
</script>
</body>
</html>"#
        )
    }

    fn browser_chrome_html() -> String {
        r#"<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root {
  color-scheme: light;
  font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  font-size: 13px;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  height: 100vh;
  overflow: hidden;
  background: #eef1f4;
  color: #1f2933;
}
.chrome {
  height: 274px;
  display: grid;
  grid-template-columns: minmax(0, 1fr);
  grid-template-rows: 30px 30px 30px 30px 30px 30px 48px;
  gap: 6px;
  align-items: center;
  padding: 5px 8px;
  border-bottom: 1px solid #c8d0d8;
}
.tabs {
  grid-column: 1 / -1;
  display: flex;
  align-items: center;
  gap: 4px;
  min-width: 0;
  overflow: hidden;
}
.tab {
  display: inline-grid;
  grid-template-columns: minmax(0, 1fr) 22px;
  align-items: center;
  gap: 3px;
  min-width: 92px;
  max-width: 220px;
  height: 30px;
  padding: 0 3px 0 9px;
  border: 1px solid #b9c3cd;
  border-radius: 6px;
  background: #dbe2e8;
  color: #2c3742;
}
.tab.active {
  background: #ffffff;
  border-color: #8fa1b2;
}
.tab-label {
  overflow: hidden;
  white-space: nowrap;
  text-overflow: ellipsis;
}
button {
  border: 1px solid #b8c2cc;
  background: #f8fafb;
  color: #1f2933;
  border-radius: 5px;
  height: 28px;
  min-width: 28px;
  padding: 0 8px;
  font: inherit;
}
button:hover { background: #ffffff; }
.tab-close {
  width: 22px;
  min-width: 22px;
  height: 22px;
  padding: 0;
  border-color: transparent;
  background: transparent;
}
.tab-close:hover { border-color: #c7cfd7; background: #eef1f4; }
.new-tab {
  flex: 0 0 30px;
  width: 30px;
  padding: 0;
  font-size: 18px;
  line-height: 1;
}
.nav {
  grid-column: 1 / -1;
  display: grid;
  grid-template-columns: 30px 30px 30px minmax(220px, 1fr) 44px 32px minmax(130px, 240px);
  gap: 6px;
  min-width: 0;
}
.credentials {
  grid-column: 1 / -1;
  display: grid;
  grid-template-columns: minmax(120px, 1fr) minmax(120px, 1fr) minmax(130px, 1fr) 64px 64px 76px;
  gap: 6px;
  min-width: 0;
}
.agent {
  grid-column: 1 / -1;
  display: grid;
  grid-template-columns: minmax(160px, 1fr) 96px repeat(4, minmax(58px, 72px)) 70px;
  gap: 6px;
  min-width: 0;
}
.cli {
  grid-column: 1 / -1;
  display: grid;
  grid-template-columns: minmax(160px, 1fr) 96px 86px;
  gap: 6px;
  min-width: 0;
}
.panes {
  grid-column: 1 / -1;
  display: grid;
  grid-template-columns: minmax(0, 1fr) 70px;
  gap: 6px;
  min-width: 0;
}
.audit {
  grid-column: 1 / -1;
  display: grid;
  grid-template-columns: 70px minmax(0, 1fr);
  gap: 6px;
  min-width: 0;
  height: 48px;
}
.audit-title {
  display: flex;
  align-items: center;
  height: 48px;
  padding: 0 10px;
  border: 1px solid #b8c2cc;
  border-radius: 6px;
  background: #ffffff;
  font-weight: 600;
}
.audit-list {
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 6px;
  min-width: 0;
  overflow: hidden;
}
.audit-card {
  min-width: 0;
  height: 48px;
  padding: 4px 6px;
  border: 1px solid #b8c2cc;
  border-radius: 6px;
  background: #ffffff;
  overflow: hidden;
}
.audit-card.empty {
  grid-column: 1 / -1;
  display: flex;
  align-items: center;
}
.audit-line {
  overflow: hidden;
  white-space: nowrap;
  text-overflow: ellipsis;
  line-height: 1.25;
}
.audit-time {
  color: #5d6b78;
  font-size: 11px;
}
.audit-summary {
  font-weight: 600;
}
.audit-detail {
  color: #384653;
  font-size: 11px;
}
.address,
.credential-select,
.credential-input,
.agent-url,
.cli-command,
.agent-position,
.cli-position,
.pane-select,
.bookmark-select {
  width: 100%;
  height: 30px;
  border: 1px solid #aeb9c4;
  border-radius: 6px;
  padding: 0 10px;
  background: #ffffff;
  color: #1f2933;
  font: inherit;
  min-width: 0;
}
.agent-option {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 4px;
  height: 30px;
  min-width: 0;
  padding: 0 5px;
  border: 1px solid #aeb9c4;
  border-radius: 6px;
  background: #ffffff;
  color: #1f2933;
  white-space: nowrap;
  overflow: hidden;
}
.agent-option input {
  flex: 0 0 auto;
  width: 13px;
  height: 13px;
  margin: 0;
}
.agent-option span {
  overflow: hidden;
  text-overflow: ellipsis;
}
</style>
</head>
<body>
  <div class="chrome">
    <div id="tabs" class="tabs"></div>
    <form id="nav" class="nav">
      <button id="back" type="button" title="Back">&lt;</button>
      <button id="forward" type="button" title="Forward">&gt;</button>
      <button id="reload" type="button" title="Reload">R</button>
      <input id="address" class="address" autocomplete="off" spellcheck="false" placeholder="Search or enter address">
      <button id="go" type="submit" title="Go">Go</button>
      <button id="bookmark-current" type="button" title="Bookmark active tab">*</button>
      <select id="bookmark-select" class="bookmark-select" title="Bookmarks"></select>
    </form>
    <form id="credentials" class="credentials">
      <select id="credential-select" class="credential-select" title="Saved login"></select>
      <input id="credential-username" class="credential-input" autocomplete="username" spellcheck="false" placeholder="Username">
      <input id="credential-password" class="credential-input" type="password" autocomplete="current-password" placeholder="Password">
      <button id="save-credential" type="submit" title="Save login">Save</button>
      <button id="fill-credential" type="button" title="Fill login">Fill</button>
      <button id="delete-credential" type="button" title="Forget saved login">Forget</button>
    </form>
    <form id="agent" class="agent">
      <input id="agent-url" class="agent-url" autocomplete="off" spellcheck="false" placeholder="Codex URL">
      <select id="agent-position" class="agent-position" title="Pane edge">
        <option value="right">Right</option>
        <option value="left">Left</option>
        <option value="bottom">Bottom</option>
      </select>
      <label class="agent-option" title="Allow credential fill"><input id="agent-credentials" type="checkbox" checked><span>Cred</span></label>
      <label class="agent-option" title="Allow page interactions"><input id="agent-interactions" type="checkbox" checked><span>Act</span></label>
      <label class="agent-option" title="Allow custom scripts"><input id="agent-scripts" type="checkbox"><span>JS</span></label>
      <label class="agent-option" title="Read-only pane"><input id="agent-read-only" type="checkbox"><span>Read</span></label>
      <button id="open-agent" type="submit" title="Open Codex pane">Open</button>
    </form>
    <form id="cli" class="cli">
      <input id="cli-command" class="cli-command" autocomplete="off" spellcheck="false" placeholder="codex or claude">
      <select id="cli-position" class="cli-position" title="CLI pane edge">
        <option value="right">Right</option>
        <option value="left">Left</option>
        <option value="bottom">Bottom</option>
      </select>
      <button id="open-cli" type="submit" title="Open local CLI pane">Open CLI</button>
    </form>
    <div id="panes" class="panes">
      <select id="agent-pane-select" class="pane-select" title="Open Codex panes"></select>
      <button id="stop-agent-pane" type="button" title="Stop selected Codex pane">Stop</button>
    </div>
    <div class="audit">
      <div class="audit-title">Audit</div>
      <div id="audit-list" class="audit-list"></div>
    </div>
  </div>
<script>
const tabsEl = document.getElementById('tabs');
const navEl = document.getElementById('nav');
const backEl = document.getElementById('back');
const forwardEl = document.getElementById('forward');
const reloadEl = document.getElementById('reload');
const addressEl = document.getElementById('address');
const bookmarkCurrentEl = document.getElementById('bookmark-current');
const bookmarkSelectEl = document.getElementById('bookmark-select');
const credentialsEl = document.getElementById('credentials');
const credentialSelectEl = document.getElementById('credential-select');
const credentialUsernameEl = document.getElementById('credential-username');
const credentialPasswordEl = document.getElementById('credential-password');
const saveCredentialEl = document.getElementById('save-credential');
const fillCredentialEl = document.getElementById('fill-credential');
const deleteCredentialEl = document.getElementById('delete-credential');
const agentEl = document.getElementById('agent');
const agentUrlEl = document.getElementById('agent-url');
const agentPositionEl = document.getElementById('agent-position');
const agentCredentialsEl = document.getElementById('agent-credentials');
const agentInteractionsEl = document.getElementById('agent-interactions');
const agentScriptsEl = document.getElementById('agent-scripts');
const agentReadOnlyEl = document.getElementById('agent-read-only');
const openAgentEl = document.getElementById('open-agent');
const agentPaneSelectEl = document.getElementById('agent-pane-select');
const stopAgentPaneEl = document.getElementById('stop-agent-pane');
const auditListEl = document.getElementById('audit-list');
const defaultAgentUrl = __TELESCOPE_DEFAULT_CODEX_URL_JSON__;
if (defaultAgentUrl && !agentUrlEl.value) {
  agentUrlEl.value = defaultAgentUrl;
}
const defaultCliCommand = __TELESCOPE_DEFAULT_CLI_COMMAND_JSON__;
const cliEl = document.getElementById('cli');
const cliCommandEl = document.getElementById('cli-command');
const cliPositionEl = document.getElementById('cli-position');
const openCliEl = document.getElementById('open-cli');
if (defaultCliCommand && !cliCommandEl.value) {
  cliCommandEl.value = defaultCliCommand;
}
let state = { active_tab_id: null, tabs: [], credentials: [], panes: [], bookmarks: [], audit_events: [] };
let renderedActiveTabId = null;

function post(type, payload = {}) {
  window.ipc.postMessage(JSON.stringify({ type, ...payload }));
}

function activeTab() {
  return state.tabs.find((tab) => tab.active) || null;
}

function tabLabel(tab) {
  return tab.title || tab.url || 'New Tab';
}

function credentialLabel(credential) {
  return credential.label || credential.username || credential.origin || 'Login';
}

function bookmarkLabel(bookmark) {
  return bookmark.title || bookmark.url || 'Bookmark';
}

function paneLabel(pane) {
  const edge = pane.position || 'pane';
  const target = pane.url || pane.id;
  const access = pane.permission_summary || (pane.connected ? 'scoped' : 'unscoped');
  return `${edge}: ${target} (${access})`;
}

function paneTitle(pane) {
  const items = [
    pane.url || pane.id,
    pane.attached_tab_id ? `tab ${pane.attached_tab_id}` : null,
    pane.session_id ? `session ${pane.session_id}` : null,
    pane.permission_summary || null,
    pane.expires_at_unix ? `expires ${new Date(pane.expires_at_unix * 1000).toLocaleString()}` : null
  ];
  return items.filter(Boolean).join(' | ');
}

function auditTime(event) {
  const value = Number(event.created_at_unix || 0);
  if (!value) return '';
  return new Date(value * 1000).toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  });
}

function render() {
  const active = activeTab();
  const activeChanged = renderedActiveTabId !== state.active_tab_id;
  renderedActiveTabId = state.active_tab_id;

  tabsEl.replaceChildren();
  for (const tab of state.tabs) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = `tab${tab.active ? ' active' : ''}`;
    button.title = tab.url || tab.title || 'New Tab';
    button.addEventListener('click', () => post('telescope.chrome.activate_tab', { tab_id: tab.id }));

    const label = document.createElement('span');
    label.className = 'tab-label';
    label.textContent = tabLabel(tab);
    button.appendChild(label);

    const close = document.createElement('button');
    close.type = 'button';
    close.className = 'tab-close';
    close.title = 'Close tab';
    close.textContent = 'x';
    close.addEventListener('click', (event) => {
      event.stopPropagation();
      post('telescope.chrome.close_tab', { tab_id: tab.id });
    });
    button.appendChild(close);
    tabsEl.appendChild(button);
  }

  const add = document.createElement('button');
  add.type = 'button';
  add.className = 'new-tab';
  add.title = 'New tab';
  add.textContent = '+';
  add.addEventListener('click', () => post('telescope.chrome.new_tab'));
  tabsEl.appendChild(add);

  if (document.activeElement !== addressEl) {
    addressEl.value = active?.url || '';
  }

  const previousCredentialId = credentialSelectEl.value;
  const previousBookmarkId = bookmarkSelectEl.value;
  credentialSelectEl.replaceChildren();
  for (const credential of state.credentials || []) {
    const option = document.createElement('option');
    option.value = credential.id;
    option.textContent = credentialLabel(credential);
    credentialSelectEl.appendChild(option);
  }
  if (!credentialSelectEl.options.length) {
    const option = document.createElement('option');
    option.value = '';
    option.textContent = 'No saved login';
    credentialSelectEl.appendChild(option);
  }

  const hasActiveTab = Boolean(active);
  const hasCredential = Boolean((state.credentials || []).length);
  bookmarkSelectEl.replaceChildren();
  const bookmarks = state.bookmarks || [];
  if (!bookmarks.length) {
    const option = document.createElement('option');
    option.value = '';
    option.textContent = 'No bookmarks';
    bookmarkSelectEl.appendChild(option);
  } else {
    const placeholder = document.createElement('option');
    placeholder.value = '';
    placeholder.textContent = 'Bookmarks';
    bookmarkSelectEl.appendChild(placeholder);
    for (const bookmark of bookmarks) {
      const option = document.createElement('option');
      option.value = bookmark.id;
      option.textContent = bookmarkLabel(bookmark);
      option.title = bookmark.url || bookmarkLabel(bookmark);
      bookmarkSelectEl.appendChild(option);
    }
  }
  const hasBookmark = Boolean(bookmarks.length);
  bookmarkSelectEl.value = bookmarks.some((bookmark) => bookmark.id === previousBookmarkId)
    ? previousBookmarkId
    : '';
  const previousPaneId = agentPaneSelectEl.value;
  agentPaneSelectEl.replaceChildren();
  for (const pane of state.panes || []) {
	    const option = document.createElement('option');
	    option.value = pane.id;
	    option.textContent = paneLabel(pane);
	    option.title = paneTitle(pane);
	    agentPaneSelectEl.appendChild(option);
	  }
  if (!agentPaneSelectEl.options.length) {
    const option = document.createElement('option');
    option.value = '';
    option.textContent = 'No Codex panes';
    agentPaneSelectEl.appendChild(option);
  }
  const hasPane = Boolean((state.panes || []).length);
  const selectedPaneId = (state.panes || []).some((pane) => pane.id === previousPaneId)
    ? previousPaneId
    : ((state.panes || [])[0]?.id || '');
  agentPaneSelectEl.value = selectedPaneId;

  auditListEl.replaceChildren();
  const auditEvents = state.audit_events || [];
  if (!auditEvents.length) {
    const card = document.createElement('div');
    card.className = 'audit-card empty';
    card.textContent = 'No audit events';
    auditListEl.appendChild(card);
  } else {
    for (const event of auditEvents) {
      const card = document.createElement('div');
      card.className = 'audit-card';
      card.title = `${event.summary || 'Audit event'} ${event.detail || ''}`.trim();

      const time = document.createElement('div');
      time.className = 'audit-line audit-time';
      time.textContent = auditTime(event);
      card.appendChild(time);

      const summary = document.createElement('div');
      summary.className = 'audit-line audit-summary';
      summary.textContent = event.summary || 'Audit event';
      card.appendChild(summary);

      const detail = document.createElement('div');
      detail.className = 'audit-line audit-detail';
      detail.textContent = event.detail || '';
      card.appendChild(detail);

      auditListEl.appendChild(card);
    }
  }

  const selectedCredentialId = (state.credentials || []).some((credential) => credential.id === previousCredentialId)
    ? previousCredentialId
    : ((state.credentials || [])[0]?.id || '');
  credentialSelectEl.value = selectedCredentialId;
  credentialSelectEl.disabled = !hasActiveTab || !hasCredential;
  credentialUsernameEl.disabled = !hasActiveTab;
  credentialPasswordEl.disabled = !hasActiveTab;
  saveCredentialEl.disabled = !hasActiveTab;
  fillCredentialEl.disabled = !hasActiveTab || !hasCredential;
  deleteCredentialEl.disabled = !hasActiveTab || !hasCredential;
  backEl.disabled = !hasActiveTab;
  forwardEl.disabled = !hasActiveTab;
  reloadEl.disabled = !hasActiveTab;
  bookmarkCurrentEl.disabled = !hasActiveTab || !active?.url;
  bookmarkSelectEl.disabled = !hasBookmark;
  agentUrlEl.disabled = !hasActiveTab;
  agentPositionEl.disabled = !hasActiveTab;
  agentReadOnlyEl.disabled = !hasActiveTab;
  agentCredentialsEl.disabled = !hasActiveTab || agentReadOnlyEl.checked;
  agentInteractionsEl.disabled = !hasActiveTab || agentReadOnlyEl.checked;
  agentScriptsEl.disabled = !hasActiveTab || agentReadOnlyEl.checked;
  openAgentEl.disabled = !hasActiveTab;
  openCliEl.disabled = !cliCommandEl.value.trim();
  agentPaneSelectEl.disabled = !hasPane;
  stopAgentPaneEl.disabled = !hasPane;

  if (activeChanged) {
    credentialPasswordEl.value = '';
    if (document.activeElement !== credentialUsernameEl) {
      const selected = (state.credentials || []).find((credential) => credential.id === selectedCredentialId);
      credentialUsernameEl.value = selected?.username || '';
    }
  }
}

navEl.addEventListener('submit', (event) => {
  event.preventDefault();
  const url = addressEl.value.trim();
  if (!url) return;
  const active = activeTab();
  if (active) {
    post('telescope.chrome.navigate_tab', { tab_id: active.id, url });
  } else {
    post('telescope.chrome.new_tab', { url });
  }
});

backEl.addEventListener('click', () => {
  const active = activeTab();
  if (!active) return;
  post('telescope.chrome.go_back', { tab_id: active.id });
});

forwardEl.addEventListener('click', () => {
  const active = activeTab();
  if (!active) return;
  post('telescope.chrome.go_forward', { tab_id: active.id });
});

reloadEl.addEventListener('click', () => {
  const active = activeTab();
  if (!active) return;
  post('telescope.chrome.reload_tab', { tab_id: active.id });
});

bookmarkCurrentEl.addEventListener('click', () => {
  const active = activeTab();
  if (!active) return;
  post('telescope.chrome.bookmark_tab', { tab_id: active.id });
});

bookmarkSelectEl.addEventListener('change', () => {
  const bookmark = (state.bookmarks || []).find((item) => item.id === bookmarkSelectEl.value);
  if (!bookmark?.url) return;
  const active = activeTab();
  if (active) {
    post('telescope.chrome.navigate_tab', { tab_id: active.id, url: bookmark.url });
  } else {
    post('telescope.chrome.new_tab', { url: bookmark.url });
  }
});

credentialSelectEl.addEventListener('change', () => {
  const selected = (state.credentials || []).find((credential) => credential.id === credentialSelectEl.value);
  if (document.activeElement !== credentialUsernameEl) {
    credentialUsernameEl.value = selected?.username || '';
  }
});

credentialsEl.addEventListener('submit', (event) => {
  event.preventDefault();
  const active = activeTab();
  if (!active) return;
  const username = credentialUsernameEl.value.trim();
  const password = credentialPasswordEl.value;
  if (!username || !password) return;
  post('telescope.chrome.save_credential', { tab_id: active.id, username, password });
  credentialPasswordEl.value = '';
});

fillCredentialEl.addEventListener('click', () => {
  const active = activeTab();
  const credential_id = credentialSelectEl.value;
  if (!active || !credential_id) return;
  post('telescope.chrome.fill_credential', { tab_id: active.id, credential_id });
});

deleteCredentialEl.addEventListener('click', () => {
  const active = activeTab();
  const credential_id = credentialSelectEl.value;
  if (!active || !credential_id) return;
  post('telescope.chrome.delete_credential', { tab_id: active.id, credential_id });
});

agentReadOnlyEl.addEventListener('change', () => {
  if (agentReadOnlyEl.checked) {
    agentCredentialsEl.checked = false;
    agentInteractionsEl.checked = false;
    agentScriptsEl.checked = false;
  }
  render();
});

for (const input of [agentCredentialsEl, agentInteractionsEl, agentScriptsEl]) {
  input.addEventListener('change', () => {
    if (input.checked) {
      agentReadOnlyEl.checked = false;
    }
    render();
  });
}

agentEl.addEventListener('submit', (event) => {
  event.preventDefault();
  const active = activeTab();
  const url = agentUrlEl.value.trim();
  const position = agentPositionEl.value;
  if (!active || !url || !position) return;
  const read_only = agentReadOnlyEl.checked;
  post('telescope.chrome.open_agent_pane', {
    tab_id: active.id,
    url,
    position,
    read_only,
    allow_credentials: read_only ? false : agentCredentialsEl.checked,
    allow_interactions: read_only ? false : agentInteractionsEl.checked,
    allow_scripts: read_only ? false : agentScriptsEl.checked
  });
});

cliCommandEl.addEventListener('input', () => render());

cliEl.addEventListener('submit', (event) => {
  event.preventDefault();
  const command = cliCommandEl.value.trim();
  const position = cliPositionEl.value;
  if (!command || !position) return;
  post('telescope.chrome.open_cli_pane', { command, position });
});

stopAgentPaneEl.addEventListener('click', () => {
  const pane_id = agentPaneSelectEl.value;
  if (!pane_id) return;
  post('telescope.chrome.stop_agent_pane', { pane_id });
});

window.__TELESCOPE_SET_CHROME_STATE = (next) => {
  state = next || { active_tab_id: null, tabs: [], credentials: [], panes: [], bookmarks: [], audit_events: [] };
  render();
};

render();
</script>
</body>
</html>"#
            .replace(
                "__TELESCOPE_DEFAULT_CODEX_URL_JSON__",
                &serde_json::to_string(&default_codex_url())
                    .unwrap_or_else(|_| "null".to_string()),
            )
            .replace(
                "__TELESCOPE_DEFAULT_CLI_COMMAND_JSON__",
                &serde_json::to_string(&default_cli_command())
                    .unwrap_or_else(|_| "\"codex\"".to_string()),
            )
    }
}

#[cfg(feature = "control-server")]
const BROWSER_CHROME_HEIGHT: u32 = 274;
#[cfg(feature = "control-server")]
const DESKTOP_TABS_FILE: &str = "tabs.json";
#[cfg(feature = "control-server")]
const DESKTOP_TAB_SNAPSHOT_VERSION: u32 = 1;
#[cfg(feature = "control-server")]
const MAX_RESTORED_TABS: usize = 32;

#[cfg(feature = "control-server")]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
struct DesktopTabSnapshot {
    version: u32,
    active_index: Option<usize>,
    tabs: Vec<DesktopSavedTab>,
}

#[cfg(feature = "control-server")]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
struct DesktopSavedTab {
    url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,
}

#[cfg(feature = "control-server")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct DesktopStartupTab {
    url: String,
    active: bool,
}

#[cfg(all(feature = "control-server", test))]
fn load_desktop_startup_tabs(
    profile_dir: &std::path::Path,
    requested_url: Option<String>,
) -> Vec<DesktopStartupTab> {
    load_desktop_startup_tabs_with_home(profile_dir, requested_url, None)
}

#[cfg(feature = "control-server")]
fn load_desktop_startup_tabs_with_home(
    profile_dir: &std::path::Path,
    requested_url: Option<String>,
    home_url: Option<String>,
) -> Vec<DesktopStartupTab> {
    let snapshot = read_desktop_tab_snapshot(&profile_dir.join(DESKTOP_TABS_FILE));
    let mut tabs = snapshot
        .as_ref()
        .map(desktop_startup_tabs_from_snapshot)
        .unwrap_or_default();

    if let Some(url) = requested_url.and_then(|url| sanitize_desktop_tab_url(&url)) {
        for tab in &mut tabs {
            tab.active = false;
        }
        tabs.push(DesktopStartupTab { url, active: true });
    }

    if tabs.is_empty() {
        tabs.push(DesktopStartupTab {
            url: home_url
                .and_then(|url| sanitize_desktop_tab_url(&url))
                .unwrap_or_else(|| "about:blank".to_string()),
            active: true,
        });
    }

    ensure_one_active_startup_tab(&mut tabs);
    tabs.truncate(MAX_RESTORED_TABS);
    ensure_one_active_startup_tab(&mut tabs);
    tabs
}

#[cfg(all(feature = "control-server", feature = "webview"))]
fn default_home_url() -> Option<String> {
    std::env::var("TELESCOPE_HOME_URL")
        .ok()
        .and_then(|url| sanitize_desktop_tab_url(&url))
}

#[cfg(feature = "control-server")]
fn read_desktop_tab_snapshot(path: &std::path::Path) -> Option<DesktopTabSnapshot> {
    let text = std::fs::read_to_string(path).ok()?;
    let snapshot = serde_json::from_str::<DesktopTabSnapshot>(&text).ok()?;
    (snapshot.version == DESKTOP_TAB_SNAPSHOT_VERSION).then_some(snapshot)
}

#[cfg(feature = "control-server")]
fn desktop_startup_tabs_from_snapshot(snapshot: &DesktopTabSnapshot) -> Vec<DesktopStartupTab> {
    let active_index = snapshot
        .active_index
        .filter(|index| *index < snapshot.tabs.len())
        .unwrap_or(0);
    snapshot
        .tabs
        .iter()
        .enumerate()
        .filter_map(|(original_index, tab)| {
            sanitize_desktop_tab_url(&tab.url).map(|url| DesktopStartupTab {
                url,
                active: original_index == active_index,
            })
        })
        .take(MAX_RESTORED_TABS)
        .collect()
}

#[cfg(feature = "control-server")]
fn ensure_one_active_startup_tab(tabs: &mut [DesktopStartupTab]) {
    if tabs.is_empty() {
        return;
    }

    let active_index = tabs.iter().position(|tab| tab.active).unwrap_or(0);
    for (index, tab) in tabs.iter_mut().enumerate() {
        tab.active = index == active_index;
    }
}

#[cfg(feature = "control-server")]
fn sanitize_desktop_tab_url(url: &str) -> Option<String> {
    let url = url.trim();
    if url == "about:blank" || url.starts_with("http://") || url.starts_with("https://") {
        Some(url.to_string())
    } else {
        None
    }
}

#[cfg(feature = "control-server")]
fn register_desktop_startup_tabs(
    plane: &telescope_control::ControlPlane,
    tabs: &[DesktopStartupTab],
) -> telescope_control::Result<Vec<telescope_control::TabState>> {
    let active_index = tabs.iter().position(|tab| tab.active).unwrap_or(0);
    let mut registered = vec![None; tabs.len()];

    for (index, tab) in tabs.iter().enumerate() {
        if index == active_index {
            continue;
        }
        registered[index] = Some(plane.register_tab(telescope_control::CreateTabRequest {
            url: Some(tab.url.clone()),
            session_id: None,
        })?);
    }

    if let Some(active_tab) = tabs.get(active_index) {
        registered[active_index] =
            Some(plane.register_tab(telescope_control::CreateTabRequest {
                url: Some(active_tab.url.clone()),
                session_id: None,
            })?);
    }

    Ok(registered.into_iter().flatten().collect())
}

#[cfg(feature = "control-server")]
fn save_desktop_tabs_if_changed(
    profile_dir: &std::path::Path,
    plane: &telescope_control::ControlPlane,
    previous_json: &mut Option<String>,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let snapshot = desktop_tab_snapshot(plane)?;
    let json = serde_json::to_string_pretty(&snapshot)?;
    if previous_json.as_deref() == Some(json.as_str()) {
        return Ok(());
    }

    write_private_desktop_file(&profile_dir.join(DESKTOP_TABS_FILE), json.as_bytes())?;
    *previous_json = Some(json);
    Ok(())
}

#[cfg(feature = "control-server")]
fn write_private_desktop_file(
    path: &std::path::Path,
    bytes: &[u8],
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        ensure_private_profile_dir(parent)?;
    }

    let tmp_path = path.with_extension("json.tmp");
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))?;
        std::fs::rename(&tmp_path, path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }

    #[cfg(not(unix))]
    {
        std::fs::write(&tmp_path, bytes)?;
        std::fs::rename(&tmp_path, path)?;
    }

    Ok(())
}

#[cfg(feature = "control-server")]
fn desktop_tab_snapshot(
    plane: &telescope_control::ControlPlane,
) -> telescope_control::Result<DesktopTabSnapshot> {
    let mut tabs = plane.list_tabs()?;
    tabs.sort_by(|left, right| {
        left.created_at_unix
            .cmp(&right.created_at_unix)
            .then_with(|| left.id.cmp(&right.id))
    });
    let active_tab_id = plane.active_tab()?.map(|tab| tab.id);
    let mut saved_tabs = Vec::new();
    let mut active_index = None;

    for tab in tabs {
        let Some(url) = tab
            .current_url
            .as_deref()
            .and_then(sanitize_desktop_tab_url)
        else {
            continue;
        };
        if active_tab_id.as_deref() == Some(tab.id.as_str()) {
            active_index = Some(saved_tabs.len());
        }
        saved_tabs.push(DesktopSavedTab {
            url,
            title: tab.title,
        });
    }

    Ok(DesktopTabSnapshot {
        version: DESKTOP_TAB_SNAPSHOT_VERSION,
        active_index,
        tabs: saved_tabs,
    })
}

#[cfg(feature = "control-server")]
fn chrome_audit_events(
    plane: &telescope_control::ControlPlane,
    limit: usize,
) -> Vec<serde_json::Value> {
    let Ok(mut events) = plane.list_audit_events() else {
        return Vec::new();
    };
    events.reverse();
    events.truncate(limit);
    events.into_iter().map(chrome_audit_event).collect()
}

#[cfg(feature = "control-server")]
fn chrome_audit_event(event: telescope_control::AuditEvent) -> serde_json::Value {
    let (summary, detail) = chrome_audit_event_text(&event.kind);
    serde_json::json!({
        "id": event.id,
        "created_at_unix": event.created_at_unix,
        "summary": summary,
        "detail": detail,
    })
}

#[cfg(feature = "control-server")]
fn chrome_audit_event_text(kind: &telescope_control::AuditEventKind) -> (&'static str, String) {
    use telescope_control::{AuditEventKind, TabHistoryDirection};

    match kind {
        AuditEventKind::SessionCreated {
            allowed_origins,
            allow_credentials,
            allow_interactions,
            allow_scripts,
            ..
        } => (
            "Session created",
            format!(
                "{} origin{}, {}",
                allowed_origins.len(),
                plural_suffix(allowed_origins.len()),
                policy_flags(*allow_credentials, *allow_interactions, *allow_scripts)
            ),
        ),
        AuditEventKind::SessionRevoked {
            revoked_grant_count,
            closed_pane_ids,
            purged_command_ids,
            ..
        } => (
            "Session revoked",
            format!(
                "{} grant{}, {} pane{}, {} command{} purged",
                revoked_grant_count,
                plural_suffix(*revoked_grant_count),
                closed_pane_ids.len(),
                plural_suffix(closed_pane_ids.len()),
                purged_command_ids.len(),
                plural_suffix(purged_command_ids.len())
            ),
        ),
        AuditEventKind::AgentGrantCreated {
            allowed_tab_ids,
            allowed_client_origins,
            ..
        } => (
            "Grant created",
            format!(
                "{} tab{}, {} client{}",
                allowed_tab_ids.len(),
                plural_suffix(allowed_tab_ids.len()),
                allowed_client_origins.len(),
                plural_suffix(allowed_client_origins.len())
            ),
        ),
        AuditEventKind::AgentGrantRevoked {
            closed_pane_ids,
            purged_command_ids,
            ..
        } => (
            "Grant revoked",
            format!(
                "{} pane{}, {} command{} purged",
                closed_pane_ids.len(),
                plural_suffix(closed_pane_ids.len()),
                purged_command_ids.len(),
                plural_suffix(purged_command_ids.len())
            ),
        ),
        AuditEventKind::TabCreated { url, .. } => (
            "Tab opened",
            url.as_deref().unwrap_or("about:blank").to_string(),
        ),
        AuditEventKind::TabActivated { tab_id } => ("Tab activated", tab_id.clone()),
        AuditEventKind::TabNavigated { url, .. } => ("Tab navigated", url.clone()),
        AuditEventKind::TabHistoryNavigationQueued {
            direction, tab_id, ..
        } => {
            let summary = match direction {
                TabHistoryDirection::Back => "Back queued",
                TabHistoryDirection::Forward => "Forward queued",
            };
            (summary, tab_id.clone())
        }
        AuditEventKind::TabReloadQueued { tab_id, .. } => ("Reload queued", tab_id.clone()),
        AuditEventKind::TabClosed {
            tab_id,
            closed_pane_ids,
        } => (
            "Tab closed",
            format!(
                "{tab_id}, {} pane{} closed",
                closed_pane_ids.len(),
                plural_suffix(closed_pane_ids.len())
            ),
        ),
        AuditEventKind::CredentialStored {
            origin, username, ..
        } => (
            "Login saved",
            format!("{username} @ {}", origin.display_url()),
        ),
        AuditEventKind::CredentialDeleted { credential_id } => {
            ("Login forgotten", credential_id.clone())
        }
        AuditEventKind::CredentialFillQueued {
            username,
            target_origin,
            ..
        } => (
            "Login fill queued",
            format!("{username} @ {}", target_origin.display_url()),
        ),
        AuditEventKind::LoginOptionsListed {
            target_origin,
            count,
            ..
        } => (
            "Login options listed",
            format!("{count} for {}", target_origin.display_url()),
        ),
        AuditEventKind::AgentActionQueued {
            action,
            target_origin,
            ..
        } => (
            "Agent action queued",
            format!(
                "{} @ {}",
                agent_action_label(action),
                target_origin.display_url()
            ),
        ),
        AuditEventKind::AgentPaneOpened {
            position,
            scoped_connection,
            ..
        } => (
            "Codex pane opened",
            format!(
                "{position:?}, {}",
                if *scoped_connection {
                    "scoped"
                } else {
                    "unscoped"
                }
            ),
        ),
        AuditEventKind::AgentPaneClosed { pane_id, .. } => ("Codex pane closed", pane_id.clone()),
        AuditEventKind::CommandResultRecorded { status, tab_id, .. } => {
            ("Command result", format!("{status:?} on {tab_id}"))
        }
    }
}

#[cfg(feature = "control-server")]
fn agent_action_label(action: &telescope_control::AgentActionAudit) -> &'static str {
    use telescope_control::AgentActionAudit;

    match action {
        AgentActionAudit::Click { .. } => "click",
        AgentActionAudit::DoubleClick { .. } => "double click",
        AgentActionAudit::DragTo { .. } => "drag",
        AgentActionAudit::Hover { .. } => "hover",
        AgentActionAudit::Focus { .. } => "focus",
        AgentActionAudit::TypeText { .. } => "type",
        AgentActionAudit::SelectOption { .. } => "select",
        AgentActionAudit::SetChecked { .. } => "toggle",
        AgentActionAudit::ScrollBy { .. } => "scroll",
        AgentActionAudit::ScrollIntoView { .. } => "scroll into view",
        AgentActionAudit::PressKey { .. } => "key",
        AgentActionAudit::Submit { .. } => "submit",
        AgentActionAudit::WaitForSelector { .. } => "wait",
        AgentActionAudit::ExtractText { .. } => "extract",
        AgentActionAudit::InspectElement { .. } => "inspect",
        AgentActionAudit::StartElementPicker => "pick element",
        AgentActionAudit::ExecuteScript => "script",
    }
}

#[cfg(feature = "control-server")]
fn policy_flags(allow_credentials: bool, allow_interactions: bool, allow_scripts: bool) -> String {
    let mut flags = Vec::new();
    if allow_credentials {
        flags.push("credentials");
    }
    if allow_interactions {
        flags.push("actions");
    }
    if allow_scripts {
        flags.push("scripts");
    }
    if flags.is_empty() {
        "read-only".to_string()
    } else {
        flags.join(", ")
    }
}

#[cfg(feature = "control-server")]
fn plural_suffix(count: usize) -> &'static str {
    if count == 1 {
        ""
    } else {
        "s"
    }
}

#[cfg(feature = "control-server")]
fn agent_connection_payload(
    control_endpoint: &str,
    pane: &telescope_control::AgentPaneState,
    connection: &telescope_control::AgentPaneConnection,
) -> serde_json::Value {
    serde_json::json!({
        "control_url": control_endpoint,
        "pane_id": pane.id,
        "pane_url": pane.url,
        "session_id": connection.session_id,
        "tab_id": connection.tab_id,
        "grant_token": connection.grant_token,
        "session_policy": connection.session_policy,
        "expires_at_unix": connection.expires_at_unix,
        "api": {
            "page_contexts": "/v1/page-contexts",
            "element_refs": "/v1/element-refs",
            "command_results": "/v1/command-results",
            "navigate": format!("/v1/tabs/{}/navigate", connection.tab_id),
            "tab_actions": format!("/v1/tabs/{}/actions", connection.tab_id),
            "login_options": format!("/v1/tabs/{}/login-options", connection.tab_id),
            "fill_login": format!("/v1/tabs/{}/fill-login", connection.tab_id),
            "close_pane": format!("/v1/agent-panes/{}", pane.id),
        }
    })
}

#[cfg(feature = "control-server")]
fn agent_connection_script_source(payload: &str) -> String {
    let mut script = String::from(
        r#"(function() {
  const connection = "#,
    );
    script.push_str(payload);
    script.push_str(
        r#";
  const frozenConnection = Object.freeze({
    ...connection,
    api: Object.freeze({ ...connection.api })
  });
  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const request = async (path, options = {}) => {
    const headers = {
      ...(options.headers || {}),
      Authorization: `Bearer ${frozenConnection.grant_token}`
    };
    if (options.body !== undefined && headers['Content-Type'] === undefined && headers['content-type'] === undefined) {
      headers['Content-Type'] = 'application/json';
    }
    const response = await fetch(`${frozenConnection.control_url}${path}`, {
      ...options,
      headers
    });
    const text = await response.text();
    let data = null;
    if (text) {
      try {
        data = JSON.parse(text);
      } catch (_error) {
        data = text;
      }
    }
    if (!response.ok) {
      const message = data && typeof data === 'object' && data.error
        ? data.error
        : `${response.status} ${response.statusText}`;
      throw new Error(message);
    }
    return data;
  };
  const postJson = (path, body) => request(path, {
    method: 'POST',
    body: JSON.stringify(body)
  });
  const action = (action) => postJson(frozenConnection.api.tab_actions, {
    session_id: frozenConnection.session_id,
    action
  });
  const navigate = (url) => postJson(frozenConnection.api.navigate, {
    url,
    session_id: frozenConnection.session_id
  });
  const pageContexts = () => request(frozenConnection.api.page_contexts);
  const tabPageContexts = async () => {
    const contexts = await pageContexts();
    return contexts.filter((context) => context.tab_id === frozenConnection.tab_id);
  };
  const currentPageContext = async () => {
    const contexts = await tabPageContexts();
    return contexts.length > 0 ? contexts[0] : null;
  };
  const pageContextMatches = (context, matcher = {}) => {
    if (!context) return false;
    if (matcher.url !== undefined && context.url !== matcher.url) return false;
    if (matcher.urlContains !== undefined && !String(context.url || '').includes(matcher.urlContains)) return false;
    if (matcher.titleContains !== undefined && !String(context.title || '').includes(matcher.titleContains)) return false;
    if (matcher.textContains !== undefined && !String(context.text_preview || '').includes(matcher.textContains)) return false;
    if (matcher.minCapturedAtUnix !== undefined && (context.captured_at_unix || 0) < matcher.minCapturedAtUnix) return false;
    return true;
  };
  const waitForPageContext = async (matcher = {}, options = {}) => {
    const timeoutMs = options.timeoutMs ?? 5000;
    const intervalMs = options.intervalMs ?? 50;
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const context = await currentPageContext();
      if (pageContextMatches(context, matcher)) return context;
      if (Date.now() >= deadline) throw new Error(`timed out waiting for page context on tab ${frozenConnection.tab_id}`);
      await sleep(intervalMs);
    }
  };
  const elementRefs = () => request(frozenConnection.api.element_refs);
  const tabElementRefs = async () => {
    const refs = await elementRefs();
    return refs.filter((reference) => reference.tab_id === frozenConnection.tab_id);
  };
  const commandResults = () => request(frozenConnection.api.command_results);
  const commandResult = async (commandId) => {
    const results = await commandResults();
    return [...results].reverse().find((result) => result.command_id === commandId) || null;
  };
  const waitForCommandResult = async (commandId, options = {}) => {
    const timeoutMs = options.timeoutMs ?? 5000;
    const intervalMs = options.intervalMs ?? 50;
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const result = await commandResult(commandId);
      if (result) return result;
      if (Date.now() >= deadline) throw new Error(`timed out waiting for command result: ${commandId}`);
      await sleep(intervalMs);
    }
  };
  const actionAndWait = async (agentAction, options = {}) => {
    const command = await action(agentAction);
    const result = await waitForCommandResult(command.id, options);
    return { command, result };
  };
  const commandMessage = (result, expectedAction) => {
    if (!result || result.message === undefined || result.message === null) {
      throw new Error(`missing command result message for ${result && result.command_id ? result.command_id : 'unknown command'}`);
    }
    let parsed = null;
    try {
      parsed = typeof result.message === 'string' ? JSON.parse(result.message) : result.message;
    } catch (_error) {
      throw new Error(`invalid command result message for ${result.command_id}: ${result.message}`);
    }
    if (!parsed || typeof parsed !== 'object') {
      throw new Error(`invalid command result message for ${result.command_id}: ${result.message}`);
    }
    if (result.status !== 'succeeded') {
      throw new Error(`${result.command_id}: ${parsed.reason || result.message}`);
    }
    if (parsed.ok === false) {
      throw new Error(`${result.command_id}: ${parsed.reason || result.message}`);
    }
    if (expectedAction && parsed.action !== expectedAction) {
      throw new Error(`expected ${expectedAction} action, got ${parsed.action}`);
    }
    return parsed;
  };
  const requiredMessageField = (message, actionName, fieldName) => {
    if (message[fieldName] === undefined || message[fieldName] === null) {
      throw new Error(`${actionName} result missing ${fieldName}`);
    }
    return message[fieldName];
  };
  const selectorWaitDetails = (result) => {
    const message = commandMessage(result, 'wait_for_selector');
    return {
      selector: requiredMessageField(message, 'wait_for_selector', 'selector'),
      timeoutMs: message.timeoutMs ?? null
    };
  };
  const extractedText = (result) => {
    const message = commandMessage(result, 'extract_text');
    return {
      selector: requiredMessageField(message, 'extract_text', 'selector'),
      text: requiredMessageField(message, 'extract_text', 'text')
    };
  };
  const inspectedElement = (result) => {
    const message = commandMessage(result, 'inspect_element');
    return {
      selector: requiredMessageField(message, 'inspect_element', 'selector'),
      tagName: requiredMessageField(message, 'inspect_element', 'tagName'),
      id: message.id ?? null,
      className: message.className ?? null,
      role: message.role ?? null,
      label: message.label ?? null,
      text: message.text ?? null,
      inputType: message.inputType ?? null,
      disabled: requiredMessageField(message, 'inspect_element', 'disabled'),
      checked: message.checked ?? null,
      selected: message.selected ?? null,
      editable: requiredMessageField(message, 'inspect_element', 'editable'),
      bounds: requiredMessageField(message, 'inspect_element', 'bounds')
    };
  };
  const waitForNextElementRef = async (knownIds = [], options = {}) => {
    const known = knownIds instanceof Set ? knownIds : new Set(knownIds);
    const timeoutMs = options.timeoutMs ?? 30000;
    const intervalMs = options.intervalMs ?? 50;
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const refs = (await tabElementRefs())
        .filter((reference) => !known.has(reference.id))
        .sort((left, right) => {
          const time = (left.created_at_unix ?? 0) - (right.created_at_unix ?? 0);
          if (time !== 0) return time;
          return String(left.id).localeCompare(String(right.id));
        });
      if (refs.length > 0) return refs[0];
      if (Date.now() >= deadline) throw new Error(`timed out waiting for next element reference on tab ${frozenConnection.tab_id}`);
      await sleep(intervalMs);
    }
  };
  const pickElement = async (options = {}) => {
    const knownIds = new Set((await tabElementRefs()).map((reference) => reference.id));
    await action({ type: 'start_element_picker' });
    return waitForNextElementRef(knownIds, options);
  };
  const loginOptions = () => postJson(frozenConnection.api.login_options, {
    session_id: frozenConnection.session_id
  });
  const defaultLogin = async () => {
    const options = await loginOptions();
    if (!Array.isArray(options) || options.length === 0) {
      throw new Error(`no login options for tab ${frozenConnection.tab_id}`);
    }
    return options[0];
  };
  const fillLogin = (credential_id) => postJson(frozenConnection.api.fill_login, {
    session_id: frozenConnection.session_id,
    credential_id
  });
  const fillDefaultLogin = async () => {
    const credential = await defaultLogin();
    return fillLogin(credential.id);
  };
  const navigateAndWait = async (url, options = {}) => {
    const tab = await navigate(url);
    const context = await waitForUrl(url, options);
    return { tab, context };
  };
  const helper = Object.freeze({
    connection: frozenConnection,
    request,
    pageContexts,
    tabPageContexts,
    currentPageContext,
    waitForPageContext,
    waitForUrl: (url, options = {}) => waitForPageContext({ url }, options),
    waitForUrlContains: (urlContains, options = {}) => waitForPageContext({ urlContains }, options),
    waitForTitleContains: (titleContains, options = {}) => waitForPageContext({ titleContains }, options),
    waitForTextContains: (textContains, options = {}) => waitForPageContext({ textContains }, options),
    navigate,
    navigateAndWait,
    elementRefs,
    tabElementRefs,
    commandResults,
    commandResult,
    waitForCommandResult,
    actionAndWait,
    waitForNextElementRef,
    action,
    click: (selector) => action({ type: 'click', selector, element_ref_id: null }),
    clickAndWait: (selector, options = {}) => actionAndWait({
      type: 'click',
      selector,
      element_ref_id: null
    }, options),
    clickRef: (element_ref_id) => action({ type: 'click', selector: null, element_ref_id }),
    clickRefAndWait: (element_ref_id, options = {}) => actionAndWait({
      type: 'click',
      selector: null,
      element_ref_id
    }, options),
    doubleClick: (selector) => action({ type: 'double_click', selector, element_ref_id: null }),
    doubleClickAndWait: (selector, options = {}) => actionAndWait({
      type: 'double_click',
      selector,
      element_ref_id: null
    }, options),
    doubleClickRef: (element_ref_id) => action({ type: 'double_click', selector: null, element_ref_id }),
    doubleClickRefAndWait: (element_ref_id, options = {}) => actionAndWait({
      type: 'double_click',
      selector: null,
      element_ref_id
    }, options),
    dragTo: (source_selector, target_selector) => action({
      type: 'drag_to',
      source_selector,
      source_element_ref_id: null,
      target_selector,
      target_element_ref_id: null
    }),
    dragToAndWait: (source_selector, target_selector, options = {}) => actionAndWait({
      type: 'drag_to',
      source_selector,
      source_element_ref_id: null,
      target_selector,
      target_element_ref_id: null
    }, options),
    dragRefToRef: (source_element_ref_id, target_element_ref_id) => action({
      type: 'drag_to',
      source_selector: null,
      source_element_ref_id,
      target_selector: null,
      target_element_ref_id
    }),
    dragRefToRefAndWait: (source_element_ref_id, target_element_ref_id, options = {}) => actionAndWait({
      type: 'drag_to',
      source_selector: null,
      source_element_ref_id,
      target_selector: null,
      target_element_ref_id
    }, options),
    hover: (selector) => action({ type: 'hover', selector, element_ref_id: null }),
    hoverAndWait: (selector, options = {}) => actionAndWait({
      type: 'hover',
      selector,
      element_ref_id: null
    }, options),
    hoverRef: (element_ref_id) => action({ type: 'hover', selector: null, element_ref_id }),
    hoverRefAndWait: (element_ref_id, options = {}) => actionAndWait({
      type: 'hover',
      selector: null,
      element_ref_id
    }, options),
    focus: (selector) => action({ type: 'focus', selector, element_ref_id: null }),
    focusAndWait: (selector, options = {}) => actionAndWait({
      type: 'focus',
      selector,
      element_ref_id: null
    }, options),
    focusRef: (element_ref_id) => action({ type: 'focus', selector: null, element_ref_id }),
    focusRefAndWait: (element_ref_id, options = {}) => actionAndWait({
      type: 'focus',
      selector: null,
      element_ref_id
    }, options),
    typeText: (selector, text, clear_first = false) => action({
      type: 'type_text',
      selector,
      element_ref_id: null,
      text,
      clear_first
    }),
    typeTextAndWait: (selector, text, clear_first = false, options = {}) => actionAndWait({
      type: 'type_text',
      selector,
      element_ref_id: null,
      text,
      clear_first
    }, options),
    typeTextRef: (element_ref_id, text, clear_first = false) => action({
      type: 'type_text',
      selector: null,
      element_ref_id,
      text,
      clear_first
    }),
    typeTextRefAndWait: (element_ref_id, text, clear_first = false, options = {}) => actionAndWait({
      type: 'type_text',
      selector: null,
      element_ref_id,
      text,
      clear_first
    }, options),
    selectOption: (selector, value) => action({
      type: 'select_option',
      selector,
      element_ref_id: null,
      value
    }),
    selectOptionAndWait: (selector, value, options = {}) => actionAndWait({
      type: 'select_option',
      selector,
      element_ref_id: null,
      value
    }, options),
    selectOptionRef: (element_ref_id, value) => action({
      type: 'select_option',
      selector: null,
      element_ref_id,
      value
    }),
    selectOptionRefAndWait: (element_ref_id, value, options = {}) => actionAndWait({
      type: 'select_option',
      selector: null,
      element_ref_id,
      value
    }, options),
    setChecked: (selector, checked) => action({
      type: 'set_checked',
      selector,
      element_ref_id: null,
      checked
    }),
    setCheckedAndWait: (selector, checked, options = {}) => actionAndWait({
      type: 'set_checked',
      selector,
      element_ref_id: null,
      checked
    }, options),
    setCheckedRef: (element_ref_id, checked) => action({
      type: 'set_checked',
      selector: null,
      element_ref_id,
      checked
    }),
    setCheckedRefAndWait: (element_ref_id, checked, options = {}) => actionAndWait({
      type: 'set_checked',
      selector: null,
      element_ref_id,
      checked
    }, options),
    scrollBy: (delta_x, delta_y) => action({ type: 'scroll_by', delta_x, delta_y }),
    scrollByAndWait: (delta_x, delta_y, options = {}) => actionAndWait({
      type: 'scroll_by',
      delta_x,
      delta_y
    }, options),
    scrollIntoView: (selector) => action({
      type: 'scroll_into_view',
      selector,
      element_ref_id: null
    }),
    scrollIntoViewAndWait: (selector, options = {}) => actionAndWait({
      type: 'scroll_into_view',
      selector,
      element_ref_id: null
    }, options),
    scrollRefIntoView: (element_ref_id) => action({
      type: 'scroll_into_view',
      selector: null,
      element_ref_id
    }),
    scrollRefIntoViewAndWait: (element_ref_id, options = {}) => actionAndWait({
      type: 'scroll_into_view',
      selector: null,
      element_ref_id
    }, options),
    pressKey: (key) => action({ type: 'press_key', key }),
    pressKeyAndWait: (key, options = {}) => actionAndWait({ type: 'press_key', key }, options),
    submit: (selector) => action({ type: 'submit', selector, element_ref_id: null }),
    submitAndWait: (selector, options = {}) => actionAndWait({
      type: 'submit',
      selector,
      element_ref_id: null
    }, options),
    submitRef: (element_ref_id) => action({ type: 'submit', selector: null, element_ref_id }),
    submitRefAndWait: (element_ref_id, options = {}) => actionAndWait({
      type: 'submit',
      selector: null,
      element_ref_id
    }, options),
    waitForSelector: (selector, timeout_ms = null) => action({
      type: 'wait_for_selector',
      selector,
      timeout_ms
    }),
    waitForSelectorResult: (selector, timeout_ms = null, options = {}) => actionAndWait({
      type: 'wait_for_selector',
      selector,
      timeout_ms
    }, options),
    waitForSelectorDetails: async (selector, timeout_ms = null, options = {}) => {
      const { result } = await actionAndWait({
        type: 'wait_for_selector',
        selector,
        timeout_ms
      }, options);
      return selectorWaitDetails(result);
    },
    extractText: (selector) => action({ type: 'extract_text', selector, element_ref_id: null }),
    extractTextAndWait: (selector, options = {}) => actionAndWait({
      type: 'extract_text',
      selector,
      element_ref_id: null
    }, options),
    extractTextResult: async (selector, options = {}) => {
      const { result } = await actionAndWait({
        type: 'extract_text',
        selector,
        element_ref_id: null
      }, options);
      return extractedText(result);
    },
    extractTextRef: (element_ref_id) => action({ type: 'extract_text', selector: null, element_ref_id }),
    extractTextRefAndWait: (element_ref_id, options = {}) => actionAndWait({
      type: 'extract_text',
      selector: null,
      element_ref_id
    }, options),
    extractTextRefResult: async (element_ref_id, options = {}) => {
      const { result } = await actionAndWait({
        type: 'extract_text',
        selector: null,
        element_ref_id
      }, options);
      return extractedText(result);
    },
    inspectElement: (selector) => action({ type: 'inspect_element', selector, element_ref_id: null }),
    inspectElementAndWait: (selector, options = {}) => actionAndWait({
      type: 'inspect_element',
      selector,
      element_ref_id: null
    }, options),
    inspectElementDetails: async (selector, options = {}) => {
      const { result } = await actionAndWait({
        type: 'inspect_element',
        selector,
        element_ref_id: null
      }, options);
      return inspectedElement(result);
    },
    inspectElementRef: (element_ref_id) => action({ type: 'inspect_element', selector: null, element_ref_id }),
    inspectElementRefAndWait: (element_ref_id, options = {}) => actionAndWait({
      type: 'inspect_element',
      selector: null,
      element_ref_id
    }, options),
    inspectElementRefDetails: async (element_ref_id, options = {}) => {
      const { result } = await actionAndWait({
        type: 'inspect_element',
        selector: null,
        element_ref_id
      }, options);
      return inspectedElement(result);
    },
    startElementPicker: () => action({ type: 'start_element_picker' }),
    pickElement,
    loginOptions,
    defaultLogin,
    fillLogin,
    fillDefaultLogin,
    fillLoginAndWait: async (credential_id, options = {}) => {
      const command = await fillLogin(credential_id);
      const result = await waitForCommandResult(command.id, options);
      return { command, result };
    },
    fillDefaultLoginAndWait: async (options = {}) => {
      const command = await fillDefaultLogin();
      const result = await waitForCommandResult(command.id, options);
      return { command, result };
    },
    closePane: () => request(frozenConnection.api.close_pane, { method: 'DELETE' })
  });
  Object.defineProperty(window, '__TELESCOPE_AGENT_CONNECTION', {
    value: frozenConnection,
    enumerable: false,
    configurable: false,
    writable: false
  });
  Object.defineProperty(window, '__TELESCOPE_AGENT', {
    value: helper,
    enumerable: false,
    configurable: false,
    writable: false
  });
  if (!Object.prototype.hasOwnProperty.call(window, 'telescope')) {
    Object.defineProperty(window, 'telescope', {
      value: helper,
      enumerable: false,
      configurable: false,
      writable: false
    });
  }
  window.dispatchEvent(new CustomEvent('telescope:agent-connection', { detail: frozenConnection }));
})();"#,
    );
    script
}

#[cfg(feature = "control-server")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WorkspaceSurface {
    width: u32,
    height: u32,
}

#[cfg(feature = "control-server")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WorkspaceRect {
    x: u32,
    y: u32,
    width: u32,
    height: u32,
}

#[cfg(feature = "control-server")]
impl From<WorkspaceSurface> for WorkspaceRect {
    fn from(surface: WorkspaceSurface) -> Self {
        Self {
            x: 0,
            y: 0,
            width: surface.width,
            height: surface.height,
        }
    }
}

#[cfg(feature = "control-server")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct PaneLayoutInput {
    id: String,
    position: telescope_control::PanePosition,
}

#[cfg(feature = "control-server")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct PaneLayout {
    id: String,
    position: telescope_control::PanePosition,
    bounds: WorkspaceRect,
}

#[cfg(feature = "control-server")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct WorkspaceLayout {
    browser: WorkspaceRect,
    panes: Vec<PaneLayout>,
}

#[cfg(feature = "control-server")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct DesktopLayout {
    chrome: WorkspaceRect,
    workspace: WorkspaceLayout,
}

#[cfg(feature = "control-server")]
impl WorkspaceLayout {
    fn pane_bounds(&self, pane_id: &str) -> Option<WorkspaceRect> {
        self.panes
            .iter()
            .find(|pane| pane.id == pane_id)
            .map(|pane| pane.bounds)
    }
}

#[cfg(feature = "control-server")]
fn compute_desktop_layout(surface: WorkspaceSurface, panes: Vec<PaneLayoutInput>) -> DesktopLayout {
    let chrome_height = surface.height.min(BROWSER_CHROME_HEIGHT);
    let chrome = WorkspaceRect {
        x: 0,
        y: 0,
        width: surface.width,
        height: chrome_height,
    };
    let mut workspace = compute_workspace_layout(
        WorkspaceSurface {
            width: surface.width,
            height: surface.height.saturating_sub(chrome_height),
        },
        panes,
    );
    offset_workspace_layout(&mut workspace, 0, chrome_height);

    DesktopLayout { chrome, workspace }
}

#[cfg(feature = "control-server")]
fn offset_workspace_layout(layout: &mut WorkspaceLayout, x: u32, y: u32) {
    layout.browser = offset_rect(layout.browser, x, y);
    for pane in &mut layout.panes {
        pane.bounds = offset_rect(pane.bounds, x, y);
    }
}

#[cfg(feature = "control-server")]
fn offset_rect(rect: WorkspaceRect, x: u32, y: u32) -> WorkspaceRect {
    WorkspaceRect {
        x: rect.x + x,
        y: rect.y + y,
        width: rect.width,
        height: rect.height,
    }
}

#[cfg(feature = "control-server")]
fn compute_workspace_layout(
    surface: WorkspaceSurface,
    panes: Vec<PaneLayoutInput>,
) -> WorkspaceLayout {
    use telescope_control::PanePosition;

    const MAX_SIDE_WIDTH: u32 = 480;
    const MAX_BOTTOM_HEIGHT: u32 = 420;

    let left_count = panes
        .iter()
        .filter(|pane| pane.position == PanePosition::Left)
        .count() as u32;
    let right_count = panes
        .iter()
        .filter(|pane| pane.position == PanePosition::Right)
        .count() as u32;
    let bottom_count = panes
        .iter()
        .filter(|pane| pane.position == PanePosition::Bottom)
        .count() as u32;

    let side_edges = u32::from(left_count > 0) + u32::from(right_count > 0);
    let side_width = if side_edges == 0 || surface.width == 0 {
        0
    } else {
        (surface.width / (side_edges + 1)).min(MAX_SIDE_WIDTH)
    };
    let bottom_height = if bottom_count == 0 || surface.height == 0 {
        0
    } else {
        (surface.height / 3).min(MAX_BOTTOM_HEIGHT)
    };

    let left_width = if left_count > 0 { side_width } else { 0 };
    let right_width = if right_count > 0 { side_width } else { 0 };
    let browser_width = surface
        .width
        .saturating_sub(left_width)
        .saturating_sub(right_width);
    let browser_height = surface.height.saturating_sub(bottom_height);
    let browser = WorkspaceRect {
        x: left_width,
        y: 0,
        width: browser_width,
        height: browser_height,
    };

    let mut left_index = 0;
    let mut right_index = 0;
    let mut bottom_index = 0;
    let mut pane_layouts = Vec::with_capacity(panes.len());

    for pane in panes {
        let bounds = match pane.position {
            PanePosition::Left => {
                let bounds =
                    split_vertical(0, 0, left_width, browser_height, left_count, left_index);
                left_index += 1;
                bounds
            }
            PanePosition::Right => {
                let bounds = split_vertical(
                    surface.width.saturating_sub(right_width),
                    0,
                    right_width,
                    browser_height,
                    right_count,
                    right_index,
                );
                right_index += 1;
                bounds
            }
            PanePosition::Bottom => {
                let bounds = split_horizontal(
                    0,
                    browser_height,
                    surface.width,
                    bottom_height,
                    bottom_count,
                    bottom_index,
                );
                bottom_index += 1;
                bounds
            }
        };

        pane_layouts.push(PaneLayout {
            id: pane.id,
            position: pane.position,
            bounds,
        });
    }

    WorkspaceLayout {
        browser,
        panes: pane_layouts,
    }
}

#[cfg(feature = "control-server")]
fn split_vertical(
    x: u32,
    y: u32,
    width: u32,
    height: u32,
    count: u32,
    index: u32,
) -> WorkspaceRect {
    if count == 0 {
        return WorkspaceRect {
            x,
            y,
            width,
            height: 0,
        };
    }

    let start = scale_axis(height, index, count);
    let end = scale_axis(height, index + 1, count);
    WorkspaceRect {
        x,
        y: y + start,
        width,
        height: end.saturating_sub(start),
    }
}

#[cfg(feature = "control-server")]
fn split_horizontal(
    x: u32,
    y: u32,
    width: u32,
    height: u32,
    count: u32,
    index: u32,
) -> WorkspaceRect {
    if count == 0 {
        return WorkspaceRect {
            x,
            y,
            width: 0,
            height,
        };
    }

    let start = scale_axis(width, index, count);
    let end = scale_axis(width, index + 1, count);
    WorkspaceRect {
        x: x + start,
        y,
        width: end.saturating_sub(start),
        height,
    }
}

#[cfg(feature = "control-server")]
fn scale_axis(total: u32, index: u32, count: u32) -> u32 {
    ((total as u64 * index as u64) / count as u64) as u32
}

#[cfg(feature = "webview")]
struct DesktopWorkspaceHost {
    #[cfg(target_os = "linux")]
    fixed: gtk::Fixed,
}

#[cfg(feature = "webview")]
impl DesktopWorkspaceHost {
    fn new(window: &tao::window::Window) -> Result<Self, Box<dyn std::error::Error>> {
        #[cfg(target_os = "linux")]
        {
            use gtk::prelude::*;
            use tao::platform::unix::WindowExtUnix;

            let fixed = gtk::Fixed::new();
            fixed.show_all();
            let vbox = window
                .default_vbox()
                .ok_or("telescope linux window did not create a default GTK box")?;
            vbox.pack_start(&fixed, true, true, 0);
            Ok(Self { fixed })
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = window;
            Ok(Self {})
        }
    }
}

#[cfg(feature = "webview")]
fn workspace_surface(size: tao::dpi::PhysicalSize<u32>) -> WorkspaceSurface {
    WorkspaceSurface {
        width: size.width,
        height: size.height,
    }
}

#[cfg(feature = "webview")]
fn workspace_rect_to_wry(bounds: WorkspaceRect) -> wry::Rect {
    wry::Rect {
        position: wry::dpi::LogicalPosition::new(bounds.x, bounds.y).into(),
        size: wry::dpi::LogicalSize::new(bounds.width, bounds.height).into(),
    }
}

#[cfg(feature = "webview")]
fn build_workspace_webview(
    builder: wry::WebViewBuilder<'_>,
    window: &tao::window::Window,
    host: &DesktopWorkspaceHost,
    bounds: WorkspaceRect,
) -> wry::Result<wry::WebView> {
    let builder = builder.with_bounds(workspace_rect_to_wry(bounds));

    #[cfg(target_os = "linux")]
    {
        let _ = window;
        use wry::WebViewBuilderExtUnix;
        builder.build_gtk(&host.fixed)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = host;
        builder.build_as_child(window)
    }
}

#[cfg(feature = "webview")]
fn profile_dir(profile: &str) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let dirs = directories::ProjectDirs::from("dev", "Telescope", "Telescope")
        .ok_or("could not resolve platform data directory")?;
    Ok(dirs.data_dir().join("profiles").join(profile))
}

#[cfg(all(feature = "control-server", feature = "webview"))]
fn start_control_server(
    profile_dir: &std::path::Path,
    plane: telescope_control::ControlPlane,
) -> Result<String, Box<dyn std::error::Error>> {
    let bind_addr = std::env::var("TELESCOPE_ADDR").unwrap_or_else(|_| "127.0.0.1:0".to_string());
    let owner_token =
        std::env::var("TELESCOPE_TOKEN").unwrap_or_else(|_| uuid::Uuid::new_v4().to_string());
    let server = tiny_http::Server::http(&bind_addr).map_err(|error| {
        std::io::Error::other(format!(
            "failed to bind telescope control server at {bind_addr}: {error}"
        ))
    })?;
    let actual_addr = server
        .server_addr()
        .to_ip()
        .ok_or("telescope control server did not bind to an IP socket")?;
    let endpoint = format!("http://{actual_addr}");

    write_control_file(profile_dir, &endpoint, &owner_token)?;
    eprintln!("telescope control: {endpoint}");
    eprintln!("TELESCOPE_TOKEN={owner_token}");

    std::thread::spawn(move || {
        if let Err(error) = telescope_control::serve_server(server, owner_token, plane) {
            eprintln!("telescope control server stopped: {error}");
        }
    });
    Ok(endpoint)
}

#[cfg(feature = "control-server")]
const DEFAULT_SEARCH_URL: &str = "https://duckduckgo.com/?q={query}";

#[cfg(all(feature = "control-server", feature = "webview"))]
fn normalize_chrome_url(input: &str) -> Option<String> {
    let input = input.trim();
    if input.is_empty() {
        return None;
    }
    if input == "about:blank" || input.starts_with("http://") || input.starts_with("https://") {
        return Some(input.to_string());
    }
    Some(format!("https://{input}"))
}

#[cfg(all(feature = "control-server", feature = "webview"))]
fn default_codex_url() -> Option<String> {
    std::env::var("TELESCOPE_CODEX_URL")
        .ok()
        .and_then(|url| normalize_codex_url(&url))
}

#[cfg(all(feature = "control-server", feature = "webview"))]
fn default_cli_command() -> String {
    std::env::var("TELESCOPE_AGENT_CLI")
        .ok()
        .and_then(|command| sanitize_cli_command(&command))
        .unwrap_or_else(|| "codex".to_string())
}

#[cfg(feature = "control-server")]
fn sanitize_cli_command(input: &str) -> Option<String> {
    let input = input.trim();
    if input.is_empty()
        || input.len() > 512
        || input.chars().any(|ch| matches!(ch, '\r' | '\n'))
    {
        return None;
    }
    Some(input.to_string())
}

#[cfg(feature = "control-server")]
fn normalize_codex_url(input: &str) -> Option<String> {
    let input = input.trim();
    if input.is_empty() || input == "about:blank" || input.chars().any(char::is_whitespace) {
        return None;
    }
    if input.starts_with("http://") || input.starts_with("https://") {
        return Some(input.to_string());
    }
    if has_unsupported_scheme(input) {
        return None;
    }
    Some(format!("https://{input}"))
}

#[cfg(all(feature = "control-server", feature = "webview"))]
fn normalize_chrome_address(input: &str) -> Option<String> {
    let search_template =
        std::env::var("TELESCOPE_SEARCH_URL").unwrap_or_else(|_| DEFAULT_SEARCH_URL.to_string());
    normalize_chrome_address_with_template(input, &search_template)
}

#[cfg(feature = "control-server")]
fn normalize_chrome_address_with_template(input: &str, search_template: &str) -> Option<String> {
    let input = input.trim();
    if input.is_empty() {
        return None;
    }
    if input == "about:blank" || input.starts_with("http://") || input.starts_with("https://") {
        return Some(input.to_string());
    }
    if input.chars().any(char::is_whitespace) {
        return Some(search_url(input, search_template));
    }
    if has_unsupported_scheme(input) {
        return None;
    }
    if looks_like_host(input) {
        let scheme = if looks_like_local_host(input) {
            "http"
        } else {
            "https"
        };
        return Some(format!("{scheme}://{input}"));
    }

    Some(search_url(input, search_template))
}

#[cfg(feature = "control-server")]
fn has_unsupported_scheme(input: &str) -> bool {
    let Some(index) = input.find(':') else {
        return false;
    };
    if input[..index].eq_ignore_ascii_case("localhost") {
        return false;
    }
    let before_colon = &input[..index];
    !before_colon.is_empty()
        && !before_colon.contains('.')
        && before_colon
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_alphabetic())
        && before_colon
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '-' | '.'))
}

#[cfg(feature = "control-server")]
fn looks_like_host(input: &str) -> bool {
    if input.chars().any(char::is_whitespace) {
        return false;
    }
    input.contains('.')
        || input.contains(':')
        || input.eq_ignore_ascii_case("localhost")
        || input.to_ascii_lowercase().starts_with("localhost/")
}

#[cfg(feature = "control-server")]
fn looks_like_local_host(input: &str) -> bool {
    let input = input.to_ascii_lowercase();
    input == "localhost"
        || input.starts_with("localhost/")
        || input.starts_with("localhost:")
        || input.starts_with("127.")
        || input.starts_with("[::1]")
        || input.starts_with("[0:0:0:0:0:0:0:1]")
}

#[cfg(feature = "control-server")]
fn search_url(query: &str, template: &str) -> String {
    let encoded = encode_search_query(query);
    if template.contains("{query}") {
        return template.replace("{query}", &encoded);
    }
    let separator = if template.contains('?') { '&' } else { '?' };
    format!("{template}{separator}q={encoded}")
}

#[cfg(feature = "control-server")]
fn encode_search_query(query: &str) -> String {
    let mut encoded = String::new();
    for byte in query.as_bytes() {
        match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(*byte as char)
            }
            b' ' => encoded.push('+'),
            byte => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

#[cfg(feature = "control-server")]
fn write_control_file(
    profile_dir: &std::path::Path,
    endpoint: &str,
    owner_token: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    ensure_private_profile_dir(profile_dir)?;
    let path = profile_dir.join("control.json");
    let body = serde_json::to_vec_pretty(&serde_json::json!({
        "url": endpoint,
        "owner_token": owner_token,
        "warning": "Owner token. Use create_agent_grant before handing control to Codex or another agent."
    }))?;

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(&body)?;
        file.sync_all()?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }

    #[cfg(not(unix))]
    {
        std::fs::write(path, body)?;
    }

    Ok(())
}

#[cfg(feature = "control-server")]
fn ensure_private_profile_dir(
    profile_dir: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(profile_dir)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(profile_dir, std::fs::Permissions::from_mode(0o700))?;
    }

    Ok(())
}

#[cfg(feature = "control-server")]
fn chrome_agent_permissions(value: &serde_json::Value) -> (bool, bool, bool) {
    if json_bool(value, "read_only", false) {
        return (false, false, false);
    }

    (
        json_bool(value, "allow_credentials", true),
        json_bool(value, "allow_interactions", true),
        json_bool(value, "allow_scripts", false),
    )
}

#[cfg(feature = "control-server")]
fn json_bool(value: &serde_json::Value, key: &str, default: bool) -> bool {
    value
        .get(key)
        .and_then(|item| item.as_bool())
        .unwrap_or(default)
}

#[cfg(feature = "control-server")]
fn bookmark_tab_from_chrome(
    plane: &telescope_control::ControlPlane,
    tab_id: &str,
) -> telescope_control::Result<telescope_control::BookmarkRecord> {
    let tab = plane
        .list_tabs()?
        .into_iter()
        .find(|tab| tab.id == tab_id)
        .ok_or_else(|| telescope_control::ControlError::NotFound(format!("tab {tab_id}")))?;
    let url = tab
        .current_url
        .ok_or_else(|| telescope_control::ControlError::BadRequest("tab has no URL".to_string()))?;
    plane.create_bookmark(telescope_control::CreateBookmarkRequest {
        url,
        title: tab.title,
    })
}

#[cfg(feature = "control-server")]
fn stop_agent_pane_from_chrome(
    plane: &telescope_control::ControlPlane,
    pane_id: &str,
) -> telescope_control::Result<()> {
    if let Ok(connection) = plane.agent_pane_connection(pane_id) {
        plane.revoke_agent_grant(&connection.grant_token)?;
    } else {
        plane.close_agent_pane(pane_id)?;
    }
    Ok(())
}

#[cfg(all(feature = "control-server", feature = "webview"))]
fn desktop_shortcut_modifiers(
    modifiers: tao::keyboard::ModifiersState,
) -> DesktopShortcutModifiers {
    DesktopShortcutModifiers {
        ctrl: modifiers.control_key(),
        meta: modifiers.super_key(),
        alt: modifiers.alt_key(),
        shift: modifiers.shift_key(),
    }
}

#[cfg(all(feature = "control-server", feature = "webview"))]
fn desktop_shortcut_key_for_event(event: &tao::event::KeyEvent) -> Option<DesktopShortcutKey> {
    match event.physical_key {
        tao::keyboard::KeyCode::KeyL => Some(DesktopShortcutKey::L),
        tao::keyboard::KeyCode::KeyR => Some(DesktopShortcutKey::R),
        tao::keyboard::KeyCode::KeyT => Some(DesktopShortcutKey::T),
        tao::keyboard::KeyCode::KeyW => Some(DesktopShortcutKey::W),
        tao::keyboard::KeyCode::F5 => Some(DesktopShortcutKey::F5),
        tao::keyboard::KeyCode::ArrowLeft => Some(DesktopShortcutKey::ArrowLeft),
        tao::keyboard::KeyCode::ArrowRight => Some(DesktopShortcutKey::ArrowRight),
        _ => None,
    }
}

#[cfg(all(feature = "control-server", feature = "webview"))]
fn run_desktop_shortcut(
    shortcut: DesktopShortcut,
    plane: &telescope_control::ControlPlane,
    active_tab_id: &str,
    chrome_webview: &wry::WebView,
) -> Result<(), String> {
    match shortcut {
        DesktopShortcut::FocusAddress => focus_chrome_address(chrome_webview),
        DesktopShortcut::NewTab => plane
            .create_tab(telescope_control::CreateTabRequest {
                url: None,
                session_id: None,
            })
            .map(|_| ())
            .map_err(|error| error.to_string()),
        DesktopShortcut::CloseTab => plane
            .close_tab(active_tab_id)
            .map(|_| ())
            .map_err(|error| error.to_string()),
        DesktopShortcut::Back => plane
            .go_back(active_tab_id)
            .map(|_| ())
            .map_err(|error| error.to_string()),
        DesktopShortcut::Forward => plane
            .go_forward(active_tab_id)
            .map(|_| ())
            .map_err(|error| error.to_string()),
        DesktopShortcut::Reload => plane
            .reload_tab(active_tab_id)
            .map(|_| ())
            .map_err(|error| error.to_string()),
    }
}

#[cfg(all(feature = "control-server", feature = "webview"))]
fn focus_chrome_address(chrome_webview: &wry::WebView) -> Result<(), String> {
    chrome_webview.focus().map_err(|error| error.to_string())?;
    chrome_webview
        .evaluate_script(
            r#"{
  const address = document.getElementById('address');
  if (address) {
    address.focus();
    address.select();
  }
}"#,
        )
        .map_err(|error| error.to_string())
}

#[cfg(all(test, feature = "control-server"))]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use telescope_control::{
        AgentPaneConnection, AgentPaneState, BrowserCommandKind, ControlPlane,
        CreateAgentGrantRequest, CreateSessionRequest, CreateTabRequest, NavigateRequest,
        OpenAgentPaneRequest, PanePosition,
    };
    use telescope_core::{CredentialVault, MemorySecretStore};

    #[test]
    fn writes_desktop_control_file() {
        let mut dir = std::env::temp_dir();
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        dir.push(format!("telescope-desktop-{nonce}"));
        std::fs::create_dir_all(&dir).unwrap();

        write_control_file(&dir, "http://127.0.0.1:12345", "owner-token").unwrap();

        let path = dir.join("control.json");
        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(value["url"], "http://127.0.0.1:12345");
        assert_eq!(value["owner_token"], "owner-token");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn chrome_address_accepts_urls_and_hostnames() {
        assert_eq!(
            normalize_chrome_address_with_template(
                " https://example.com/path ",
                DEFAULT_SEARCH_URL
            )
            .as_deref(),
            Some("https://example.com/path")
        );
        assert_eq!(
            normalize_chrome_address_with_template("example.com", DEFAULT_SEARCH_URL).as_deref(),
            Some("https://example.com")
        );
        assert_eq!(
            normalize_chrome_address_with_template("example.com:8443/path", DEFAULT_SEARCH_URL)
                .as_deref(),
            Some("https://example.com:8443/path")
        );
        assert_eq!(
            normalize_chrome_address_with_template("localhost:3000", DEFAULT_SEARCH_URL).as_deref(),
            Some("http://localhost:3000")
        );
        assert_eq!(
            normalize_chrome_address_with_template("127.0.0.1:3000", DEFAULT_SEARCH_URL).as_deref(),
            Some("http://127.0.0.1:3000")
        );
    }

    #[test]
    fn chrome_address_searches_plain_text() {
        assert_eq!(
            normalize_chrome_address_with_template("openai codex docs", DEFAULT_SEARCH_URL)
                .as_deref(),
            Some("https://duckduckgo.com/?q=openai+codex+docs")
        );
        assert_eq!(
            normalize_chrome_address_with_template("rust: trait object", DEFAULT_SEARCH_URL)
                .as_deref(),
            Some("https://duckduckgo.com/?q=rust%3A+trait+object")
        );
        assert_eq!(
            normalize_chrome_address_with_template(
                "rust ownership?",
                "https://search.example/s?q={query}"
            )
            .as_deref(),
            Some("https://search.example/s?q=rust+ownership%3F")
        );
        assert_eq!(
            normalize_chrome_address_with_template("telescope", "https://search.example")
                .as_deref(),
            Some("https://search.example?q=telescope")
        );
    }

    #[test]
    fn chrome_address_rejects_unsafe_schemes() {
        assert!(
            normalize_chrome_address_with_template("javascript:alert(1)", DEFAULT_SEARCH_URL)
                .is_none()
        );
        assert!(normalize_chrome_address_with_template(
            "data:text/html,blocked",
            DEFAULT_SEARCH_URL
        )
        .is_none());
        assert_eq!(
            normalize_chrome_address_with_template("about:blank", DEFAULT_SEARCH_URL).as_deref(),
            Some("about:blank")
        );
    }

    #[test]
    fn codex_url_default_accepts_web_urls_and_hosts_only() {
        assert_eq!(
            normalize_codex_url(" https://codex.example/login ").as_deref(),
            Some("https://codex.example/login")
        );
        assert_eq!(
            normalize_codex_url("codex.example/login").as_deref(),
            Some("https://codex.example/login")
        );
        assert!(normalize_codex_url("javascript:alert(1)").is_none());
        assert!(normalize_codex_url("data:text/html,blocked").is_none());
        assert!(normalize_codex_url("codex example").is_none());
        assert!(normalize_codex_url("about:blank").is_none());
    }

    #[test]
    fn desktop_shortcuts_map_common_browser_commands() {
        let command = DesktopShortcutModifiers {
            ctrl: true,
            ..DesktopShortcutModifiers::default()
        };
        let meta = DesktopShortcutModifiers {
            meta: true,
            ..DesktopShortcutModifiers::default()
        };
        let alt = DesktopShortcutModifiers {
            alt: true,
            ..DesktopShortcutModifiers::default()
        };

        assert_eq!(
            desktop_shortcut_for_key(command, DesktopShortcutKey::L),
            Some(DesktopShortcut::FocusAddress)
        );
        assert_eq!(
            desktop_shortcut_for_key(meta, DesktopShortcutKey::T),
            Some(DesktopShortcut::NewTab)
        );
        assert_eq!(
            desktop_shortcut_for_key(command, DesktopShortcutKey::W),
            Some(DesktopShortcut::CloseTab)
        );
        assert_eq!(
            desktop_shortcut_for_key(command, DesktopShortcutKey::R),
            Some(DesktopShortcut::Reload)
        );
        assert_eq!(
            desktop_shortcut_for_key(DesktopShortcutModifiers::default(), DesktopShortcutKey::F5),
            Some(DesktopShortcut::Reload)
        );
        assert_eq!(
            desktop_shortcut_for_key(alt, DesktopShortcutKey::ArrowLeft),
            Some(DesktopShortcut::Back)
        );
        assert_eq!(
            desktop_shortcut_for_key(alt, DesktopShortcutKey::ArrowRight),
            Some(DesktopShortcut::Forward)
        );
    }

    #[test]
    fn desktop_shortcuts_ignore_modified_or_unowned_combinations() {
        assert_eq!(
            desktop_shortcut_for_key(
                DesktopShortcutModifiers {
                    ctrl: true,
                    shift: true,
                    ..DesktopShortcutModifiers::default()
                },
                DesktopShortcutKey::L,
            ),
            None
        );
        assert_eq!(
            desktop_shortcut_for_key(
                DesktopShortcutModifiers {
                    alt: true,
                    ctrl: true,
                    ..DesktopShortcutModifiers::default()
                },
                DesktopShortcutKey::ArrowLeft,
            ),
            None
        );
        assert_eq!(
            desktop_shortcut_for_key(DesktopShortcutModifiers::default(), DesktopShortcutKey::L),
            None
        );
    }

    #[test]
    fn desktop_tab_restore_defaults_empty_profile_to_blank() {
        let dir = temp_test_dir("tabs-empty");

        let startup_tabs = load_desktop_startup_tabs(&dir, None);

        assert_eq!(startup_tabs.len(), 1);
        assert_eq!(startup_tabs[0].url, "about:blank");
        assert!(startup_tabs[0].active);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn desktop_tab_restore_uses_configured_home_for_empty_profile() {
        let dir = temp_test_dir("tabs-home");

        let startup_tabs = load_desktop_startup_tabs_with_home(
            &dir,
            None,
            Some("https://home.example/start".to_string()),
        );

        assert_eq!(startup_tabs.len(), 1);
        assert_eq!(startup_tabs[0].url, "https://home.example/start");
        assert!(startup_tabs[0].active);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn desktop_tab_restore_ignores_invalid_home_url() {
        let dir = temp_test_dir("tabs-invalid-home");

        let startup_tabs = load_desktop_startup_tabs_with_home(
            &dir,
            None,
            Some("javascript:alert(1)".to_string()),
        );

        assert_eq!(startup_tabs.len(), 1);
        assert_eq!(startup_tabs[0].url, "about:blank");
        assert!(startup_tabs[0].active);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn desktop_tab_snapshot_persists_tabs_without_sessions() {
        let dir = temp_test_dir("tabs");
        let plane = test_plane();
        let session = plane
            .create_session(CreateSessionRequest {
                allowed_origins: vec!["https://example.com".to_string()],
                allow_credentials: true,
                allow_interactions: true,
                allow_scripts: false,
                ttl_seconds: None,
            })
            .unwrap();
        plane
            .register_tab(CreateTabRequest {
                url: Some("https://example.com/dashboard".to_string()),
                session_id: Some(session.id.clone()),
            })
            .unwrap();

        let mut previous_json = None;
        save_desktop_tabs_if_changed(&dir, &plane, &mut previous_json).unwrap();

        let json = std::fs::read_to_string(dir.join(DESKTOP_TABS_FILE)).unwrap();
        assert!(json.contains("https://example.com/dashboard"));
        assert!(!json.contains(&session.id));
        assert!(!json.contains("session_id"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(dir.join(DESKTOP_TABS_FILE))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }

        let startup_tabs = load_desktop_startup_tabs(&dir, None);
        assert_eq!(startup_tabs.len(), 1);
        assert_eq!(startup_tabs[0].url, "https://example.com/dashboard");
        assert!(startup_tabs[0].active);

        let restored_plane = test_plane();
        let restored_tabs = register_desktop_startup_tabs(&restored_plane, &startup_tabs).unwrap();
        assert_eq!(restored_tabs.len(), 1);
        assert_eq!(restored_tabs[0].session_id, None);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn desktop_tab_restore_appends_requested_url_as_active() {
        let dir = temp_test_dir("tabs-requested");
        let snapshot = DesktopTabSnapshot {
            version: DESKTOP_TAB_SNAPSHOT_VERSION,
            active_index: Some(0),
            tabs: vec![DesktopSavedTab {
                url: "https://saved.example".to_string(),
                title: Some("Saved".to_string()),
            }],
        };
        std::fs::write(
            dir.join(DESKTOP_TABS_FILE),
            serde_json::to_vec(&snapshot).unwrap(),
        )
        .unwrap();

        let startup_tabs =
            load_desktop_startup_tabs(&dir, Some("https://fresh.example".to_string()));

        assert_eq!(startup_tabs.len(), 2);
        assert_eq!(startup_tabs[0].url, "https://saved.example");
        assert!(!startup_tabs[0].active);
        assert_eq!(startup_tabs[1].url, "https://fresh.example");
        assert!(startup_tabs[1].active);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn desktop_tab_restore_ignores_invalid_saved_urls() {
        let dir = temp_test_dir("tabs-invalid");
        let snapshot = DesktopTabSnapshot {
            version: DESKTOP_TAB_SNAPSHOT_VERSION,
            active_index: Some(1),
            tabs: vec![
                DesktopSavedTab {
                    url: "javascript:alert(1)".to_string(),
                    title: None,
                },
                DesktopSavedTab {
                    url: "https://valid.example".to_string(),
                    title: None,
                },
            ],
        };
        std::fs::write(
            dir.join(DESKTOP_TABS_FILE),
            serde_json::to_vec(&snapshot).unwrap(),
        )
        .unwrap();

        let startup_tabs = load_desktop_startup_tabs(&dir, None);

        assert_eq!(startup_tabs.len(), 1);
        assert_eq!(startup_tabs[0].url, "https://valid.example");
        assert!(startup_tabs[0].active);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn chrome_agent_permissions_default_to_interactive_without_scripts() {
        assert_eq!(
            chrome_agent_permissions(&serde_json::json!({})),
            (true, true, false)
        );
    }

    #[test]
    fn chrome_agent_permissions_support_read_only_and_script_only() {
        assert_eq!(
            chrome_agent_permissions(&serde_json::json!({
                "read_only": true,
                "allow_credentials": true,
                "allow_interactions": true,
                "allow_scripts": true,
            })),
            (false, false, false)
        );
        assert_eq!(
            chrome_agent_permissions(&serde_json::json!({
                "allow_credentials": false,
                "allow_interactions": false,
                "allow_scripts": true,
            })),
            (false, false, true)
        );
    }

    #[test]
    fn chrome_bookmark_helper_saves_active_tab_url_and_title() {
        let plane = test_plane();
        let tab = plane
            .register_tab(CreateTabRequest {
                url: Some("https://example.com/dashboard".to_string()),
                session_id: None,
            })
            .unwrap();
        plane
            .publish_page_context(telescope_control::PageContextRequest {
                tab_id: tab.id.clone(),
                url: "https://example.com/dashboard".to_string(),
                title: Some("Dashboard".to_string()),
                text_preview: None,
                selected_element_id: None,
                interactive_elements: Vec::new(),
            })
            .unwrap();

        let bookmark = bookmark_tab_from_chrome(&plane, &tab.id).unwrap();

        assert_eq!(bookmark.url, "https://example.com/dashboard");
        assert_eq!(bookmark.title.as_deref(), Some("Dashboard"));
        assert_eq!(plane.list_bookmarks().unwrap(), vec![bookmark]);
    }

    #[test]
    fn chrome_audit_events_are_bounded_newest_first_display_items() {
        let plane = test_plane();
        let tab = plane
            .create_tab(CreateTabRequest {
                url: Some("https://example.com".to_string()),
                session_id: None,
            })
            .unwrap();
        plane
            .navigate_tab(
                &tab.id,
                NavigateRequest {
                    url: "https://example.com/account".to_string(),
                    session_id: None,
                },
            )
            .unwrap();

        let events = chrome_audit_events(&plane, 1);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["summary"], "Tab navigated");
        assert_eq!(events[0]["detail"], "https://example.com/account");
        assert!(events[0]["created_at_unix"].as_u64().is_some());
    }

    #[test]
    fn chrome_audit_events_format_policy_without_tokens() {
        let plane = test_plane();
        plane
            .create_session(CreateSessionRequest {
                allowed_origins: vec!["https://example.com".to_string()],
                allow_credentials: false,
                allow_interactions: false,
                allow_scripts: false,
                ttl_seconds: None,
            })
            .unwrap();

        let events = chrome_audit_events(&plane, 5);

        assert_eq!(events[0]["summary"], "Session created");
        assert_eq!(events[0]["detail"], "1 origin, read-only");
        assert!(serde_json::to_string(&events)
            .unwrap()
            .contains("read-only"));
    }

    #[test]
    fn chrome_stop_agent_pane_revokes_scoped_grant_and_closes_pane() {
        let plane = test_plane();
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
                url: Some("https://example.com".to_string()),
                session_id: Some(session.id.clone()),
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
                session_id: Some(session.id),
                agent_grant_token: Some(grant.token.clone()),
            })
            .unwrap();
        plane.poll_commands(Some(&tab.id)).unwrap();

        stop_agent_pane_from_chrome(&plane, &pane.id).unwrap();

        assert!(plane.agent_pane_connection(&pane.id).is_err());
        assert!(plane.lookup_agent_grant(&grant.token).is_err());
        assert!(plane.list_agent_panes().unwrap().is_empty());
        let commands = plane.poll_commands(Some(&tab.id)).unwrap();
        assert_eq!(commands.len(), 1);
        assert!(matches!(
            commands[0].kind,
            BrowserCommandKind::CloseAgentPane { ref pane_id } if pane_id == &pane.id
        ));
    }

    #[test]
    fn chrome_stop_agent_pane_closes_unscoped_pane() {
        let plane = test_plane();
        let pane = plane
            .open_agent_pane(OpenAgentPaneRequest {
                url: "https://codex.example/login".to_string(),
                position: PanePosition::Bottom,
                attached_tab_id: None,
                session_id: None,
                agent_grant_token: None,
            })
            .unwrap();
        plane.poll_commands(None).unwrap();

        stop_agent_pane_from_chrome(&plane, &pane.id).unwrap();

        assert!(plane.list_agent_panes().unwrap().is_empty());
        let commands = plane.poll_commands(None).unwrap();
        assert_eq!(commands.len(), 1);
        assert!(matches!(
            commands[0].kind,
            BrowserCommandKind::CloseAgentPane { ref pane_id } if pane_id == &pane.id
        ));
    }

    #[test]
    fn agent_connection_script_injects_scoped_helper() {
        let pane = AgentPaneState {
            id: "pane-1".to_string(),
            url: "https://codex.example/login".to_string(),
            position: PanePosition::Right,
            attached_tab_id: Some("tab-1".to_string()),
            session_id: Some("session-1".to_string()),
            created_at_unix: 1,
            updated_at_unix: 1,
        };
        let connection = AgentPaneConnection {
            pane_id: pane.id.clone(),
            session_id: "session-1".to_string(),
            tab_id: "tab-1".to_string(),
            grant_token: "grant-token".to_string(),
            session_policy: telescope_control::AgentPolicy {
                allowed_origins: vec![
                    telescope_control::WebOrigin::parse("https://example.com").unwrap()
                ],
                allow_credentials: true,
                allow_interactions: true,
                allow_scripts: false,
                expires_at_unix: Some(61),
            },
            created_at_unix: 1,
            expires_at_unix: Some(61),
        };
        let payload = serde_json::to_string(&agent_connection_payload(
            "http://127.0.0.1:47777",
            &pane,
            &connection,
        ))
        .unwrap();
        let script = agent_connection_script_source(&payload);

        assert!(script.contains("__TELESCOPE_AGENT_CONNECTION"));
        assert!(script.contains("session_policy"));
        assert!(script.contains("__TELESCOPE_AGENT"));
        assert!(script.contains("window, 'telescope'"));
        assert!(script.contains("tabPageContexts"));
        assert!(script.contains("currentPageContext"));
        assert!(script.contains("waitForPageContext"));
        assert!(script.contains("waitForUrlContains"));
        assert!(script.contains("navigateAndWait"));
        assert!(script.contains("clickRef"));
        assert!(script.contains("doubleClickRefAndWait"));
        assert!(script.contains("dragRefToRefAndWait"));
        assert!(script.contains("hoverRefAndWait"));
        assert!(script.contains("focusRefAndWait"));
        assert!(script.contains("selectOptionRefAndWait"));
        assert!(script.contains("setCheckedRefAndWait"));
        assert!(script.contains("scrollByAndWait"));
        assert!(script.contains("scrollRefIntoViewAndWait"));
        assert!(script.contains("waitForCommandResult"));
        assert!(script.contains("commandMessage"));
        assert!(script.contains("waitForSelectorDetails"));
        assert!(script.contains("actionAndWait"));
        assert!(script.contains("clickRefAndWait"));
        assert!(script.contains("submitRefAndWait"));
        assert!(script.contains("extractTextAndWait"));
        assert!(script.contains("extractTextResult"));
        assert!(script.contains("extractTextRefResult"));
        assert!(script.contains("inspectElementRefAndWait"));
        assert!(script.contains("inspectElementDetails"));
        assert!(script.contains("inspectElementRefDetails"));
        assert!(script.contains("fillLoginAndWait"));
        assert!(script.contains("defaultLogin"));
        assert!(script.contains("fillDefaultLogin"));
        assert!(script.contains("fillDefaultLoginAndWait"));
        assert!(script.contains("waitForNextElementRef"));
        assert!(script.contains("pickElement"));
        assert!(script.contains("loginOptions"));
        assert!(script.contains("/v1/tabs/tab-1/navigate"));
        assert!(script.contains("/v1/tabs/tab-1/login-options"));
        assert!(script.contains("fillLogin"));
        assert!(script.contains("/v1/agent-panes/pane-1"));
        assert!(script.contains("Bearer ${frozenConnection.grant_token}"));
        assert!(!script.contains("owner_token"));
    }

    #[test]
    fn workspace_layout_docks_panes_inside_main_window() {
        let layout = compute_workspace_layout(
            WorkspaceSurface {
                width: 1600,
                height: 1000,
            },
            vec![
                pane_input("left", PanePosition::Left),
                pane_input("right", PanePosition::Right),
                pane_input("bottom", PanePosition::Bottom),
            ],
        );

        assert_eq!(
            layout.browser,
            WorkspaceRect {
                x: 480,
                y: 0,
                width: 640,
                height: 667
            }
        );
        assert_eq!(
            layout.pane_bounds("left").unwrap(),
            WorkspaceRect {
                x: 0,
                y: 0,
                width: 480,
                height: 667
            }
        );
        assert_eq!(
            layout.pane_bounds("right").unwrap(),
            WorkspaceRect {
                x: 1120,
                y: 0,
                width: 480,
                height: 667
            }
        );
        assert_eq!(
            layout.pane_bounds("bottom").unwrap(),
            WorkspaceRect {
                x: 0,
                y: 667,
                width: 1600,
                height: 333
            }
        );
    }

    #[test]
    fn workspace_layout_splits_multiple_panes_on_same_edge() {
        let layout = compute_workspace_layout(
            WorkspaceSurface {
                width: 1200,
                height: 900,
            },
            vec![
                pane_input("left-a", PanePosition::Left),
                pane_input("left-b", PanePosition::Left),
                pane_input("bottom-a", PanePosition::Bottom),
                pane_input("bottom-b", PanePosition::Bottom),
            ],
        );

        assert_eq!(
            layout.browser,
            WorkspaceRect {
                x: 480,
                y: 0,
                width: 720,
                height: 600
            }
        );
        assert_eq!(
            layout.pane_bounds("left-a").unwrap(),
            WorkspaceRect {
                x: 0,
                y: 0,
                width: 480,
                height: 300
            }
        );
        assert_eq!(
            layout.pane_bounds("left-b").unwrap(),
            WorkspaceRect {
                x: 0,
                y: 300,
                width: 480,
                height: 300
            }
        );
        assert_eq!(
            layout.pane_bounds("bottom-a").unwrap(),
            WorkspaceRect {
                x: 0,
                y: 600,
                width: 600,
                height: 300
            }
        );
        assert_eq!(
            layout.pane_bounds("bottom-b").unwrap(),
            WorkspaceRect {
                x: 600,
                y: 600,
                width: 600,
                height: 300
            }
        );
    }

    #[test]
    fn desktop_layout_reserves_chrome_and_offsets_workspace() {
        let layout = compute_desktop_layout(
            WorkspaceSurface {
                width: 1600,
                height: 1000,
            },
            vec![
                pane_input("left", PanePosition::Left),
                pane_input("right", PanePosition::Right),
                pane_input("bottom", PanePosition::Bottom),
            ],
        );

        assert_eq!(
            layout.chrome,
            WorkspaceRect {
                x: 0,
                y: 0,
                width: 1600,
                height: BROWSER_CHROME_HEIGHT
            }
        );
        assert_eq!(
            layout.workspace.browser,
            WorkspaceRect {
                x: 480,
                y: BROWSER_CHROME_HEIGHT,
                width: 640,
                height: 484
            }
        );
        assert_eq!(
            layout.workspace.pane_bounds("left").unwrap(),
            WorkspaceRect {
                x: 0,
                y: BROWSER_CHROME_HEIGHT,
                width: 480,
                height: 484
            }
        );
        assert_eq!(
            layout.workspace.pane_bounds("bottom").unwrap(),
            WorkspaceRect {
                x: 0,
                y: 758,
                width: 1600,
                height: 242
            }
        );
    }

    fn pane_input(id: &str, position: PanePosition) -> PaneLayoutInput {
        PaneLayoutInput {
            id: id.to_string(),
            position,
        }
    }

    fn temp_test_dir(prefix: &str) -> std::path::PathBuf {
        let mut dir = std::env::temp_dir();
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        dir.push(format!("telescope-desktop-{prefix}-{nonce}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn test_plane() -> ControlPlane {
        ControlPlane::new(CredentialVault::ephemeral(
            "desktop-test",
            Arc::new(MemorySecretStore::new()),
        ))
    }
}

#[cfg(feature = "webview")]
fn serde_json_string(value: &str) -> String {
    serde_json::to_string(value).expect("string serialization cannot fail")
}

#[cfg(not(feature = "webview"))]
fn main() {
    eprintln!(
        "telescope-browser was built without the `webview` feature. Rebuild with `--features webview`."
    );
}
