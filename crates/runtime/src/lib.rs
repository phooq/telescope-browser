use std::fmt;
use telescope_control::{
    AgentAction, AgentPaneConnection, AgentPaneState, BrowserCommand, BrowserCommandKind,
    CommandExecutionStatus, ControlError, ControlPlane, TabState,
};
use telescope_core::{BrowserCredentialMaterial, TelescopeError, WebOrigin};
use thiserror::Error;
use zeroize::Zeroize;

pub type Result<T> = std::result::Result<T, RuntimeError>;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("{0}")]
    Control(#[from] ControlError),
    #[error("{0}")]
    Core(#[from] TelescopeError),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("browser adapter error: {0}")]
    Adapter(String),
}

#[derive(Clone)]
pub struct BrowserRuntime {
    plane: ControlPlane,
}

impl BrowserRuntime {
    pub fn new(plane: ControlPlane) -> Self {
        Self { plane }
    }

    pub fn drain_actions(&self, tab_id: Option<&str>) -> Result<Vec<BrowserAction>> {
        self.plane
            .poll_commands(tab_id)?
            .into_iter()
            .map(|command| self.action_for_command(command))
            .collect()
    }

    pub fn apply_pending<S: BrowserActionSink>(
        &self,
        tab_id: Option<&str>,
        sink: &mut S,
    ) -> Result<Vec<String>> {
        let mut applied = Vec::new();

        for action in self.drain_actions(tab_id)? {
            let command_id = action.command_id().to_string();
            let tab_id = action.tab_id().to_string();
            let result = apply_action(sink, &action);

            match result {
                Ok(()) => {
                    if !action.reports_browser_result() {
                        self.plane.record_command_result(
                            &command_id,
                            &tab_id,
                            CommandExecutionStatus::Succeeded,
                            None,
                        )?;
                    }
                    applied.push(command_id);
                }
                Err(error) => {
                    let message = error.to_string();
                    self.plane.record_command_result(
                        &command_id,
                        &tab_id,
                        CommandExecutionStatus::Failed,
                        Some(message),
                    )?;
                    return Err(error);
                }
            }
        }

        Ok(applied)
    }

    fn action_for_command(&self, command: BrowserCommand) -> Result<BrowserAction> {
        match command.kind {
            BrowserCommandKind::OpenTab { tab } => Ok(BrowserAction::OpenTab {
                command_id: command.id,
                tab_id: command.tab_id,
                tab,
            }),
            BrowserCommandKind::CloseTab => Ok(BrowserAction::CloseTab {
                command_id: command.id,
                tab_id: command.tab_id,
            }),
            BrowserCommandKind::ActivateTab => Ok(BrowserAction::ActivateTab {
                command_id: command.id,
                tab_id: command.tab_id,
            }),
            BrowserCommandKind::Navigate { url } => Ok(BrowserAction::Navigate {
                command_id: command.id,
                tab_id: command.tab_id,
                url,
            }),
            BrowserCommandKind::GoBack => Ok(BrowserAction::GoBack {
                command_id: command.id,
                tab_id: command.tab_id,
            }),
            BrowserCommandKind::GoForward => Ok(BrowserAction::GoForward {
                command_id: command.id,
                tab_id: command.tab_id,
            }),
            BrowserCommandKind::Reload => Ok(BrowserAction::Reload {
                command_id: command.id,
                tab_id: command.tab_id,
            }),
            BrowserCommandKind::FillLogin {
                credential_id,
                target_origin,
                ..
            } => {
                let material = self.plane.credential_material_for_browser(&credential_id)?;
                if material.origin != target_origin {
                    return Err(TelescopeError::PolicyDenied(format!(
                        "credential `{}` belongs to `{}`, not `{target_origin}`",
                        material.credential_id, material.origin
                    ))
                    .into());
                }
                let command_id = command.id;
                let tab_id = command.tab_id;
                Ok(BrowserAction::EvaluateScript {
                    script: fill_login_script(&command_id, &tab_id, &target_origin, material)?,
                    command_id,
                    tab_id,
                    reports_browser_result: true,
                })
            }
            BrowserCommandKind::AgentAction {
                action,
                target_origin,
            } => {
                let command_id = command.id;
                let tab_id = command.tab_id;
                Ok(BrowserAction::EvaluateScript {
                    script: agent_action_script(&command_id, &tab_id, &target_origin, action)?,
                    command_id,
                    tab_id,
                    reports_browser_result: true,
                })
            }
            BrowserCommandKind::OpenAgentPane { pane, connection } => {
                Ok(BrowserAction::OpenAgentPane {
                    command_id: command.id,
                    tab_id: command.tab_id,
                    pane,
                    connection,
                })
            }
            BrowserCommandKind::CloseAgentPane { pane_id } => Ok(BrowserAction::CloseAgentPane {
                command_id: command.id,
                tab_id: command.tab_id,
                pane_id,
            }),
        }
    }
}

pub trait BrowserActionSink {
    fn open_tab(&mut self, tab: &TabState) -> Result<()>;
    fn close_tab(&mut self, tab_id: &str) -> Result<()>;
    fn activate_tab(&mut self, tab_id: &str) -> Result<()>;
    fn navigate(&mut self, tab_id: &str, url: &str) -> Result<()>;
    fn go_back(&mut self, tab_id: &str) -> Result<()>;
    fn go_forward(&mut self, tab_id: &str) -> Result<()>;
    fn reload(&mut self, tab_id: &str) -> Result<()>;
    fn evaluate_script(&mut self, tab_id: &str, script: &str) -> Result<()>;
    fn open_agent_pane(
        &mut self,
        pane: &AgentPaneState,
        connection: Option<&AgentPaneConnection>,
    ) -> Result<()>;
    fn close_agent_pane(&mut self, pane_id: &str) -> Result<()>;
}

pub fn apply_action<S: BrowserActionSink>(sink: &mut S, action: &BrowserAction) -> Result<()> {
    match action {
        BrowserAction::OpenTab { tab, .. } => sink.open_tab(tab),
        BrowserAction::CloseTab { tab_id, .. } => sink.close_tab(tab_id),
        BrowserAction::ActivateTab { tab_id, .. } => sink.activate_tab(tab_id),
        BrowserAction::Navigate { tab_id, url, .. } => sink.navigate(tab_id, url),
        BrowserAction::GoBack { tab_id, .. } => sink.go_back(tab_id),
        BrowserAction::GoForward { tab_id, .. } => sink.go_forward(tab_id),
        BrowserAction::Reload { tab_id, .. } => sink.reload(tab_id),
        BrowserAction::EvaluateScript { tab_id, script, .. } => {
            sink.evaluate_script(tab_id, script.expose_for_webview())
        }
        BrowserAction::OpenAgentPane {
            pane, connection, ..
        } => sink.open_agent_pane(pane, connection.as_ref()),
        BrowserAction::CloseAgentPane { pane_id, .. } => sink.close_agent_pane(pane_id),
    }
}

pub enum BrowserAction {
    OpenTab {
        command_id: String,
        tab_id: String,
        tab: TabState,
    },
    CloseTab {
        command_id: String,
        tab_id: String,
    },
    ActivateTab {
        command_id: String,
        tab_id: String,
    },
    Navigate {
        command_id: String,
        tab_id: String,
        url: String,
    },
    GoBack {
        command_id: String,
        tab_id: String,
    },
    GoForward {
        command_id: String,
        tab_id: String,
    },
    Reload {
        command_id: String,
        tab_id: String,
    },
    EvaluateScript {
        command_id: String,
        tab_id: String,
        script: SensitiveScript,
        reports_browser_result: bool,
    },
    OpenAgentPane {
        command_id: String,
        tab_id: String,
        pane: AgentPaneState,
        connection: Option<AgentPaneConnection>,
    },
    CloseAgentPane {
        command_id: String,
        tab_id: String,
        pane_id: String,
    },
}

impl BrowserAction {
    pub fn command_id(&self) -> &str {
        match self {
            Self::OpenTab { command_id, .. }
            | Self::CloseTab { command_id, .. }
            | Self::ActivateTab { command_id, .. }
            | Self::Navigate { command_id, .. }
            | Self::GoBack { command_id, .. }
            | Self::GoForward { command_id, .. }
            | Self::Reload { command_id, .. }
            | Self::EvaluateScript { command_id, .. }
            | Self::OpenAgentPane { command_id, .. }
            | Self::CloseAgentPane { command_id, .. } => command_id,
        }
    }

    pub fn tab_id(&self) -> &str {
        match self {
            Self::OpenTab { tab_id, .. }
            | Self::CloseTab { tab_id, .. }
            | Self::ActivateTab { tab_id, .. }
            | Self::Navigate { tab_id, .. }
            | Self::GoBack { tab_id, .. }
            | Self::GoForward { tab_id, .. }
            | Self::Reload { tab_id, .. }
            | Self::EvaluateScript { tab_id, .. }
            | Self::OpenAgentPane { tab_id, .. }
            | Self::CloseAgentPane { tab_id, .. } => tab_id,
        }
    }
}

impl fmt::Debug for BrowserAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OpenTab {
                command_id,
                tab_id,
                tab,
            } => f
                .debug_struct("OpenTab")
                .field("command_id", command_id)
                .field("tab_id", tab_id)
                .field("tab", tab)
                .finish(),
            Self::CloseTab { command_id, tab_id } => f
                .debug_struct("CloseTab")
                .field("command_id", command_id)
                .field("tab_id", tab_id)
                .finish(),
            Self::ActivateTab { command_id, tab_id } => f
                .debug_struct("ActivateTab")
                .field("command_id", command_id)
                .field("tab_id", tab_id)
                .finish(),
            Self::Navigate {
                command_id,
                tab_id,
                url,
            } => f
                .debug_struct("Navigate")
                .field("command_id", command_id)
                .field("tab_id", tab_id)
                .field("url", url)
                .finish(),
            Self::GoBack { command_id, tab_id } => f
                .debug_struct("GoBack")
                .field("command_id", command_id)
                .field("tab_id", tab_id)
                .finish(),
            Self::GoForward { command_id, tab_id } => f
                .debug_struct("GoForward")
                .field("command_id", command_id)
                .field("tab_id", tab_id)
                .finish(),
            Self::Reload { command_id, tab_id } => f
                .debug_struct("Reload")
                .field("command_id", command_id)
                .field("tab_id", tab_id)
                .finish(),
            Self::EvaluateScript {
                command_id, tab_id, ..
            } => f
                .debug_struct("EvaluateScript")
                .field("command_id", command_id)
                .field("tab_id", tab_id)
                .field("script", &"<redacted>")
                .finish(),
            Self::OpenAgentPane {
                command_id,
                tab_id,
                pane,
                connection,
            } => f
                .debug_struct("OpenAgentPane")
                .field("command_id", command_id)
                .field("tab_id", tab_id)
                .field("pane", pane)
                .field(
                    "connection",
                    &connection
                        .as_ref()
                        .map(|connection| (&connection.pane_id, "<redacted-grant-token>")),
                )
                .finish(),
            Self::CloseAgentPane {
                command_id,
                tab_id,
                pane_id,
            } => f
                .debug_struct("CloseAgentPane")
                .field("command_id", command_id)
                .field("tab_id", tab_id)
                .field("pane_id", pane_id)
                .finish(),
        }
    }
}

impl BrowserAction {
    fn reports_browser_result(&self) -> bool {
        matches!(
            self,
            Self::EvaluateScript {
                reports_browser_result: true,
                ..
            }
        )
    }
}

pub struct SensitiveScript {
    inner: String,
}

impl SensitiveScript {
    pub fn new(inner: String) -> Self {
        Self { inner }
    }

    pub fn expose_for_webview(&self) -> &str {
        &self.inner
    }
}

impl Drop for SensitiveScript {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

impl fmt::Debug for SensitiveScript {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SensitiveScript(<redacted>)")
    }
}

pub fn fill_login_script(
    command_id: &str,
    tab_id: &str,
    target_origin: &WebOrigin,
    mut material: BrowserCredentialMaterial,
) -> Result<SensitiveScript> {
    let reporter = command_result_reporter_script(command_id, tab_id)?;
    let origin_guard = origin_guard_script(target_origin, "fill_login")?;
    let username = serde_json::to_string(&material.username)?;
    let password = serde_json::to_string(&material.password)?;
    material.password.zeroize();

    Ok(SensitiveScript::new(format!(
        r#"(function() {{
{reporter}
{origin_guard}
  const username = {username};
  const password = {password};
  const passwordInput = document.querySelector('input[type="password"]');
  if (!passwordInput) {{
    return report({{ ok: false, action: 'fill_login', reason: 'missing_password_input' }});
  }}

  const root = passwordInput.form || passwordInput.closest('form') || document;
  const inputs = Array.from(root.querySelectorAll('input'));
  const visibleTextInputs = inputs.filter((input) => {{
    const type = (input.getAttribute('type') || 'text').toLowerCase();
    return !input.disabled && !input.readOnly && type !== 'password' &&
      ['email', 'text', 'tel', 'url', 'search'].includes(type);
  }});
  const usernameInput =
    visibleTextInputs.find((input) => /email|user|login|account/i.test(`${{input.name}} ${{input.id}} ${{input.autocomplete}}`)) ||
    visibleTextInputs[0] ||
    null;

  function setNativeValue(input, value) {{
    const descriptor = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(input), 'value') ||
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
    if (descriptor && descriptor.set) {{
      descriptor.set.call(input, value);
    }} else {{
      input.value = value;
    }}
    input.dispatchEvent(new Event('input', {{ bubbles: true }}));
    input.dispatchEvent(new Event('change', {{ bubbles: true }}));
  }}

  if (usernameInput) {{
    setNativeValue(usernameInput, username);
  }}
  setNativeValue(passwordInput, password);
  return report({{
    ok: true,
    action: 'fill_login',
    usernameFieldFound: Boolean(usernameInput),
    passwordFieldFound: true
  }});
}})();"#
    )))
}

pub fn agent_action_script(
    command_id: &str,
    tab_id: &str,
    target_origin: &WebOrigin,
    action: AgentAction,
) -> Result<SensitiveScript> {
    match action {
        AgentAction::Click {
            selector: Some(selector),
            ..
        } => click_script(command_id, tab_id, target_origin, &selector),
        AgentAction::DoubleClick {
            selector: Some(selector),
            ..
        } => double_click_script(command_id, tab_id, target_origin, &selector),
        AgentAction::DragTo {
            source_selector: Some(source_selector),
            target_selector: Some(target_selector),
            ..
        } => drag_to_script(
            command_id,
            tab_id,
            target_origin,
            &source_selector,
            &target_selector,
        ),
        AgentAction::Hover {
            selector: Some(selector),
            ..
        } => hover_script(command_id, tab_id, target_origin, &selector),
        AgentAction::Focus {
            selector: Some(selector),
            ..
        } => focus_script(command_id, tab_id, target_origin, &selector),
        AgentAction::TypeText {
            selector: Some(selector),
            text,
            clear_first,
            ..
        } => type_text_script(
            command_id,
            tab_id,
            target_origin,
            &selector,
            &text,
            clear_first,
        ),
        AgentAction::SelectOption {
            selector: Some(selector),
            value,
            ..
        } => select_option_script(command_id, tab_id, target_origin, &selector, &value),
        AgentAction::SetChecked {
            selector: Some(selector),
            checked,
            ..
        } => set_checked_script(command_id, tab_id, target_origin, &selector, checked),
        AgentAction::ScrollBy { delta_x, delta_y } => {
            scroll_by_script(command_id, tab_id, target_origin, delta_x, delta_y)
        }
        AgentAction::ScrollIntoView {
            selector: Some(selector),
            ..
        } => scroll_into_view_script(command_id, tab_id, target_origin, &selector),
        AgentAction::PressKey { key } => press_key_script(command_id, tab_id, target_origin, &key),
        AgentAction::Submit {
            selector: Some(selector),
            ..
        } => submit_script(command_id, tab_id, target_origin, &selector),
        AgentAction::WaitForSelector {
            selector,
            timeout_ms,
        } => wait_for_selector_script(
            command_id,
            tab_id,
            target_origin,
            &selector,
            timeout_ms.unwrap_or(5_000),
        ),
        AgentAction::ExtractText {
            selector: Some(selector),
            ..
        } => extract_text_script(command_id, tab_id, target_origin, &selector),
        AgentAction::InspectElement {
            selector: Some(selector),
            ..
        } => inspect_element_script(command_id, tab_id, target_origin, &selector),
        AgentAction::StartElementPicker => {
            element_picker_action_script(command_id, tab_id, target_origin)
        }
        AgentAction::ExecuteScript { script } => {
            execute_script(command_id, tab_id, target_origin, &script)
        }
        AgentAction::Click { .. }
        | AgentAction::DoubleClick { .. }
        | AgentAction::DragTo { .. }
        | AgentAction::Hover { .. }
        | AgentAction::Focus { .. }
        | AgentAction::TypeText { .. }
        | AgentAction::SelectOption { .. }
        | AgentAction::SetChecked { .. }
        | AgentAction::ScrollIntoView { .. }
        | AgentAction::Submit { .. }
        | AgentAction::ExtractText { .. }
        | AgentAction::InspectElement { .. } => Err(RuntimeError::Adapter(
            "action target was not resolved by control plane".to_string(),
        )),
    }
}

fn command_result_reporter_script(command_id: &str, tab_id: &str) -> Result<String> {
    let command_id = serde_json::to_string(command_id)?;
    let tab_id = serde_json::to_string(tab_id)?;
    Ok(format!(
        r#"  const commandId = {command_id};
  const tabId = {tab_id};
  const report = (result) => {{
    window.__TELESCOPE_AGENT_RESULTS = window.__TELESCOPE_AGENT_RESULTS || {{}};
    window.__TELESCOPE_AGENT_RESULTS[commandId] = result;
    let message;
    try {{
      message = JSON.stringify(result);
    }} catch (_) {{
      message = String(result);
    }}
    const payload = {{
      type: 'telescope.command_result',
      command_id: commandId,
      tab_id: tabId,
      status: result && result.ok === false ? 'failed' : 'succeeded',
      message
    }};
    if (window.ipc && window.ipc.postMessage) {{
      window.ipc.postMessage(JSON.stringify(payload));
    }}
    return result;
  }};
"#
    ))
}

fn origin_guard_script(target_origin: &WebOrigin, action: &str) -> Result<String> {
    let expected_origin = serde_json::to_string(&target_origin.display_url())?;
    let action = serde_json::to_string(action)?;
    Ok(format!(
        r#"  const expectedOrigin = {expected_origin};
  const currentOrigin = window.location.origin;
  if (currentOrigin !== expectedOrigin) {{
    return report({{
      ok: false,
      action: {action},
      reason: 'origin_mismatch',
      expectedOrigin,
      currentOrigin
    }});
  }}
"#
    ))
}

fn click_script(
    command_id: &str,
    tab_id: &str,
    target_origin: &WebOrigin,
    selector: &str,
) -> Result<SensitiveScript> {
    let reporter = command_result_reporter_script(command_id, tab_id)?;
    let origin_guard = origin_guard_script(target_origin, "click")?;
    let selector = serde_json::to_string(selector)?;
    Ok(SensitiveScript::new(format!(
        r#"(function() {{
{reporter}
{origin_guard}
  const selector = {selector};
  const element = document.querySelector(selector);
  if (!element) {{
    return report({{ ok: false, action: 'click', reason: 'missing_element', selector }});
  }}
  element.scrollIntoView({{ block: 'center', inline: 'center' }});
  element.dispatchEvent(new MouseEvent('mouseover', {{ bubbles: true, cancelable: true, view: window }}));
  element.dispatchEvent(new MouseEvent('mousedown', {{ bubbles: true, cancelable: true, view: window }}));
  element.dispatchEvent(new MouseEvent('mouseup', {{ bubbles: true, cancelable: true, view: window }}));
  element.click();
  return report({{ ok: true, action: 'click', selector }});
}})();"#
    )))
}

fn double_click_script(
    command_id: &str,
    tab_id: &str,
    target_origin: &WebOrigin,
    selector: &str,
) -> Result<SensitiveScript> {
    let reporter = command_result_reporter_script(command_id, tab_id)?;
    let origin_guard = origin_guard_script(target_origin, "double_click")?;
    let selector = serde_json::to_string(selector)?;
    Ok(SensitiveScript::new(format!(
        r#"(function() {{
{reporter}
{origin_guard}
  const selector = {selector};
  const element = document.querySelector(selector);
  if (!element) {{
    return report({{ ok: false, action: 'double_click', reason: 'missing_element', selector }});
  }}
  element.scrollIntoView({{ block: 'center', inline: 'center' }});
  const rect = element.getBoundingClientRect();
  const clientX = rect.left + rect.width / 2;
  const clientY = rect.top + rect.height / 2;
  const eventOptions = {{ bubbles: true, cancelable: true, view: window, clientX, clientY }};
  element.dispatchEvent(new MouseEvent('mouseover', eventOptions));
  for (const detail of [1, 2]) {{
    element.dispatchEvent(new MouseEvent('mousedown', {{ ...eventOptions, detail }}));
    element.dispatchEvent(new MouseEvent('mouseup', {{ ...eventOptions, detail }}));
    element.dispatchEvent(new MouseEvent('click', {{ ...eventOptions, detail }}));
  }}
  element.dispatchEvent(new MouseEvent('dblclick', {{ ...eventOptions, detail: 2 }}));
  return report({{
    ok: true,
    action: 'double_click',
    selector,
    bounds: {{ x: rect.x, y: rect.y, width: rect.width, height: rect.height }}
  }});
}})();"#
    )))
}

fn drag_to_script(
    command_id: &str,
    tab_id: &str,
    target_origin: &WebOrigin,
    source_selector: &str,
    target_selector: &str,
) -> Result<SensitiveScript> {
    let reporter = command_result_reporter_script(command_id, tab_id)?;
    let origin_guard = origin_guard_script(target_origin, "drag_to")?;
    let source_selector = serde_json::to_string(source_selector)?;
    let target_selector = serde_json::to_string(target_selector)?;
    Ok(SensitiveScript::new(format!(
        r#"(function() {{
{reporter}
{origin_guard}
  const sourceSelector = {source_selector};
  const targetSelector = {target_selector};
  const source = document.querySelector(sourceSelector);
  if (!source) {{
    return report({{ ok: false, action: 'drag_to', reason: 'missing_source', sourceSelector, targetSelector }});
  }}
  const target = document.querySelector(targetSelector);
  if (!target) {{
    return report({{ ok: false, action: 'drag_to', reason: 'missing_target', sourceSelector, targetSelector }});
  }}
  source.scrollIntoView({{ block: 'center', inline: 'center' }});
  target.scrollIntoView({{ block: 'center', inline: 'center' }});
  const sourceRect = source.getBoundingClientRect();
  const targetRect = target.getBoundingClientRect();
  const sourceX = sourceRect.left + sourceRect.width / 2;
  const sourceY = sourceRect.top + sourceRect.height / 2;
  const targetX = targetRect.left + targetRect.width / 2;
  const targetY = targetRect.top + targetRect.height / 2;
  const dataTransfer = typeof DataTransfer === 'function' ? new DataTransfer() : null;
  const mouse = (type, element, clientX, clientY) => {{
    element.dispatchEvent(new MouseEvent(type, {{
      bubbles: true,
      cancelable: true,
      view: window,
      clientX,
      clientY
    }}));
  }};
  const pointer = (type, element, clientX, clientY) => {{
    if (typeof PointerEvent !== 'function') return;
    element.dispatchEvent(new PointerEvent(type, {{
      bubbles: true,
      cancelable: true,
      view: window,
      pointerId: 1,
      pointerType: 'mouse',
      isPrimary: true,
      clientX,
      clientY
    }}));
  }};
  const drag = (type, element, clientX, clientY) => {{
    if (typeof DragEvent === 'function') {{
      element.dispatchEvent(new DragEvent(type, {{
        bubbles: true,
        cancelable: true,
        view: window,
        clientX,
        clientY,
        dataTransfer
      }}));
    }} else {{
      const event = new Event(type, {{ bubbles: true, cancelable: true }});
      event.dataTransfer = dataTransfer;
      event.clientX = clientX;
      event.clientY = clientY;
      element.dispatchEvent(event);
    }}
  }};

  pointer('pointerover', source, sourceX, sourceY);
  pointer('pointerdown', source, sourceX, sourceY);
  mouse('mouseover', source, sourceX, sourceY);
  mouse('mousedown', source, sourceX, sourceY);
  drag('dragstart', source, sourceX, sourceY);
  pointer('pointermove', target, targetX, targetY);
  mouse('mousemove', target, targetX, targetY);
  drag('dragenter', target, targetX, targetY);
  drag('dragover', target, targetX, targetY);
  drag('drop', target, targetX, targetY);
  drag('dragend', source, targetX, targetY);
  mouse('mouseup', target, targetX, targetY);
  pointer('pointerup', target, targetX, targetY);
  return report({{
    ok: true,
    action: 'drag_to',
    sourceSelector,
    targetSelector,
    sourceBounds: {{ x: sourceRect.x, y: sourceRect.y, width: sourceRect.width, height: sourceRect.height }},
    targetBounds: {{ x: targetRect.x, y: targetRect.y, width: targetRect.width, height: targetRect.height }}
  }});
}})();"#
    )))
}

fn hover_script(
    command_id: &str,
    tab_id: &str,
    target_origin: &WebOrigin,
    selector: &str,
) -> Result<SensitiveScript> {
    let reporter = command_result_reporter_script(command_id, tab_id)?;
    let origin_guard = origin_guard_script(target_origin, "hover")?;
    let selector = serde_json::to_string(selector)?;
    Ok(SensitiveScript::new(format!(
        r#"(function() {{
{reporter}
{origin_guard}
  const selector = {selector};
  const element = document.querySelector(selector);
  if (!element) {{
    return report({{ ok: false, action: 'hover', reason: 'missing_element', selector }});
  }}
  element.scrollIntoView({{ block: 'center', inline: 'center' }});
  const rect = element.getBoundingClientRect();
  const clientX = rect.left + rect.width / 2;
  const clientY = rect.top + rect.height / 2;
  const eventOptions = {{ bubbles: true, cancelable: true, view: window, clientX, clientY }};
  if (typeof PointerEvent === 'function') {{
    element.dispatchEvent(new PointerEvent('pointerover', {{ ...eventOptions, pointerId: 1, pointerType: 'mouse', isPrimary: true }}));
    element.dispatchEvent(new PointerEvent('pointerenter', {{ ...eventOptions, pointerId: 1, pointerType: 'mouse', isPrimary: true }}));
    element.dispatchEvent(new PointerEvent('pointermove', {{ ...eventOptions, pointerId: 1, pointerType: 'mouse', isPrimary: true }}));
  }}
  element.dispatchEvent(new MouseEvent('mouseover', eventOptions));
  element.dispatchEvent(new MouseEvent('mouseenter', eventOptions));
  element.dispatchEvent(new MouseEvent('mousemove', eventOptions));
  return report({{
    ok: true,
    action: 'hover',
    selector,
    bounds: {{ x: rect.x, y: rect.y, width: rect.width, height: rect.height }}
  }});
}})();"#
    )))
}

fn focus_script(
    command_id: &str,
    tab_id: &str,
    target_origin: &WebOrigin,
    selector: &str,
) -> Result<SensitiveScript> {
    let reporter = command_result_reporter_script(command_id, tab_id)?;
    let origin_guard = origin_guard_script(target_origin, "focus")?;
    let selector = serde_json::to_string(selector)?;
    Ok(SensitiveScript::new(format!(
        r#"(function() {{
{reporter}
{origin_guard}
  const selector = {selector};
  const element = document.querySelector(selector);
  if (!element) {{
    return report({{ ok: false, action: 'focus', reason: 'missing_element', selector }});
  }}
  if (typeof element.focus !== 'function') {{
    return report({{ ok: false, action: 'focus', reason: 'not_focusable', selector }});
  }}
  element.scrollIntoView({{ block: 'center', inline: 'center' }});
  try {{
    element.focus({{ preventScroll: true }});
  }} catch (_) {{
    element.focus();
  }}
  if (document.activeElement !== element) {{
    return report({{ ok: false, action: 'focus', reason: 'not_focusable', selector }});
  }}
  const rect = element.getBoundingClientRect();
  return report({{
    ok: true,
    action: 'focus',
    selector,
    active: true,
    bounds: {{ x: rect.x, y: rect.y, width: rect.width, height: rect.height }}
  }});
}})();"#
    )))
}

fn type_text_script(
    command_id: &str,
    tab_id: &str,
    target_origin: &WebOrigin,
    selector: &str,
    text: &str,
    clear_first: bool,
) -> Result<SensitiveScript> {
    let reporter = command_result_reporter_script(command_id, tab_id)?;
    let origin_guard = origin_guard_script(target_origin, "type_text")?;
    let selector = serde_json::to_string(selector)?;
    let text = serde_json::to_string(text)?;
    Ok(SensitiveScript::new(format!(
        r#"(function() {{
{reporter}
{origin_guard}
  const selector = {selector};
  const text = {text};
  const clearFirst = {clear_first};
  const element = document.querySelector(selector);
  if (!element) {{
    return report({{ ok: false, action: 'type_text', reason: 'missing_element', selector }});
  }}
  element.scrollIntoView({{ block: 'center', inline: 'center' }});
  element.focus();
  const current = clearFirst ? '' : (element.value || element.textContent || '');
  const next = current + text;
  const descriptor = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(element), 'value') ||
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
  if ('value' in element) {{
    if (descriptor && descriptor.set) {{
      descriptor.set.call(element, next);
    }} else {{
      element.value = next;
    }}
  }} else {{
    element.textContent = next;
  }}
  element.dispatchEvent(new Event('input', {{ bubbles: true }}));
  element.dispatchEvent(new Event('change', {{ bubbles: true }}));
  return report({{ ok: true, action: 'type_text', selector }});
}})();"#
    )))
}

fn press_key_script(
    command_id: &str,
    tab_id: &str,
    target_origin: &WebOrigin,
    key: &str,
) -> Result<SensitiveScript> {
    let reporter = command_result_reporter_script(command_id, tab_id)?;
    let origin_guard = origin_guard_script(target_origin, "press_key")?;
    let key = serde_json::to_string(key)?;
    Ok(SensitiveScript::new(format!(
        r#"(function() {{
{reporter}
{origin_guard}
  const key = {key};
  const target = document.activeElement || document.body;
  for (const type of ['keydown', 'keypress', 'keyup']) {{
    target.dispatchEvent(new KeyboardEvent(type, {{ key, bubbles: true, cancelable: true }}));
  }}
  return report({{ ok: true, action: 'press_key', key }});
}})();"#
    )))
}

fn select_option_script(
    command_id: &str,
    tab_id: &str,
    target_origin: &WebOrigin,
    selector: &str,
    value: &str,
) -> Result<SensitiveScript> {
    let reporter = command_result_reporter_script(command_id, tab_id)?;
    let origin_guard = origin_guard_script(target_origin, "select_option")?;
    let selector = serde_json::to_string(selector)?;
    let value = serde_json::to_string(value)?;
    Ok(SensitiveScript::new(format!(
        r#"(function() {{
{reporter}
{origin_guard}
  const selector = {selector};
  const requestedValue = {value};
  const element = document.querySelector(selector);
  if (!element) {{
    return report({{ ok: false, action: 'select_option', reason: 'missing_element', selector }});
  }}
  const select = element.matches && element.matches('select') ? element : null;
  if (!select) {{
    return report({{ ok: false, action: 'select_option', reason: 'not_select', selector }});
  }}
  if (select.disabled) {{
    return report({{ ok: false, action: 'select_option', reason: 'disabled', selector }});
  }}
  const option = Array.from(select.options).find((item) =>
    item.value === requestedValue ||
    item.label === requestedValue ||
    (item.textContent || '').trim() === requestedValue
  );
  if (!option) {{
    return report({{ ok: false, action: 'select_option', reason: 'missing_option', selector }});
  }}
  select.scrollIntoView({{ block: 'center', inline: 'center' }});
  select.focus();
  option.selected = true;
  select.value = option.value;
  select.dispatchEvent(new Event('input', {{ bubbles: true }}));
  select.dispatchEvent(new Event('change', {{ bubbles: true }}));
  return report({{
    ok: true,
    action: 'select_option',
    selector,
    selectedIndex: select.selectedIndex,
    selectedValue: select.value
  }});
}})();"#
    )))
}

fn set_checked_script(
    command_id: &str,
    tab_id: &str,
    target_origin: &WebOrigin,
    selector: &str,
    checked: bool,
) -> Result<SensitiveScript> {
    let reporter = command_result_reporter_script(command_id, tab_id)?;
    let origin_guard = origin_guard_script(target_origin, "set_checked")?;
    let selector = serde_json::to_string(selector)?;
    Ok(SensitiveScript::new(format!(
        r#"(function() {{
{reporter}
{origin_guard}
  const selector = {selector};
  const checked = {checked};
  const element = document.querySelector(selector);
  if (!element) {{
    return report({{ ok: false, action: 'set_checked', reason: 'missing_element', selector }});
  }}
  const tag = element.localName ? element.localName.toLowerCase() : '';
  const type = (element.getAttribute && element.getAttribute('type') || '').toLowerCase();
  if (!(tag === 'input' && (type === 'checkbox' || type === 'radio'))) {{
    return report({{ ok: false, action: 'set_checked', reason: 'not_checkable', selector }});
  }}
  if (element.disabled) {{
    return report({{ ok: false, action: 'set_checked', reason: 'disabled', selector }});
  }}
  element.scrollIntoView({{ block: 'center', inline: 'center' }});
  element.focus();
  const descriptor = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(element), 'checked') ||
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'checked');
  if (descriptor && descriptor.set) {{
    descriptor.set.call(element, checked);
  }} else {{
    element.checked = checked;
  }}
  element.dispatchEvent(new Event('input', {{ bubbles: true }}));
  element.dispatchEvent(new Event('change', {{ bubbles: true }}));
  return report({{ ok: true, action: 'set_checked', selector, checked: element.checked }});
}})();"#
    )))
}

fn scroll_by_script(
    command_id: &str,
    tab_id: &str,
    target_origin: &WebOrigin,
    delta_x: i32,
    delta_y: i32,
) -> Result<SensitiveScript> {
    let reporter = command_result_reporter_script(command_id, tab_id)?;
    let origin_guard = origin_guard_script(target_origin, "scroll_by")?;
    Ok(SensitiveScript::new(format!(
        r#"(function() {{
{reporter}
{origin_guard}
  const deltaX = {delta_x};
  const deltaY = {delta_y};
  window.scrollBy(deltaX, deltaY);
  return report({{
    ok: true,
    action: 'scroll_by',
    deltaX,
    deltaY,
    scrollX: window.scrollX,
    scrollY: window.scrollY
  }});
}})();"#
    )))
}

fn scroll_into_view_script(
    command_id: &str,
    tab_id: &str,
    target_origin: &WebOrigin,
    selector: &str,
) -> Result<SensitiveScript> {
    let reporter = command_result_reporter_script(command_id, tab_id)?;
    let origin_guard = origin_guard_script(target_origin, "scroll_into_view")?;
    let selector = serde_json::to_string(selector)?;
    Ok(SensitiveScript::new(format!(
        r#"(function() {{
{reporter}
{origin_guard}
  const selector = {selector};
  const element = document.querySelector(selector);
  if (!element) {{
    return report({{ ok: false, action: 'scroll_into_view', reason: 'missing_element', selector }});
  }}
  element.scrollIntoView({{ block: 'center', inline: 'center' }});
  const rect = element.getBoundingClientRect();
  return report({{
    ok: true,
    action: 'scroll_into_view',
    selector,
    bounds: {{ x: rect.x, y: rect.y, width: rect.width, height: rect.height }}
  }});
}})();"#
    )))
}

fn submit_script(
    command_id: &str,
    tab_id: &str,
    target_origin: &WebOrigin,
    selector: &str,
) -> Result<SensitiveScript> {
    let reporter = command_result_reporter_script(command_id, tab_id)?;
    let origin_guard = origin_guard_script(target_origin, "submit")?;
    let selector = serde_json::to_string(selector)?;
    Ok(SensitiveScript::new(format!(
        r#"(function() {{
{reporter}
{origin_guard}
  const selector = {selector};
  const element = document.querySelector(selector);
  if (!element) {{
    return report({{ ok: false, action: 'submit', reason: 'missing_element', selector }});
  }}
  const form = element.matches && element.matches('form')
    ? element
    : (element.form || (element.closest ? element.closest('form') : null));
  if (!form) {{
    return report({{ ok: false, action: 'submit', reason: 'missing_form', selector }});
  }}

  element.scrollIntoView({{ block: 'center', inline: 'center' }});
  if (element.focus) element.focus();
  const tag = element.localName ? element.localName.toLowerCase() : '';
  const type = (element.getAttribute && element.getAttribute('type') || '').toLowerCase();
  const isSubmitter = element.form === form && (
    (tag === 'button' && (!type || type === 'submit')) ||
    (tag === 'input' && (type === 'submit' || type === 'image'))
  );
  const triggerSubmit = () => {{
    if (typeof form.requestSubmit === 'function') {{
      if (isSubmitter) {{
        form.requestSubmit(element);
      }} else {{
        form.requestSubmit();
      }}
      return;
    }}
    const event = new Event('submit', {{ bubbles: true, cancelable: true }});
    if (form.dispatchEvent(event) && typeof form.submit === 'function') {{
      form.submit();
    }}
  }};
  const result = report({{ ok: true, action: 'submit', selector, formFound: true, submitterFound: isSubmitter }});
  setTimeout(triggerSubmit, 0);
  return result;
}})();"#
    )))
}

fn wait_for_selector_script(
    command_id: &str,
    tab_id: &str,
    target_origin: &WebOrigin,
    selector: &str,
    timeout_ms: u64,
) -> Result<SensitiveScript> {
    let reporter = command_result_reporter_script(command_id, tab_id)?;
    let origin_guard = origin_guard_script(target_origin, "wait_for_selector")?;
    let selector = serde_json::to_string(selector)?;
    Ok(SensitiveScript::new(format!(
        r#"(function() {{
{reporter}
{origin_guard}
  const selector = {selector};
  const timeoutMs = {timeout_ms};
  const started = Date.now();
  const finish = (result) => {{
    return report(result);
  }};
  const tick = () => {{
    if (document.querySelector(selector)) {{
      return finish({{ ok: true, action: 'wait_for_selector', selector }});
    }}
    if (Date.now() - started >= timeoutMs) {{
      return finish({{ ok: false, reason: 'timeout', selector, timeoutMs }});
    }}
    setTimeout(tick, 50);
    return {{ ok: true, pending: true, selector }};
  }};
  return tick();
}})();"#
    )))
}

fn extract_text_script(
    command_id: &str,
    tab_id: &str,
    target_origin: &WebOrigin,
    selector: &str,
) -> Result<SensitiveScript> {
    let reporter = command_result_reporter_script(command_id, tab_id)?;
    let origin_guard = origin_guard_script(target_origin, "extract_text")?;
    let selector = serde_json::to_string(selector)?;
    Ok(SensitiveScript::new(format!(
        r#"(function() {{
{reporter}
{origin_guard}
  const selector = {selector};
  const element = document.querySelector(selector);
  if (!element) {{
    return report({{ ok: false, action: 'extract_text', reason: 'missing_element', selector }});
  }}
  const text = element.innerText || element.textContent || '';
  return report({{ ok: true, action: 'extract_text', selector, text }});
}})();"#
    )))
}

fn inspect_element_script(
    command_id: &str,
    tab_id: &str,
    target_origin: &WebOrigin,
    selector: &str,
) -> Result<SensitiveScript> {
    let reporter = command_result_reporter_script(command_id, tab_id)?;
    let origin_guard = origin_guard_script(target_origin, "inspect_element")?;
    let selector = serde_json::to_string(selector)?;
    Ok(SensitiveScript::new(format!(
        r#"(function() {{
{reporter}
{origin_guard}
  const selector = {selector};
  const element = document.querySelector(selector);
  if (!element) {{
    return report({{ ok: false, action: 'inspect_element', reason: 'missing_element', selector }});
  }}
  const rect = element.getBoundingClientRect();
  const tagName = element.localName ? element.localName.toLowerCase() : '';
  const inputType = (element.getAttribute && element.getAttribute('type') || '').toLowerCase() || null;
  const isPassword = tagName === 'input' && inputType === 'password';
  const rawText = isPassword ? '' : (element.innerText || element.textContent || '');
  const text = rawText.trim().slice(0, 500) || null;
  const label =
    element.getAttribute('aria-label') ||
    element.getAttribute('title') ||
    element.getAttribute('placeholder') ||
    null;
  const role = element.getAttribute('role') || tagName || null;
  const disabled = Boolean(element.disabled || element.getAttribute('aria-disabled') === 'true');
  const checked = typeof element.checked === 'boolean' ? element.checked : null;
  const selected = typeof element.selected === 'boolean' ? element.selected : null;
  return report({{
    ok: true,
    action: 'inspect_element',
    selector,
    tagName,
    id: element.id || null,
    className: typeof element.className === 'string' ? element.className.slice(0, 300) || null : null,
    role,
    label,
    text,
    inputType,
    disabled,
    checked,
    selected,
    editable: Boolean(element.isContentEditable),
    bounds: {{ x: rect.x, y: rect.y, width: rect.width, height: rect.height }}
  }});
}})();"#
    )))
}

fn execute_script(
    command_id: &str,
    tab_id: &str,
    target_origin: &WebOrigin,
    script: &str,
) -> Result<SensitiveScript> {
    let reporter = command_result_reporter_script(command_id, tab_id)?;
    let origin_guard = origin_guard_script(target_origin, "execute_script")?;
    Ok(SensitiveScript::new(format!(
        r#"(function() {{
{reporter}
{origin_guard}
  try {{
    const value = (function() {{
{script}
    }})();
    if (value && typeof value.then === 'function') {{
      value
        .then((resolved) => report({{ ok: true, action: 'execute_script', result: resolved === undefined ? null : resolved }}))
        .catch((error) => report({{ ok: false, action: 'execute_script', reason: String(error) }}));
      return {{ ok: true, action: 'execute_script', pending: true }};
    }}
    return report({{ ok: true, action: 'execute_script', result: value === undefined ? null : value }});
  }} catch (error) {{
    return report({{ ok: false, action: 'execute_script', reason: String(error) }});
  }}
}})();"#
    )))
}

pub fn element_picker_script(tab_id: &str) -> Result<SensitiveScript> {
    element_picker_script_inner(None, tab_id, None)
}

fn element_picker_action_script(
    command_id: &str,
    tab_id: &str,
    target_origin: &WebOrigin,
) -> Result<SensitiveScript> {
    element_picker_script_inner(Some(command_id), tab_id, Some(target_origin))
}

fn element_picker_script_inner(
    command_id: Option<&str>,
    tab_id: &str,
    target_origin: Option<&WebOrigin>,
) -> Result<SensitiveScript> {
    let reporter = match command_id {
        Some(command_id) => Some(command_result_reporter_script(command_id, tab_id)?),
        None => None,
    }
    .unwrap_or_default();
    let origin_guard = match (command_id, target_origin) {
        (Some(_), Some(target_origin)) => {
            origin_guard_script(target_origin, "start_element_picker")?
        }
        _ => String::new(),
    };
    let tab_id = serde_json::to_string(tab_id)?;
    let result_return = if command_id.is_some() {
        "return report({ ok: true, action: 'start_element_picker' });"
    } else {
        "return { ok: true, action: 'start_element_picker' };"
    };
    Ok(SensitiveScript::new(format!(
        r#"(function() {{
{reporter}
{origin_guard}
  const tabId = {tab_id};
  const previous = document.getElementById('__telescope_element_picker_ring');
  if (previous) previous.remove();
  const ring = document.createElement('div');
  ring.id = '__telescope_element_picker_ring';
  Object.assign(ring.style, {{
    position: 'fixed',
    pointerEvents: 'none',
    zIndex: 2147483647,
    border: '2px solid #00a3ff',
    background: 'rgba(0, 163, 255, 0.08)',
    borderRadius: '4px',
    transition: 'all 40ms linear'
  }});
  document.documentElement.appendChild(ring);

  const cssEscape = window.CSS && CSS.escape ? CSS.escape : (value) => String(value).replace(/[^a-zA-Z0-9_-]/g, '\\$&');
  const selectorFor = (element) => {{
    if (element.id) return `#${{cssEscape(element.id)}}`;
    const parts = [];
    let node = element;
    while (node && node.nodeType === Node.ELEMENT_NODE && parts.length < 6) {{
      let part = node.localName.toLowerCase();
      if (node.classList.length) {{
        part += Array.from(node.classList).slice(0, 2).map((name) => `.${{cssEscape(name)}}`).join('');
      }}
      const parent = node.parentElement;
      if (parent) {{
        const siblings = Array.from(parent.children).filter((child) => child.localName === node.localName);
        if (siblings.length > 1) part += `:nth-of-type(${{siblings.indexOf(node) + 1}})`;
      }}
      parts.unshift(part);
      node = parent;
    }}
    return parts.join(' > ');
  }};

  const describe = (element) => {{
    const rect = element.getBoundingClientRect();
    return {{
      type: 'telescope.element_reference',
      tab_id: tabId,
      url: window.location.href,
      selector: selectorFor(element),
      label: element.getAttribute('aria-label') || element.getAttribute('title') || null,
      role: element.getAttribute('role') || element.localName,
      text: (element.innerText || element.textContent || '').trim().slice(0, 500) || null,
      bounds: {{ x: rect.x, y: rect.y, width: rect.width, height: rect.height }}
    }};
  }};

  const move = (event) => {{
    const rect = event.target.getBoundingClientRect();
    Object.assign(ring.style, {{
      left: `${{rect.x}}px`,
      top: `${{rect.y}}px`,
      width: `${{rect.width}}px`,
      height: `${{rect.height}}px`
    }});
  }};
  const click = (event) => {{
    event.preventDefault();
    event.stopPropagation();
    document.removeEventListener('mousemove', move, true);
    document.removeEventListener('click', click, true);
    ring.remove();
    const payload = describe(event.target);
    if (window.ipc && window.ipc.postMessage) {{
      window.ipc.postMessage(JSON.stringify(payload));
    }}
    window.__TELESCOPE_LAST_ELEMENT_REFERENCE = payload;
    return false;
  }};
  document.addEventListener('mousemove', move, true);
  document.addEventListener('click', click, true);
  {result_return}
}})();"#
    )))
}

pub fn page_context_script(tab_id: &str, max_text_chars: usize) -> Result<SensitiveScript> {
    page_context_script_with_interactive_elements(tab_id, max_text_chars, 60)
}

pub fn page_context_script_with_interactive_elements(
    tab_id: &str,
    max_text_chars: usize,
    max_interactive_elements: usize,
) -> Result<SensitiveScript> {
    let tab_id = serde_json::to_string(tab_id)?;
    Ok(SensitiveScript::new(format!(
        r#"(function() {{
  const tabId = {tab_id};
  const maxTextChars = {max_text_chars};
  const maxInteractiveElements = {max_interactive_elements};
  const bodyText = document.body ? (document.body.innerText || document.body.textContent || '') : '';
  const limitText = (value, max) => String(value || '').replace(/\s+/g, ' ').trim().slice(0, max) || null;
  const cssEscape = window.CSS && CSS.escape ? CSS.escape : (value) => String(value).replace(/[^a-zA-Z0-9_-]/g, '\\$&');
  const selectorFor = (element) => {{
    if (element.id) return '#' + cssEscape(element.id);
    const parts = [];
    let node = element;
    while (node && node.nodeType === Node.ELEMENT_NODE && parts.length < 6) {{
      let part = node.localName.toLowerCase();
      if (node.classList.length) {{
        part += Array.from(node.classList).slice(0, 2).map((name) => '.' + cssEscape(name)).join('');
      }}
      const parent = node.parentElement;
      if (parent) {{
        const siblings = Array.from(parent.children).filter((child) => child.localName === node.localName);
        if (siblings.length > 1) part += ':nth-of-type(' + (siblings.indexOf(node) + 1) + ')';
      }}
      parts.unshift(part);
      node = parent;
    }}
    return parts.join(' > ');
  }};
  const labelledByText = (ids) => String(ids || '').split(/\s+/).map((id) => {{
    const node = id ? document.getElementById(id) : null;
    return node ? (node.innerText || node.textContent || '') : '';
  }}).join(' ');
  const labelFor = (element) => {{
    const aria = element.getAttribute('aria-label');
    if (aria) return limitText(aria, 240);
    const labelled = labelledByText(element.getAttribute('aria-labelledby'));
    if (labelled) return limitText(labelled, 240);
    if (element.labels && element.labels.length) {{
      const labelText = Array.from(element.labels).map((label) => label.innerText || label.textContent || '').join(' ');
      if (labelText) return limitText(labelText, 240);
    }}
    const closestLabel = element.closest ? element.closest('label') : null;
    if (closestLabel) {{
      const labelText = closestLabel.innerText || closestLabel.textContent || '';
      if (labelText) return limitText(labelText, 240);
    }}
    return limitText(element.getAttribute('placeholder') || element.getAttribute('title') || element.getAttribute('alt'), 240);
  }};
  const roleFor = (element) => {{
    const explicit = element.getAttribute('role');
    if (explicit) return explicit;
    const tag = element.localName.toLowerCase();
    if (tag === 'a' && element.hasAttribute('href')) return 'link';
    if (tag === 'button') return 'button';
    if (tag === 'select') return 'combobox';
    if (tag === 'textarea') return 'textbox';
    if (tag === 'summary') return 'button';
    if (element.isContentEditable) return 'textbox';
    if (tag === 'input') {{
      const inputType = (element.getAttribute('type') || 'text').toLowerCase();
      if (['button', 'submit', 'reset'].includes(inputType)) return 'button';
      if (['checkbox', 'radio', 'range'].includes(inputType)) return inputType;
      return 'textbox';
    }}
    return tag;
  }};
  const isVisible = (element) => {{
    const rect = element.getBoundingClientRect();
    const style = window.getComputedStyle(element);
    return rect.width > 0 && rect.height > 0 && style.visibility !== 'hidden' && style.display !== 'none';
  }};
  const describeInteractiveElement = (element) => {{
    const rect = element.getBoundingClientRect();
    const tag = element.localName.toLowerCase();
    const inputType = tag === 'input' ? (element.getAttribute('type') || 'text').toLowerCase() : null;
    const isTextlessControl = ['input', 'textarea', 'select'].includes(tag);
    return {{
      selector: selectorFor(element),
      tag_name: tag,
      role: roleFor(element),
      label: labelFor(element),
      text: isTextlessControl ? null : limitText(element.innerText || element.textContent || '', 240),
      input_type: inputType,
      bounds: {{ x: rect.x, y: rect.y, width: rect.width, height: rect.height }},
      disabled: Boolean(element.disabled || element.getAttribute('aria-disabled') === 'true')
    }};
  }};
  const interactiveSelector = 'a[href], button, input, select, textarea, summary, [role="button"], [role="link"], [role="menuitem"], [role="checkbox"], [role="radio"], [role="tab"], [role="textbox"], [contenteditable=""], [contenteditable="true"], [tabindex]:not([tabindex="-1"])';
  const interactiveElements = Array.from(document.querySelectorAll(interactiveSelector))
    .filter(isVisible)
    .slice(0, maxInteractiveElements)
    .map(describeInteractiveElement);
  const payload = {{
    type: 'telescope.page_context',
    tab_id: tabId,
    url: window.location.href,
    title: document.title || null,
    text_preview: bodyText.replace(/\s+/g, ' ').trim().slice(0, maxTextChars) || null,
    selected_element_id: window.__TELESCOPE_SELECTED_ELEMENT_ID || null,
    interactive_elements: interactiveElements
  }};
  if (window.ipc && window.ipc.postMessage) {{
    window.ipc.postMessage(JSON.stringify(payload));
  }}
  window.__TELESCOPE_LAST_PAGE_CONTEXT = payload;
  return {{ ok: true, action: 'capture_page_context' }};
}})();"#
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use telescope_control::{
        AgentAction, AgentActionRequest, ControlPlane, CreateSessionRequest, CreateTabRequest,
        FillLoginRequest, OpenAgentPaneRequest, PanePosition,
    };
    use telescope_core::{CredentialInput, CredentialVault, MemorySecretStore};

    #[derive(Default)]
    struct RecordingSink {
        opened_tabs: Vec<TabState>,
        closed_tabs: Vec<String>,
        activated_tabs: Vec<String>,
        navigations: Vec<(String, String)>,
        history_back: Vec<String>,
        history_forward: Vec<String>,
        reloads: Vec<String>,
        scripts: Vec<(String, String)>,
        panes: Vec<(AgentPaneState, Option<AgentPaneConnection>)>,
        closed_panes: Vec<String>,
    }

    impl BrowserActionSink for RecordingSink {
        fn open_tab(&mut self, tab: &TabState) -> Result<()> {
            self.opened_tabs.push(tab.clone());
            Ok(())
        }

        fn close_tab(&mut self, tab_id: &str) -> Result<()> {
            self.closed_tabs.push(tab_id.to_string());
            Ok(())
        }

        fn activate_tab(&mut self, tab_id: &str) -> Result<()> {
            self.activated_tabs.push(tab_id.to_string());
            Ok(())
        }

        fn navigate(&mut self, tab_id: &str, url: &str) -> Result<()> {
            self.navigations.push((tab_id.to_string(), url.to_string()));
            Ok(())
        }

        fn go_back(&mut self, tab_id: &str) -> Result<()> {
            self.history_back.push(tab_id.to_string());
            Ok(())
        }

        fn go_forward(&mut self, tab_id: &str) -> Result<()> {
            self.history_forward.push(tab_id.to_string());
            Ok(())
        }

        fn reload(&mut self, tab_id: &str) -> Result<()> {
            self.reloads.push(tab_id.to_string());
            Ok(())
        }

        fn evaluate_script(&mut self, tab_id: &str, script: &str) -> Result<()> {
            self.scripts.push((tab_id.to_string(), script.to_string()));
            Ok(())
        }

        fn open_agent_pane(
            &mut self,
            pane: &AgentPaneState,
            connection: Option<&AgentPaneConnection>,
        ) -> Result<()> {
            self.panes.push((pane.clone(), connection.cloned()));
            Ok(())
        }

        fn close_agent_pane(&mut self, pane_id: &str) -> Result<()> {
            self.closed_panes.push(pane_id.to_string());
            Ok(())
        }
    }

    fn plane() -> ControlPlane {
        ControlPlane::new(CredentialVault::ephemeral(
            "runtime-test",
            Arc::new(MemorySecretStore::new()),
        ))
    }

    #[test]
    fn runtime_applies_browser_tab_open_and_close() {
        let plane = plane();
        let tab = plane
            .create_tab(CreateTabRequest {
                url: Some("https://example.com".to_string()),
                session_id: None,
            })
            .unwrap();
        plane.close_tab(&tab.id).unwrap();

        let runtime = BrowserRuntime::new(plane);
        let mut sink = RecordingSink::default();
        runtime.apply_pending(None, &mut sink).unwrap();

        assert_eq!(sink.opened_tabs.len(), 1);
        assert_eq!(sink.opened_tabs[0].id, tab.id);
        assert_eq!(
            sink.opened_tabs[0].current_url.as_deref(),
            Some("https://example.com")
        );
        assert_eq!(sink.closed_tabs, vec![tab.id]);
    }

    #[test]
    fn runtime_applies_browser_tab_activation() {
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
        plane.activate_tab(&first.id).unwrap();
        assert_eq!(plane.active_tab().unwrap().unwrap().id, first.id);

        let runtime = BrowserRuntime::new(plane);
        let mut sink = RecordingSink::default();
        runtime.apply_pending(None, &mut sink).unwrap();

        assert_eq!(sink.activated_tabs, vec![first.id]);
        assert_ne!(sink.activated_tabs[0], second.id);
    }

    #[test]
    fn runtime_applies_browser_history_and_reload_controls() {
        let plane = plane();
        let tab = plane
            .create_tab(CreateTabRequest {
                url: Some("https://example.com".to_string()),
                session_id: None,
            })
            .unwrap();
        plane.poll_commands(None).unwrap();
        plane.go_back(&tab.id).unwrap();
        plane.go_forward(&tab.id).unwrap();
        plane.reload_tab(&tab.id).unwrap();

        let runtime = BrowserRuntime::new(plane);
        let mut sink = RecordingSink::default();
        runtime.apply_pending(Some(&tab.id), &mut sink).unwrap();

        assert_eq!(sink.history_back, vec![tab.id.clone()]);
        assert_eq!(sink.history_forward, vec![tab.id.clone()]);
        assert_eq!(sink.reloads, vec![tab.id]);
    }

    #[test]
    fn runtime_resolves_password_only_for_browser_script() {
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
                username: "me@example.com".to_string(),
                password: "secret-password".to_string(),
                login_url: None,
                label: None,
            })
            .unwrap();
        plane
            .fill_login(
                &tab.id,
                FillLoginRequest {
                    session_id: session.id,
                    credential_id: credential.id,
                },
            )
            .unwrap();

        let runtime = BrowserRuntime::new(plane.clone());
        let mut sink = RecordingSink::default();
        runtime.apply_pending(Some(&tab.id), &mut sink).unwrap();

        assert_eq!(sink.scripts.len(), 1);
        assert!(sink.scripts[0].1.contains("secret-password"));
        assert!(!format!("{:?}", runtime.drain_actions(None).unwrap()).contains("secret-password"));
        assert!(sink.scripts[0].1.contains("telescope.command_result"));
        assert!(sink.scripts[0].1.contains("fill_login"));
        assert!(sink.scripts[0].1.contains("missing_password_input"));
        assert!(sink.scripts[0].1.contains("expectedOrigin"));
        assert!(sink.scripts[0].1.contains("https://example.com"));
        assert!(sink.scripts[0].1.contains("origin_mismatch"));
        let results = plane.list_command_results().unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn debug_output_redacts_sensitive_script() {
        let script = fill_login_script(
            "cmd",
            "tab",
            &telescope_core::WebOrigin::parse("https://example.com").unwrap(),
            BrowserCredentialMaterial {
                credential_id: "cred".to_string(),
                origin: telescope_core::WebOrigin::parse("https://example.com").unwrap(),
                username: "me".to_string(),
                password: "debug-secret".to_string(),
            },
        )
        .unwrap();
        let action = BrowserAction::EvaluateScript {
            command_id: "cmd".to_string(),
            tab_id: "tab".to_string(),
            script,
            reports_browser_result: true,
        };

        assert!(!format!("{action:?}").contains("debug-secret"));
    }

    #[test]
    fn runtime_generates_fine_grained_action_scripts() {
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
        plane
            .queue_agent_action(
                &tab.id,
                AgentActionRequest {
                    session_id: session.id,
                    action: AgentAction::TypeText {
                        selector: Some("#search".to_string()),
                        element_ref_id: None,
                        text: "hello".to_string(),
                        clear_first: true,
                    },
                },
            )
            .unwrap();

        let runtime = BrowserRuntime::new(plane);
        let mut sink = RecordingSink::default();
        runtime.apply_pending(Some(&tab.id), &mut sink).unwrap();

        assert_eq!(sink.scripts.len(), 1);
        assert!(sink.scripts[0].1.contains("#search"));
        assert!(sink.scripts[0].1.contains("hello"));
        assert!(sink.scripts[0].1.contains("telescope.command_result"));
        assert!(sink.scripts[0].1.contains("tab_id"));
        assert!(sink.scripts[0].1.contains("origin_mismatch"));
        assert!(sink.scripts[0].1.contains("https://example.com"));
        assert!(runtime.plane.list_command_results().unwrap().is_empty());
    }

    #[test]
    fn runtime_generates_inspect_element_script_without_form_values() {
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
        plane
            .queue_agent_action(
                &tab.id,
                AgentActionRequest {
                    session_id: session.id,
                    action: AgentAction::InspectElement {
                        selector: Some("input[type=\"password\"]".to_string()),
                        element_ref_id: None,
                    },
                },
            )
            .unwrap();

        let runtime = BrowserRuntime::new(plane);
        let mut sink = RecordingSink::default();
        runtime.apply_pending(Some(&tab.id), &mut sink).unwrap();

        assert_eq!(sink.scripts.len(), 1);
        assert!(sink.scripts[0].1.contains("action: 'inspect_element'"));
        assert!(sink.scripts[0].1.contains("input[type=\\\"password\\\"]"));
        assert!(sink.scripts[0].1.contains("inputType === 'password'"));
        assert!(!sink.scripts[0].1.contains(".value"));
        assert!(sink.scripts[0].1.contains("origin_mismatch"));
    }

    #[test]
    fn runtime_generates_select_and_checked_action_scripts() {
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
        plane
            .queue_agent_action(
                &tab.id,
                AgentActionRequest {
                    session_id: session.id.clone(),
                    action: AgentAction::SelectOption {
                        selector: Some("select[name=\"timezone\"]".to_string()),
                        element_ref_id: None,
                        value: "UTC".to_string(),
                    },
                },
            )
            .unwrap();
        plane
            .queue_agent_action(
                &tab.id,
                AgentActionRequest {
                    session_id: session.id,
                    action: AgentAction::SetChecked {
                        selector: Some("input[name=\"email_updates\"]".to_string()),
                        element_ref_id: None,
                        checked: true,
                    },
                },
            )
            .unwrap();

        let runtime = BrowserRuntime::new(plane);
        let mut sink = RecordingSink::default();
        runtime.apply_pending(Some(&tab.id), &mut sink).unwrap();

        assert_eq!(sink.scripts.len(), 2);
        assert!(sink.scripts[0].1.contains("select[name=\\\"timezone\\\"]"));
        assert!(sink.scripts[0].1.contains("action: 'select_option'"));
        assert!(sink.scripts[0].1.contains("missing_option"));
        assert!(sink.scripts[0].1.contains("origin_mismatch"));
        assert!(sink.scripts[1]
            .1
            .contains("input[name=\\\"email_updates\\\"]"));
        assert!(sink.scripts[1].1.contains("action: 'set_checked'"));
        assert!(sink.scripts[1].1.contains("not_checkable"));
        assert!(sink.scripts[1].1.contains("origin_mismatch"));
    }

    #[test]
    fn runtime_generates_double_click_and_drag_action_scripts() {
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
        plane
            .queue_agent_action(
                &tab.id,
                AgentActionRequest {
                    session_id: session.id.clone(),
                    action: AgentAction::DoubleClick {
                        selector: Some("[data-card=\"todo-1\"]".to_string()),
                        element_ref_id: None,
                    },
                },
            )
            .unwrap();
        plane
            .queue_agent_action(
                &tab.id,
                AgentActionRequest {
                    session_id: session.id,
                    action: AgentAction::DragTo {
                        source_selector: Some("[data-card=\"todo-1\"]".to_string()),
                        source_element_ref_id: None,
                        target_selector: Some("[data-column=\"done\"]".to_string()),
                        target_element_ref_id: None,
                    },
                },
            )
            .unwrap();

        let runtime = BrowserRuntime::new(plane);
        let mut sink = RecordingSink::default();
        runtime.apply_pending(Some(&tab.id), &mut sink).unwrap();

        assert_eq!(sink.scripts.len(), 2);
        assert!(sink.scripts[0].1.contains("action: 'double_click'"));
        assert!(sink.scripts[0].1.contains("[data-card=\\\"todo-1\\\"]"));
        assert!(sink.scripts[0].1.contains("dblclick"));
        assert!(sink.scripts[0].1.contains("origin_mismatch"));
        assert!(sink.scripts[1].1.contains("action: 'drag_to'"));
        assert!(sink.scripts[1].1.contains("missing_source"));
        assert!(sink.scripts[1].1.contains("missing_target"));
        assert!(sink.scripts[1].1.contains("DragEvent"));
        assert!(sink.scripts[1].1.contains("[data-column=\\\"done\\\"]"));
        assert!(sink.scripts[1].1.contains("origin_mismatch"));
    }

    #[test]
    fn runtime_generates_hover_and_focus_action_scripts() {
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
            .queue_agent_action(
                &tab.id,
                AgentActionRequest {
                    session_id: session.id.clone(),
                    action: AgentAction::Hover {
                        selector: Some("button[data-menu=\"account\"]".to_string()),
                        element_ref_id: None,
                    },
                },
            )
            .unwrap();
        plane
            .queue_agent_action(
                &tab.id,
                AgentActionRequest {
                    session_id: session.id,
                    action: AgentAction::Focus {
                        selector: Some("input[name=\"search\"]".to_string()),
                        element_ref_id: None,
                    },
                },
            )
            .unwrap();

        let runtime = BrowserRuntime::new(plane);
        let mut sink = RecordingSink::default();
        runtime.apply_pending(Some(&tab.id), &mut sink).unwrap();

        assert_eq!(sink.scripts.len(), 2);
        assert!(sink.scripts[0].1.contains("action: 'hover'"));
        assert!(sink.scripts[0]
            .1
            .contains("button[data-menu=\\\"account\\\"]"));
        assert!(sink.scripts[0].1.contains("PointerEvent"));
        assert!(sink.scripts[0].1.contains("origin_mismatch"));
        assert!(sink.scripts[1].1.contains("action: 'focus'"));
        assert!(sink.scripts[1].1.contains("input[name=\\\"search\\\"]"));
        assert!(sink.scripts[1].1.contains("not_focusable"));
        assert!(sink.scripts[1].1.contains("origin_mismatch"));
    }

    #[test]
    fn runtime_generates_scroll_action_scripts() {
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
                url: Some("https://example.com/docs".to_string()),
                session_id: Some(session.id.clone()),
            })
            .unwrap();
        plane
            .queue_agent_action(
                &tab.id,
                AgentActionRequest {
                    session_id: session.id.clone(),
                    action: AgentAction::ScrollBy {
                        delta_x: 0,
                        delta_y: 900,
                    },
                },
            )
            .unwrap();
        plane
            .queue_agent_action(
                &tab.id,
                AgentActionRequest {
                    session_id: session.id,
                    action: AgentAction::ScrollIntoView {
                        selector: Some("#install".to_string()),
                        element_ref_id: None,
                    },
                },
            )
            .unwrap();

        let runtime = BrowserRuntime::new(plane);
        let mut sink = RecordingSink::default();
        runtime.apply_pending(Some(&tab.id), &mut sink).unwrap();

        assert_eq!(sink.scripts.len(), 2);
        assert!(sink.scripts[0].1.contains("action: 'scroll_by'"));
        assert!(sink.scripts[0]
            .1
            .contains("window.scrollBy(deltaX, deltaY)"));
        assert!(sink.scripts[0].1.contains("origin_mismatch"));
        assert!(sink.scripts[1].1.contains("action: 'scroll_into_view'"));
        assert!(sink.scripts[1].1.contains("#install"));
        assert!(sink.scripts[1].1.contains("missing_element"));
        assert!(sink.scripts[1].1.contains("origin_mismatch"));
    }

    #[test]
    fn runtime_generates_submit_action_script() {
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
        plane
            .queue_agent_action(
                &tab.id,
                AgentActionRequest {
                    session_id: session.id,
                    action: AgentAction::Submit {
                        selector: Some("button[type=\"submit\"]".to_string()),
                        element_ref_id: None,
                    },
                },
            )
            .unwrap();

        let runtime = BrowserRuntime::new(plane);
        let mut sink = RecordingSink::default();
        runtime.apply_pending(Some(&tab.id), &mut sink).unwrap();

        assert_eq!(sink.scripts.len(), 1);
        assert!(sink.scripts[0].1.contains("button[type=\\\"submit\\\"]"));
        assert!(sink.scripts[0].1.contains("action: 'submit'"));
        assert!(sink.scripts[0].1.contains("requestSubmit"));
        assert!(sink.scripts[0].1.contains("origin_mismatch"));
        assert!(sink.scripts[0].1.contains("https://example.com"));
    }

    #[test]
    fn runtime_applies_agent_pane_opens() {
        let plane = plane();
        let tab = plane
            .register_tab(CreateTabRequest {
                url: Some("https://example.com".to_string()),
                session_id: None,
            })
            .unwrap();
        plane
            .open_agent_pane(OpenAgentPaneRequest {
                url: "https://codex.example/login".to_string(),
                position: PanePosition::Bottom,
                attached_tab_id: Some(tab.id.clone()),
                session_id: None,
                agent_grant_token: None,
            })
            .unwrap();

        let runtime = BrowserRuntime::new(plane);
        let mut sink = RecordingSink::default();
        runtime.apply_pending(Some(&tab.id), &mut sink).unwrap();

        assert_eq!(sink.panes.len(), 1);
        assert_eq!(sink.panes[0].0.position, PanePosition::Bottom);
        assert_eq!(sink.panes[0].0.url, "https://codex.example/login");
        assert!(sink.panes[0].1.is_none());
    }

    #[test]
    fn runtime_applies_agent_pane_closes() {
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
        plane.poll_commands(Some(&tab.id)).unwrap();
        plane.close_agent_pane(&pane.id).unwrap();

        let runtime = BrowserRuntime::new(plane);
        let mut sink = RecordingSink::default();
        runtime.apply_pending(Some(&tab.id), &mut sink).unwrap();

        assert_eq!(sink.closed_panes, vec![pane.id]);
    }

    #[test]
    fn element_picker_posts_component_reference() {
        let script = element_picker_script("tab-1").unwrap();
        assert!(script
            .expose_for_webview()
            .contains("telescope.element_reference"));
        assert!(script
            .expose_for_webview()
            .contains("window.ipc.postMessage"));
    }

    #[test]
    fn page_context_script_posts_bounded_context() {
        let script = page_context_script("tab-1", 4096).unwrap();
        assert!(script
            .expose_for_webview()
            .contains("telescope.page_context"));
        assert!(script.expose_for_webview().contains("maxTextChars = 4096"));
        assert!(script.expose_for_webview().contains("interactive_elements"));
        assert!(script
            .expose_for_webview()
            .contains("maxInteractiveElements = 60"));
        assert!(!script.expose_for_webview().contains(".value"));
    }
}
