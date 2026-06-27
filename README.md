# Telescope

Telescope is an early Rust browser/control-plane prototype for human and AI-agent browsing.

The project is intentionally split into small crates:

- `telescope-core`: origin normalization, secure credential vault abstraction, and agent policy checks.
- `telescope-control`: local authenticated HTTP API and in-process browser command queue.
- `telescope-runtime`: browser-side command execution and secret materialization.
- `telescope-sdk`: ergonomic Rust client for controlling a running Telescope instance.
- `telescope-cli`: command-line entry point for serving the control API and managing credentials.
- `telescope-desktop`: feature-gated desktop webview shell using `wry`.

Security model in this slice:

- Credentials are indexed as non-secret metadata in a profile JSON file.
- Credential secrets are stored behind a `SecretStore` trait. The default production store is the OS keyring.
- Agent sessions are scoped to exact web origins and can be separately allowed to use credentials, interact with pages, or run custom scripts.
- Scoped agent grants let Codex or another agent use a short-lived token for a session and selected tabs without receiving the owner control token. Revoking a grant closes connected panes and discards unpolled browser commands that were queued through that grant.
- Owner clients can revoke a whole agent session, which revokes its grants, closes connected panes, detaches browser tabs from that session, and purges pending session-scoped browser commands. Expired sessions and grants are cleaned up on the next control API request.
- SDK clients can ask Telescope to navigate or fill a login, but the SDK API does not return raw passwords.
- Owner SDK clients and the trusted desktop chrome can save, update, delete, or fill credentials for a tab by deriving the credential origin from that tab's current URL.
- The browser runtime resolves credential secrets in process, converts queued commands into browser actions, and records page-side command results.
- Security-sensitive owner/agent actions are recorded in a bounded audit event feed. Desktop and `telescope serve` profiles append the same non-secret events to `audit.jsonl`, and the desktop chrome shows a compact recent-event strip for local operator visibility.
- Owner clients can export a non-secret handoff snapshot for moving work between shells or hosts. It includes tabs, sessions, bookmarks, panes, page context, cursor refs, command results, and audit events, but not credentials, grant tokens, pending commands, or pane connection descriptors. The SDK and CLI can apply the tab URLs and bookmarks from that snapshot to another running Telescope instance.
- The CLI can print the active tab's latest non-secret page context, visible interactive controls, cursor-picked element references, and recent page-side command results with `telescope desktop context`, `telescope desktop refs`, and `telescope desktop results`, which is useful after attaching to the running browser from another terminal or SSH session.
- SDK-created tabs queue explicit browser open commands, become the active browser tab, appear in the desktop tab strip, and can be switched with `activate_tab`. Owner clients can also queue back, forward, and reload commands for a tab. Closing a tab removes tab-scoped context, cursor references, and attached agent panes before queueing browser close commands. The desktop profile stores the non-secret browser tab URL/title set in `tabs.json` and restores those tabs on the next launch.
- Owner clients and desktop chrome can persist bookmarks in the active profile's `bookmarks.json`; scoped agent grants cannot read or mutate bookmarks.
- Codex or another agent UI can be opened as a left, right, or bottom pane. Telescope queues pane opens into the browser runtime, and the desktop shell docks a persistent native webview inside the main browser window. Telescope can publish bounded page context, visible interactive controls, and cursor-selected element references to that pane.
- Scoped Codex panes get a grant-backed connection descriptor injected as `window.__TELESCOPE_AGENT_CONNECTION` plus a scoped helper as `window.__TELESCOPE_AGENT` and `window.telescope` when that name is free. The pane can discover its local Telescope API URL, tab ID, session ID, and scoped grant token without receiving the owner token, then fetch page context, discover current-page login options, use cursor refs, queue actions, fill approved credentials, wait for command results, or close itself through the grant.
- Desktop user tabs share the browser profile context so normal site cookies and signed-in sessions work across tabs. Codex panes use a separate shared agent profile context, so the user's site cookies are not mixed with the Codex login session.
- The local HTTP API requires a bearer token for all non-health endpoints.

This is not yet a full custom rendering engine. Telescope uses platform webviews for rendering, with Rust owning the agent policy, credential vault, SDK, and control protocol.

## Build

```sh
cargo test --workspace --exclude telescope-desktop
```

The desktop shell is behind a feature because it links the platform webview stack:

```sh
cargo run -p telescope-desktop --features webview -- https://example.com
```

When the desktop browser starts, it also starts a localhost control server attached to the live browser runtime. It prints `TELESCOPE_TOKEN=...` and writes `control.json` into the active Telescope profile directory. That file contains the local URL and owner token for user-owned automation; create a scoped agent grant before handing control to Codex or another agent.

With an empty profile, Telescope opens `about:blank` rather than contacting a default website. Set `TELESCOPE_HOME_URL` to an explicit `http://`, `https://`, or `about:blank` home page, pass a URL on the command line, or restore saved tabs to open pages at startup.

Telescope uses WebKitGTK on Linux, WKWebView on macOS, and WebView2 on Windows through `wry`. Linux needs WebKitGTK and GTK development packages. macOS builds need the Xcode command line tools. Windows builds need the Microsoft C++ build tools and the WebView2 runtime, which is present on current Windows installs and available as a redistributable for older systems. Run `telescope desktop doctor` to inspect the active profile/control-file target and the platform webview prerequisites without connecting to a running browser.

On Debian/Ubuntu-style Linux systems, install the native packages first:

```sh
sudo apt-get install -y pkg-config libwebkit2gtk-4.1-dev libgtk-3-dev \
  libglib2.0-dev libgdk-pixbuf-2.0-dev libpango1.0-dev libsoup-3.0-dev \
  libcairo2-dev libayatana-appindicator3-dev librsvg2-dev
```

The cross-platform CI workflow runs these gates on Ubuntu, macOS, and Windows:

```sh
cargo fmt --all --check
cargo check --workspace
cargo test --workspace
cargo check -p telescope-desktop --features webview
```

On Linux, install the native packages above before checking the `webview` feature. The macOS and Windows checks should be run on those operating systems when validating native launch behavior; cross-target checks from Linux are useful for catching Rust type errors, but they do not prove the platform webview runtime can start.

## Run The Control Server

```sh
cargo run -p telescope-cli -- serve --token dev-token
```

The standalone `telescope serve` command prints `TELESCOPE_CONTROL_FILE=...` and writes `control.json` into the active profile directory with the local URL and owner token. Connect from Rust with that file, or use `TELESCOPE_URL` and `TELESCOPE_TOKEN` directly:

```rust
use telescope_sdk::TelescopeClient;

let client = TelescopeClient::from_control_file("/path/to/Telescope/profile/control.json")?;
let session = client.create_session(["https://example.com"], true)?;
let mut tab = client.active_browser_tab_or_create(Some("https://example.com"), Some(&session.id))?;
let tabs = client.list_tabs()?;
let active = client.active_tab()?;
let handoff = client.handoff_snapshot()?;
let restored = client.restore_handoff_snapshot(&handoff)?;
tab.navigate("https://example.com/login")?;
let bookmark = tab.bookmark(Some("Example Login"))?;
tab.open_bookmark(&bookmark.id)?;
let bookmarked_tab = tab.open_bookmark_in_new_tab(&bookmark.id)?;
assert_eq!(
    bookmarked_tab.state().current_url.as_deref(),
    Some(bookmark.url.as_str())
);
tab.refresh()?;
let context = tab.current_page_context()?;
let refs = tab.list_element_references()?;
tab.go_back()?;
tab.go_forward()?;
tab.reload()?;
let credential = tab.store_credential("me@example.com", "secret")?;
let fill = tab.fill_default_credential_and_wait(std::time::Duration::from_secs(5))?;
tab.delete_credential(&credential.id)?;

let grant = client.create_agent_grant(&session.id, [tab.id().to_string()], Some(600))?;
let agent = client.scoped_agent_client(&grant)?;
agent.click(tab.id(), &session.id, "button[type='submit']")?;
client.revoke_session(&session.id)?;
tab.activate()?;
tab.close()?;
```

For the desktop browser, read the generated profile control file:

```rust
let client = TelescopeClient::from_control_file("/path/to/Telescope/profile/control.json")?;
```

The CLI can also attach to the running desktop browser. By default it reads the active profile's `control.json`; pass `--control-file`, or set `TELESCOPE_URL` and `TELESCOPE_TOKEN`, to target another instance:

```sh
cargo run -p telescope-cli -- desktop active-tab
cargo run -p telescope-cli -- desktop doctor
cargo run -p telescope-cli -- desktop open https://example.com
cargo run -p telescope-cli -- desktop open https://example.com --tab-id <tab-id>
cargo run -p telescope-cli -- desktop new-tab https://example.com/docs
cargo run -p telescope-cli -- desktop activate-tab <tab-id>
cargo run -p telescope-cli -- desktop close-tab <tab-id>
cargo run -p telescope-cli -- desktop context --limit 20
cargo run -p telescope-cli -- desktop refs
cargo run -p telescope-cli -- desktop results --limit 20
cargo run -p telescope-cli -- desktop sessions
cargo run -p telescope-cli -- desktop revoke-session <session-id>
cargo run -p telescope-cli -- desktop grants
cargo run -p telescope-cli -- desktop revoke-grant <grant-token>
cargo run -p telescope-cli -- desktop stop-pane <pane-id>
cargo run -p telescope-cli -- desktop back --tab-id <tab-id>
cargo run -p telescope-cli -- desktop forward --tab-id <tab-id>
cargo run -p telescope-cli -- desktop reload
cargo run -p telescope-cli -- desktop reload --tab-id <tab-id>
cargo run -p telescope-cli -- desktop handoff --json
cargo run -p telescope-cli -- desktop handoff --output /tmp/telescope-handoff.json
cargo run -p telescope-cli -- desktop handoff --restore /tmp/telescope-handoff.json
cargo run -p telescope-cli -- desktop bookmarks list
cargo run -p telescope-cli -- desktop bookmarks save --tab-id <tab-id>
cargo run -p telescope-cli -- desktop bookmarks open <bookmark-id> --tab-id <tab-id>
cargo run -p telescope-cli -- desktop bookmarks open <bookmark-id> --new-tab
cargo run -p telescope-cli -- desktop bookmarks delete <bookmark-id>
cargo run -p telescope-cli -- desktop open-codex https://your-codex-url.example/login --position right
TELESCOPE_CODEX_URL=https://your-codex-url.example/login cargo run -p telescope-cli -- desktop open-codex --position right
cargo run -p telescope-cli -- desktop open-codex https://your-codex-url.example/login --tab-id <tab-id> --read-only --position left
cargo run -p telescope-cli -- desktop open-codex https://your-codex-url.example/login --read-only --position bottom
cargo run -p telescope-cli -- desktop open-codex https://your-codex-url.example/login --no-credentials --no-interactions --allow-scripts
TELESCOPE_PASSWORD='secret' cargo run -p telescope-cli -- desktop credentials save me@example.com
cargo run -p telescope-cli -- desktop credentials fill
cargo run -p telescope-cli -- desktop credentials fill --tab-id <tab-id> --wait-seconds 5
cargo run -p telescope-cli -- desktop credentials delete <credential-id>
cargo run -p telescope-cli -- desktop audit --limit 20
```

## Docked Codex Pane And Cursor References

The Codex pane URL is caller-provided so Telescope does not hardcode a moving product URL:

```rust
use telescope_sdk::{PanePosition, ScopedAgentPaneOptions, TelescopeClient};

let client = TelescopeClient::new("http://127.0.0.1:47639", "dev-token")?;
let tab = client.create_browser_tab(Some("https://example.com/dashboard"), None)?;

let codex = tab.open_codex_pane(
    "https://your-codex-url.example/login",
    PanePosition::Right,
    Some(600),
)?;
let read_only_codex = tab.open_read_only_codex_pane(
    "https://your-codex-url.example/login",
    PanePosition::Bottom,
    Some(600),
)?;
let script_only_codex = client.open_codex_pane_for_active_tab_with_options(
    ScopedAgentPaneOptions::interactive(
        "https://your-codex-url.example/login",
        PanePosition::Left,
    )
    .with_credentials(false)
    .with_interactions(false)
    .with_scripts(true)
    .with_ttl_seconds(600),
)?;

let connection_json = serde_json::to_string(&codex.connection)?;
let picked = codex.pick_element(std::time::Duration::from_secs(30))?;
let result = codex.click_ref_and_wait(
    &picked.id,
    std::time::Duration::from_secs(5),
)?;
let signed_in = codex.wait_for_url_contains(
    "/dashboard",
    std::time::Duration::from_secs(10),
)?;

client.stop_scoped_agent_pane(&read_only_codex)?;
client.stop_scoped_agent_pane(&script_only_codex)?;
client.stop_scoped_agent_pane(&codex)?;
```

`pick_element` starts a one-shot cursor picker in the page, waits for the next clicked component reference on the pane's attached tab, and returns the selector, role, label, text preview, and bounds that later actions can reuse. Element references are origin-bound, so a Codex pane cannot replay a reference after the tab has moved to another site.

The desktop runtime captures bounded page context snapshots periodically through IPC, giving the docked agent pane page title, URL, selected element, text preview, and a capped list of visible interactive controls with selectors, roles, labels, and bounds. The capture script does not read form field values, and the control plane drops text for password inputs before storing the snapshot. These snapshots also update the control plane's authoritative tab URL/title, so later agent actions and credential fills are checked against the page the browser actually observed, not a stale SDK navigation request. Accepted fill-login and action commands also carry the authorized origin into the runtime script, which checks `window.location.origin` before acting and returns an `origin_mismatch` result if the tab moved before execution. Login fill and fine-grained agent actions report page-side command results over the same in-process bridge, so callers can distinguish "script was injected" from outcomes such as "password field was missing", "element was missing", or extracted text. The Rust SDK can list command results for a specific `BrowserTab` or `ScopedAgentPane`, and can parse read-only command results into `SelectorWaitResult`, `ExtractedText`, and `InspectedElement` via helpers such as `wait_for_selector_details`, `extract_text_result`, `extract_text_ref_result`, `inspect_element_details`, and `inspect_element_ref_details`. Scoped panes only receive command results for commands issued by their own grant.

When the desktop pane webview loads, Telescope injects the same scoped descriptor into the page as `window.__TELESCOPE_AGENT_CONNECTION` and dispatches `telescope:agent-connection`. The descriptor contains the local control URL, pane ID, tab ID, session ID, scoped grant token, session policy flags, and endpoint paths for context, navigation, element refs, command results, actions, login options, login fill, and pane close. It also injects `window.__TELESCOPE_AGENT`, with a `window.telescope` alias when available, so pane code can call helpers such as `currentPageContext()`, `navigateAndWait(...)`, `waitForUrlContains(...)`, `elementRefs()`, `pickElement(...)`, `clickRefAndWait(...)`, `doubleClickRefAndWait(...)`, `dragRefToRefAndWait(...)`, `hoverRefAndWait(...)`, `focusRefAndWait(...)`, `selectOptionRefAndWait(...)`, `setCheckedRefAndWait(...)`, `scrollByAndWait(...)`, `scrollRefIntoViewAndWait(...)`, `waitForSelectorDetails(...)`, `extractTextResult(...)`, `inspectElementRefDetails(...)`, `submitRefAndWait(...)`, `loginOptions()`, `defaultLogin()`, `fillLoginAndWait(...)`, `fillDefaultLoginAndWait(...)`, and `waitForCommandResult(...)` without manually constructing local API requests.

The local control server handles browser CORS preflights, including private-network preflight headers, so a Codex web UI loaded in the pane can call the injected local API endpoint with its scoped bearer token. Non-preflight API requests still require a valid owner token or scoped agent grant. Grants created by `open_scoped_agent_pane` and `open_scoped_agent_pane_for_active_tab` are bound to the pane URL's origin, so requests without a matching `Origin` header are rejected even if they have the grant token. The Rust `ScopedAgentPane` helper sends the matching origin automatically for pane-bound grant calls.

The scoped agent client can close its own pane. The owner client can revoke the backing agent grant; revocation closes any panes connected to that grant and removes their pane connection descriptors.

In the current desktop shell, a trusted local chrome webview renders the tab strip, back/forward/reload buttons, address field, bookmark controls, a compact saved-login row, Codex pane controls, and a recent audit-event strip above the page workspace. The address field accepts full URLs, hostnames, localhost URLs, and plain search text; searches use DuckDuckGo by default and can be configured with `TELESCOPE_SEARCH_URL`, using `{query}` as the encoded-query placeholder. The shell handles common browser shortcuts from the window: `Ctrl`/`Cmd+L` focuses the address field, `Ctrl`/`Cmd+T` opens a tab, `Ctrl`/`Cmd+W` closes the active tab, `Ctrl`/`Cmd+R` or `F5` reloads, and `Alt+Left`/`Alt+Right` navigate history. The bookmark controls save the active tab URL/title and navigate the active tab to a saved bookmark. The saved-login row can store a username/password for the active tab's current origin and fill a selected saved login without exposing the password to page JavaScript, Codex panes, or SDK responses. The Codex controls open a left, right, or bottom pane for the active tab by deriving a session from the active tab's current origin and minting an origin-bound grant for the pane URL; set `TELESCOPE_CODEX_URL` to prefill that pane URL in desktop chrome or omit the URL from `telescope desktop open-codex`. The chrome can also narrow the pane to read-only, no-credential, no-interaction, or script-enabled access. The same chrome lists open Codex panes with their permission summary and can stop one directly; scoped pane stops revoke the backing grant before the runtime closes the pane. `telescope desktop handoff --json` exports the owner-visible, non-secret state needed to reorient after switching shells or SSH hosts; `--output <path>` writes the same JSON to a private file; `--restore <path>` opens the captured tab URLs and imports bookmarks into the current browser instance. SDK-created browser tabs open as native webviews inside the main browser window and share the main browser profile plus the same page-context IPC bridge. New tabs become active, tab-strip clicks queue `activate_tab`, and inactive tab webviews stay hidden in the workspace. Desktop profiles restore the previous browser tab URLs and active tab on launch; if a URL is passed on the command line, it is opened as the active tab alongside restored tabs. Codex panes are also docked into the main browser window: left and right panes occupy side columns, bottom panes occupy a bottom strip, and multiple panes on the same edge split that edge. All Codex panes share a separate agent profile so the user only has to sign into Codex once, without sharing user-site cookies into that pane.
# telescope-browser
