use clap::{Args, Parser, Subcommand};
use directories::ProjectDirs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use telescope_control::{bind_control_server, serve_server, ControlPlane};
use telescope_core::{CredentialInput, CredentialVault, OsKeyringStore};
use telescope_sdk::{
    BookmarkRecord, CommandExecutionReport, ElementReference, HandoffRestoreReport,
    HandoffSnapshot, PageContextSnapshot, PanePosition, ScopedAgentPaneOptions, TelescopeClient,
};

#[derive(Debug, Parser)]
#[command(name = "telescope")]
#[command(about = "Rust browser and agent-control prototype")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Serve {
        #[arg(long, default_value = "127.0.0.1:47639")]
        addr: String,
        #[arg(long, env = "TELESCOPE_TOKEN")]
        token: Option<String>,
        #[arg(long, default_value = "default")]
        profile: String,
    },
    Credential {
        #[command(subcommand)]
        command: CredentialCommand,
    },
    Desktop {
        #[command(flatten)]
        target: DesktopTarget,
        #[command(subcommand)]
        command: DesktopCommand,
    },
}

#[derive(Debug, Subcommand)]
enum CredentialCommand {
    Add {
        origin: String,
        username: String,
        #[arg(long, env = "TELESCOPE_PASSWORD")]
        password: String,
        #[arg(long)]
        login_url: Option<String>,
        #[arg(long)]
        label: Option<String>,
        #[arg(long, default_value = "default")]
        profile: String,
    },
    List {
        #[arg(long, default_value = "default")]
        profile: String,
    },
    Delete {
        credential_id: String,
        #[arg(long, default_value = "default")]
        profile: String,
    },
}

#[derive(Debug, Args)]
struct DesktopTarget {
    #[arg(long, env = "TELESCOPE_CONTROL_FILE")]
    control_file: Option<PathBuf>,
    #[arg(long, env = "TELESCOPE_URL")]
    url: Option<String>,
    #[arg(long, env = "TELESCOPE_TOKEN")]
    token: Option<String>,
    #[arg(long, default_value = "default")]
    profile: String,
}

#[derive(Debug, Subcommand)]
enum DesktopCommand {
    ActiveTab {
        #[arg(long)]
        json: bool,
    },
    Tabs {
        #[arg(long)]
        json: bool,
    },
    Open {
        url: String,
        #[arg(long)]
        tab_id: Option<String>,
        #[arg(long)]
        json: bool,
    },
    NewTab {
        url: Option<String>,
        #[arg(long)]
        json: bool,
    },
    ActivateTab {
        tab_id: String,
        #[arg(long)]
        json: bool,
    },
    CloseTab {
        tab_id: String,
        #[arg(long)]
        json: bool,
    },
    Context {
        #[arg(long)]
        tab_id: Option<String>,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    Refs {
        #[arg(long)]
        tab_id: Option<String>,
        #[arg(long)]
        json: bool,
    },
    Results {
        #[arg(long)]
        tab_id: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    Sessions {
        #[arg(long)]
        json: bool,
    },
    RevokeSession {
        session_id: String,
        #[arg(long)]
        json: bool,
    },
    Grants {
        #[arg(long)]
        json: bool,
    },
    RevokeGrant {
        token: String,
        #[arg(long)]
        json: bool,
    },
    Back {
        #[arg(long)]
        tab_id: Option<String>,
        #[arg(long)]
        json: bool,
    },
    Forward {
        #[arg(long)]
        tab_id: Option<String>,
        #[arg(long)]
        json: bool,
    },
    Reload {
        #[arg(long)]
        tab_id: Option<String>,
        #[arg(long)]
        json: bool,
    },
    OpenCodex {
        url: Option<String>,
        #[arg(long)]
        tab_id: Option<String>,
        #[arg(long, default_value = "right", value_parser = parse_pane_position)]
        position: PanePosition,
        #[arg(long, default_value_t = 3600)]
        ttl_seconds: u64,
        #[arg(
            long,
            conflicts_with_all = ["no_credentials", "no_interactions", "allow_scripts"]
        )]
        read_only: bool,
        #[arg(long)]
        no_credentials: bool,
        #[arg(long)]
        no_interactions: bool,
        #[arg(long)]
        allow_scripts: bool,
        #[arg(long)]
        json: bool,
    },
    Credentials {
        #[command(subcommand)]
        command: DesktopCredentialCommand,
    },
    Bookmarks {
        #[command(subcommand)]
        command: DesktopBookmarkCommand,
    },
    ClosePane {
        pane_id: String,
        #[arg(long)]
        json: bool,
    },
    StopPane {
        pane_id: String,
        #[arg(long)]
        json: bool,
    },
    Audit {
        #[arg(long)]
        json: bool,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    Doctor {
        #[arg(long)]
        json: bool,
    },
    Handoff {
        #[arg(long)]
        json: bool,
        #[arg(long, conflicts_with = "restore")]
        output: Option<PathBuf>,
        #[arg(long, conflicts_with = "output")]
        restore: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum DesktopCredentialCommand {
    List {
        #[arg(long)]
        tab_id: Option<String>,
        #[arg(long)]
        json: bool,
    },
    Save {
        username: String,
        #[arg(long, env = "TELESCOPE_PASSWORD")]
        password: String,
        #[arg(long)]
        tab_id: Option<String>,
        #[arg(long)]
        json: bool,
    },
    Fill {
        #[arg(long)]
        tab_id: Option<String>,
        #[arg(long)]
        credential_id: Option<String>,
        #[arg(long)]
        wait_seconds: Option<u64>,
        #[arg(long)]
        json: bool,
    },
    Delete {
        credential_id: String,
        #[arg(long)]
        tab_id: Option<String>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum DesktopBookmarkCommand {
    List {
        #[arg(long)]
        json: bool,
    },
    Save {
        #[arg(long)]
        tab_id: Option<String>,
        #[arg(long)]
        title: Option<String>,
        #[arg(long)]
        json: bool,
    },
    Open {
        bookmark_id: String,
        #[arg(long)]
        tab_id: Option<String>,
        #[arg(long, conflicts_with = "tab_id")]
        new_tab: bool,
        #[arg(long)]
        json: bool,
    },
    Delete {
        bookmark_id: String,
        #[arg(long)]
        json: bool,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Command::Serve {
            addr,
            token,
            profile,
        } => {
            let token = token.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
            let plane = ControlPlane::with_profile_storage(
                open_vault(&profile)?,
                audit_log_path(&profile)?,
                bookmark_path(&profile)?,
            )?;
            let (server, endpoint) = bind_control_server(&addr)?;
            let control_file = write_control_file(&profile_dir(&profile)?, &endpoint, &token)?;
            eprintln!("telescope control listening on {endpoint}");
            eprintln!("TELESCOPE_TOKEN={token}");
            eprintln!("TELESCOPE_CONTROL_FILE={}", control_file.display());
            serve_server(server, token, plane)?;
        }
        Command::Credential { command } => match command {
            CredentialCommand::Add {
                origin,
                username,
                password,
                login_url,
                label,
                profile,
            } => {
                let mut vault = open_vault(&profile)?;
                let record = vault.put(CredentialInput {
                    origin,
                    username,
                    password,
                    login_url,
                    label,
                })?;
                println!("stored {} for {}", record.id, record.origin);
            }
            CredentialCommand::List { profile } => {
                let vault = open_vault(&profile)?;
                for record in vault.list() {
                    println!("{}\t{}\t{}", record.id, record.origin, record.username);
                }
            }
            CredentialCommand::Delete {
                credential_id,
                profile,
            } => {
                let mut vault = open_vault(&profile)?;
                vault.delete(&credential_id)?;
                println!("deleted {credential_id}");
            }
        },
        Command::Desktop { target, command } => match command {
            DesktopCommand::Doctor { json } => run_desktop_doctor(&target, json)?,
            command => {
                let client = open_desktop_client(&target)?;
                run_desktop_command(&client, command)?;
            }
        },
    }

    Ok(())
}

fn run_desktop_command(
    client: &TelescopeClient,
    command: DesktopCommand,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        DesktopCommand::ActiveTab { json } => {
            let tab = client.active_tab()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&tab)?);
            } else if let Some(tab) = tab {
                print_tab(&tab);
            } else {
                println!("no active tab");
            }
        }
        DesktopCommand::Tabs { json } => {
            let tabs = client.list_tabs()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&tabs)?);
            } else {
                for tab in &tabs {
                    print_tab(tab);
                }
            }
        }
        DesktopCommand::Open { url, tab_id, json } => {
            let tab = match tab_id {
                Some(tab_id) => client.navigate(&tab_id, &url, None)?,
                None => match client.active_tab()? {
                    Some(tab) => client.navigate(&tab.id, &url, None)?,
                    None => client.create_tab(Some(&url), None)?,
                },
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&tab)?);
            } else {
                print_tab(&tab);
            }
        }
        DesktopCommand::NewTab { url, json } => {
            let tab = client.create_tab(url.as_deref(), None)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&tab)?);
            } else {
                print_tab(&tab);
            }
        }
        DesktopCommand::ActivateTab { tab_id, json } => {
            let tab = client.activate_tab(&tab_id)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&tab)?);
            } else {
                print_tab(&tab);
            }
        }
        DesktopCommand::CloseTab { tab_id, json } => {
            let tab = client.close_tab(&tab_id)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&tab)?);
            } else {
                print_tab(&tab);
            }
        }
        DesktopCommand::Context {
            tab_id,
            limit,
            json,
        } => {
            let tab_id = match tab_id {
                Some(tab_id) => tab_id,
                None => active_tab_id(client)?,
            };
            let context = client.page_context_for_tab(&tab_id)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&context)?);
            } else if let Some(context) = context {
                print_page_context(&context, limit);
            } else {
                println!("no page context for tab {tab_id}");
            }
        }
        DesktopCommand::Refs { tab_id, json } => {
            let tab_id = match tab_id {
                Some(tab_id) => tab_id,
                None => active_tab_id(client)?,
            };
            let refs = client.list_element_references_for_tab(&tab_id)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&refs)?);
            } else if refs.is_empty() {
                println!("no element refs for tab {tab_id}");
            } else {
                for reference in &refs {
                    print_element_reference(reference);
                }
            }
        }
        DesktopCommand::Results {
            tab_id,
            limit,
            json,
        } => {
            let mut results = client.list_command_results()?;
            if let Some(tab_id) = tab_id {
                results.retain(|result| result.tab_id == tab_id);
            }
            let start = results.len().saturating_sub(limit);
            let results = results[start..].to_vec();
            if json {
                println!("{}", serde_json::to_string_pretty(&results)?);
            } else if results.is_empty() {
                println!("no command results");
            } else {
                for result in &results {
                    print_command_result(result);
                }
            }
        }
        DesktopCommand::Sessions { json } => {
            let sessions = client.list_sessions()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&sessions)?);
            } else {
                for session in &sessions {
                    print_session(session);
                }
            }
        }
        DesktopCommand::RevokeSession { session_id, json } => {
            let revoked = client.revoke_session(&session_id)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&revoked)?);
            } else {
                println!(
                    "revoked session {}\tclosed panes {}\trevoked grants {}\tdetached tabs {}\tpurged commands {}",
                    revoked.session_id,
                    revoked.closed_pane_ids.len(),
                    revoked.revoked_grant_count,
                    revoked.detached_tab_ids.len(),
                    revoked.purged_command_ids.len()
                );
            }
        }
        DesktopCommand::Grants { json } => {
            let grants = client.list_agent_grants()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&grants)?);
            } else {
                for grant in &grants {
                    print_grant(grant);
                }
            }
        }
        DesktopCommand::RevokeGrant { token, json } => {
            let revoked = client.revoke_agent_grant(&token)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&revoked)?);
            } else {
                println!(
                    "revoked grant {}\tclosed panes {}\tpurged commands {}",
                    revoked.token,
                    revoked.closed_pane_ids.len(),
                    revoked.purged_command_ids.len()
                );
            }
        }
        DesktopCommand::Back { tab_id, json } => {
            let tab_id = match tab_id {
                Some(tab_id) => tab_id,
                None => active_tab_id(client)?,
            };
            let command = client.go_back(&tab_id)?;
            print_queued_command("queued back command", &command, json)?;
        }
        DesktopCommand::Forward { tab_id, json } => {
            let tab_id = match tab_id {
                Some(tab_id) => tab_id,
                None => active_tab_id(client)?,
            };
            let command = client.go_forward(&tab_id)?;
            print_queued_command("queued forward command", &command, json)?;
        }
        DesktopCommand::Reload { tab_id, json } => {
            let tab_id = match tab_id {
                Some(tab_id) => tab_id,
                None => active_tab_id(client)?,
            };
            let command = client.reload_tab(&tab_id)?;
            print_queued_command("queued reload command", &command, json)?;
        }
        DesktopCommand::OpenCodex {
            url,
            tab_id,
            position,
            ttl_seconds,
            read_only,
            no_credentials,
            no_interactions,
            allow_scripts,
            json,
        } => {
            let url = codex_url_from_arg_or_env(url)?;
            let options = open_codex_options(
                url,
                position,
                ttl_seconds,
                read_only,
                no_credentials,
                no_interactions,
                allow_scripts,
            );
            let opened = match tab_id {
                Some(tab_id) => {
                    client.open_scoped_agent_pane_for_tab_with_options(&tab_id, options)?
                }
                None => client.open_codex_pane_for_active_tab_with_options(options)?,
            };
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "pane": opened.pane,
                        "grant": opened.grant,
                        "connection": opened.connection,
                    }))?
                );
            } else {
                println!(
                    "opened pane {}\ttab {}\tsession {}",
                    opened.pane.id, opened.connection.tab_id, opened.connection.session_id
                );
            }
        }
        DesktopCommand::Credentials { command } => {
            run_desktop_credential_command(client, command)?;
        }
        DesktopCommand::Bookmarks { command } => {
            run_desktop_bookmark_command(client, command)?;
        }
        DesktopCommand::ClosePane { pane_id, json } => {
            let closed = client.close_agent_pane(&pane_id)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&closed)?);
            } else {
                println!("closed pane {}", closed.id);
            }
        }
        DesktopCommand::StopPane { pane_id, json } => {
            let stopped = client.stop_agent_pane(&pane_id)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&stopped)?);
            } else {
                print_stopped_pane(&stopped);
            }
        }
        DesktopCommand::Audit { json, limit } => {
            let events = client.list_audit_events()?;
            let start = events.len().saturating_sub(limit);
            let events = events[start..].to_vec();
            if json {
                println!("{}", serde_json::to_string_pretty(&events)?);
            } else {
                for event in events {
                    println!(
                        "{}\t{}\t{}",
                        event.created_at_unix,
                        event.id,
                        serde_json::to_string(&event.kind)?
                    );
                }
            }
        }
        DesktopCommand::Handoff {
            json,
            output,
            restore,
        } => {
            if let Some(path) = restore {
                let snapshot =
                    serde_json::from_str::<HandoffSnapshot>(&std::fs::read_to_string(&path)?)?;
                let summary = client.restore_handoff_snapshot(&snapshot)?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&summary)?);
                } else {
                    print_handoff_restore_summary(&summary);
                }
                return Ok(());
            }

            let snapshot = client.handoff_snapshot()?;
            let output_path = if let Some(path) = output {
                let body = serde_json::to_vec_pretty(&snapshot)?;
                write_private_file(&path, &body)?;
                Some(path)
            } else {
                None
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&snapshot)?);
            } else {
                print_handoff_snapshot(&snapshot)?;
                if let Some(path) = output_path {
                    println!("saved_handoff\t{}", path.display());
                }
            }
        }
        DesktopCommand::Doctor { .. } => {
            unreachable!("desktop doctor is handled before client setup")
        }
    }

    Ok(())
}

fn active_tab_id(client: &TelescopeClient) -> Result<String, Box<dyn std::error::Error>> {
    Ok(client.active_tab()?.ok_or("cannot find an active tab")?.id)
}

#[derive(Debug)]
struct DesktopDoctorReport {
    profile: String,
    profile_dir: String,
    profile_dir_exists: bool,
    control_file: String,
    control_file_source: String,
    control_file_exists: bool,
    control_file_readable: bool,
    control_file_valid: bool,
    control_file_error: Option<String>,
    target_status: String,
    platform: String,
    webview_runtime: String,
    webview_hint: String,
    webview_checks: Vec<DesktopDoctorCheck>,
}

#[derive(Debug)]
struct DesktopDoctorCheck {
    name: String,
    status: String,
    detail: String,
}

fn run_desktop_doctor(
    target: &DesktopTarget,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let report = desktop_doctor_report(target)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&desktop_doctor_report_json(&report))?
        );
    } else {
        print_desktop_doctor_report(&report);
    }
    Ok(())
}

fn desktop_doctor_report(
    target: &DesktopTarget,
) -> Result<DesktopDoctorReport, Box<dyn std::error::Error>> {
    let profile_dir = profile_dir(&target.profile)?;
    let control_file = target
        .control_file
        .clone()
        .unwrap_or(default_control_file(&target.profile)?);
    let control_file_source = if target.control_file.is_some() {
        "explicit"
    } else {
        "profile"
    };
    let control_file_inspection = inspect_control_file(&control_file);
    let platform = std::env::consts::OS.to_string();
    let target_status = desktop_doctor_target_status(
        target.url.is_some(),
        target.token.is_some(),
        control_file_inspection.exists,
    );

    Ok(DesktopDoctorReport {
        profile: target.profile.clone(),
        profile_dir_exists: profile_dir.is_dir(),
        profile_dir: profile_dir.display().to_string(),
        control_file: control_file.display().to_string(),
        control_file_source: control_file_source.to_string(),
        control_file_exists: control_file_inspection.exists,
        control_file_readable: control_file_inspection.readable,
        control_file_valid: control_file_inspection.valid,
        control_file_error: control_file_inspection.error,
        target_status: target_status.to_string(),
        webview_runtime: webview_runtime_for_os(&platform).to_string(),
        webview_hint: webview_hint_for_os(&platform).to_string(),
        webview_checks: webview_checks_for_os(&platform),
        platform,
    })
}

fn desktop_doctor_report_json(report: &DesktopDoctorReport) -> serde_json::Value {
    serde_json::json!({
        "profile": report.profile,
        "profile_dir": report.profile_dir,
        "profile_dir_exists": report.profile_dir_exists,
        "control_file": report.control_file,
        "control_file_source": report.control_file_source,
        "control_file_exists": report.control_file_exists,
        "control_file_readable": report.control_file_readable,
        "control_file_valid": report.control_file_valid,
        "control_file_error": report.control_file_error,
        "target_status": report.target_status,
        "platform": report.platform,
        "webview_runtime": report.webview_runtime,
        "webview_hint": report.webview_hint,
        "webview_checks": report.webview_checks.iter().map(|check| {
            serde_json::json!({
                "name": check.name,
                "status": check.status,
                "detail": check.detail,
            })
        }).collect::<Vec<_>>(),
    })
}

#[derive(Debug)]
struct ControlFileInspection {
    exists: bool,
    readable: bool,
    valid: bool,
    error: Option<String>,
}

fn inspect_control_file(path: &Path) -> ControlFileInspection {
    if !path.exists() {
        return ControlFileInspection {
            exists: false,
            readable: false,
            valid: false,
            error: Some("control file does not exist".to_string()),
        };
    }

    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) => {
            return ControlFileInspection {
                exists: true,
                readable: false,
                valid: false,
                error: Some(error.to_string()),
            };
        }
    };
    let value = match serde_json::from_str::<serde_json::Value>(&text) {
        Ok(value) => value,
        Err(error) => {
            return ControlFileInspection {
                exists: true,
                readable: true,
                valid: false,
                error: Some(error.to_string()),
            };
        }
    };
    let valid = value
        .get("url")
        .and_then(|item| item.as_str())
        .is_some_and(|item| !item.trim().is_empty())
        && value
            .get("owner_token")
            .and_then(|item| item.as_str())
            .is_some_and(|item| !item.trim().is_empty());

    ControlFileInspection {
        exists: true,
        readable: true,
        valid,
        error: (!valid).then(|| "control file is missing url or owner_token".to_string()),
    }
}

fn desktop_doctor_target_status(
    has_url: bool,
    has_token: bool,
    has_control_file: bool,
) -> &'static str {
    match (has_url, has_token, has_control_file) {
        (true, true, _) => "direct-url-token",
        (true, false, _) => "missing-token",
        (false, true, _) => "missing-url",
        (false, false, true) => "control-file",
        (false, false, false) => "control-file-missing",
    }
}

fn webview_runtime_for_os(os: &str) -> &'static str {
    match os {
        "linux" => "WebKitGTK",
        "macos" => "WKWebView",
        "windows" => "WebView2",
        _ => "unsupported",
    }
}

fn webview_hint_for_os(os: &str) -> &'static str {
    match os {
        "linux" => {
            "Install pkg-config, WebKitGTK 4.1, GTK 3, GLib, GDK Pixbuf, Pango, and libsoup development packages."
        }
        "macos" => "Install the Xcode command line tools.",
        "windows" => {
            "Install Microsoft C++ build tools. The WebView2 runtime is built into current Windows installs and available as a redistributable for older systems."
        }
        _ => "Telescope desktop has not declared a webview backend for this OS.",
    }
}

fn webview_checks_for_os(os: &str) -> Vec<DesktopDoctorCheck> {
    if os != "linux" {
        return vec![DesktopDoctorCheck {
            name: webview_runtime_for_os(os).to_string(),
            status: "info".to_string(),
            detail: webview_hint_for_os(os).to_string(),
        }];
    }

    [
        "webkit2gtk-4.1",
        "gtk+-3.0",
        "glib-2.0",
        "gdk-pixbuf-2.0",
        "pango",
    ]
    .into_iter()
    .map(pkg_config_check)
    .collect()
}

fn pkg_config_check(package: &str) -> DesktopDoctorCheck {
    let status = std::process::Command::new("pkg-config")
        .arg("--exists")
        .arg(package)
        .status();
    match status {
        Ok(status) if status.success() => DesktopDoctorCheck {
            name: package.to_string(),
            status: "ok".to_string(),
            detail: "pkg-config found the package".to_string(),
        },
        Ok(_) => DesktopDoctorCheck {
            name: package.to_string(),
            status: "missing".to_string(),
            detail: "pkg-config could not find the package".to_string(),
        },
        Err(error) => DesktopDoctorCheck {
            name: package.to_string(),
            status: "unknown".to_string(),
            detail: format!("could not run pkg-config: {error}"),
        },
    }
}

fn print_desktop_doctor_report(report: &DesktopDoctorReport) {
    println!("profile\t{}", report.profile);
    println!("profile_dir\t{}", report.profile_dir);
    println!("profile_dir_exists\t{}", yes_no(report.profile_dir_exists));
    println!(
        "control_file\t{}\t{}",
        report.control_file, report.control_file_source
    );
    println!(
        "control_file_exists\t{}",
        yes_no(report.control_file_exists)
    );
    println!(
        "control_file_readable\t{}",
        yes_no(report.control_file_readable)
    );
    println!("control_file_valid\t{}", yes_no(report.control_file_valid));
    if let Some(error) = &report.control_file_error {
        println!("control_file_error\t{error}");
    }
    println!("target_status\t{}", report.target_status);
    println!("platform\t{}", report.platform);
    println!("webview_runtime\t{}", report.webview_runtime);
    println!("webview_hint\t{}", report.webview_hint);
    for check in &report.webview_checks {
        println!(
            "webview_check\t{}\t{}\t{}",
            check.name, check.status, check.detail
        );
    }
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn open_codex_options(
    url: String,
    position: PanePosition,
    ttl_seconds: u64,
    read_only: bool,
    no_credentials: bool,
    no_interactions: bool,
    allow_scripts: bool,
) -> ScopedAgentPaneOptions {
    let mut options = if read_only {
        ScopedAgentPaneOptions::read_only(url, position)
    } else {
        ScopedAgentPaneOptions::interactive(url, position)
            .with_credentials(!no_credentials)
            .with_interactions(!no_interactions)
            .with_scripts(allow_scripts)
    };
    options.ttl_seconds = Some(ttl_seconds);
    options
}

fn codex_url_from_arg_or_env(url: Option<String>) -> Result<String, Box<dyn std::error::Error>> {
    let url = url
        .or_else(|| std::env::var("TELESCOPE_CODEX_URL").ok())
        .ok_or("open-codex needs a URL or TELESCOPE_CODEX_URL")?;
    let url = url.trim();
    if url.is_empty() {
        return Err("open-codex URL cannot be empty".into());
    }
    Ok(url.to_string())
}

fn print_queued_command(
    label: &str,
    command: &telescope_sdk::BrowserCommand,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if json {
        println!("{}", serde_json::to_string_pretty(command)?);
    } else {
        println!("{label} {}", command.id);
    }
    Ok(())
}

fn run_desktop_credential_command(
    client: &TelescopeClient,
    command: DesktopCredentialCommand,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        DesktopCredentialCommand::List { tab_id, json } => {
            let tab_id = desktop_command_tab_id(client, tab_id)?;
            let credentials = client.list_credentials_for_tab(&tab_id)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&credentials)?);
            } else {
                for credential in credentials {
                    println!(
                        "{}\t{}\t{}",
                        credential.id, credential.origin, credential.username
                    );
                }
            }
        }
        DesktopCredentialCommand::Save {
            username,
            password,
            tab_id,
            json,
        } => {
            let tab_id = desktop_command_tab_id(client, tab_id)?;
            let credential = client.store_credential_for_tab(&tab_id, &username, &password)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&credential)?);
            } else {
                println!("stored {} for {}", credential.id, credential.origin);
            }
        }
        DesktopCredentialCommand::Fill {
            tab_id,
            credential_id,
            wait_seconds,
            json,
        } => {
            let tab_id = desktop_command_tab_id(client, tab_id)?;
            let credential_id = match credential_id {
                Some(credential_id) => credential_id,
                None => {
                    client
                        .list_credentials_for_tab(&tab_id)?
                        .into_iter()
                        .next()
                        .ok_or("target tab has no saved credentials")?
                        .id
                }
            };
            let command = client.fill_credential_for_tab(&tab_id, &credential_id)?;
            if let Some(wait_seconds) = wait_seconds {
                let result = client
                    .wait_for_command_result(&command.id, Duration::from_secs(wait_seconds))?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&result)?);
                } else {
                    print_command_result(&result);
                }
            } else if json {
                println!("{}", serde_json::to_string_pretty(&command)?);
            } else {
                println!("queued fill command {}", command.id);
            }
        }
        DesktopCredentialCommand::Delete {
            credential_id,
            tab_id,
            json,
        } => {
            let tab_id = desktop_command_tab_id(client, tab_id)?;
            client.delete_credential_for_tab(&tab_id, &credential_id)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "deleted": true,
                        "credential_id": credential_id,
                    }))?
                );
            } else {
                println!("deleted {credential_id}");
            }
        }
    }

    Ok(())
}

fn desktop_command_tab_id(
    client: &TelescopeClient,
    tab_id: Option<String>,
) -> Result<String, Box<dyn std::error::Error>> {
    match tab_id {
        Some(tab_id) => Ok(tab_id),
        None => active_tab_id(client),
    }
}

fn run_desktop_bookmark_command(
    client: &TelescopeClient,
    command: DesktopBookmarkCommand,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        DesktopBookmarkCommand::List { json } => {
            let bookmarks = client.list_bookmarks()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&bookmarks)?);
            } else {
                for bookmark in &bookmarks {
                    print_bookmark(bookmark);
                }
            }
        }
        DesktopBookmarkCommand::Save {
            tab_id,
            title,
            json,
        } => {
            let tab_id = desktop_command_tab_id(client, tab_id)?;
            let bookmark = client.bookmark_tab(&tab_id, title.as_deref())?;
            if json {
                println!("{}", serde_json::to_string_pretty(&bookmark)?);
            } else {
                println!("saved bookmark {}\t{}", bookmark.id, bookmark.url);
            }
        }
        DesktopBookmarkCommand::Open {
            bookmark_id,
            tab_id,
            new_tab,
            json,
        } => {
            let bookmark = client
                .list_bookmarks()?
                .into_iter()
                .find(|bookmark| bookmark.id == bookmark_id)
                .ok_or("bookmark not found")?;
            let tab = if new_tab {
                client.create_tab(Some(&bookmark.url), None)?
            } else {
                match tab_id {
                    Some(tab_id) => client.navigate(&tab_id, &bookmark.url, None)?,
                    None => match client.active_tab()? {
                        Some(tab) => client.navigate(&tab.id, &bookmark.url, None)?,
                        None => client.create_tab(Some(&bookmark.url), None)?,
                    },
                }
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&tab)?);
            } else {
                println!("opened bookmark {}\tin tab {}", bookmark.id, tab.id);
            }
        }
        DesktopBookmarkCommand::Delete { bookmark_id, json } => {
            let bookmark = client.delete_bookmark(&bookmark_id)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&bookmark)?);
            } else {
                println!("deleted bookmark {}\t{}", bookmark.id, bookmark.url);
            }
        }
    }

    Ok(())
}

fn print_bookmark(bookmark: &BookmarkRecord) {
    println!(
        "{}\t{}\t{}",
        bookmark.id,
        bookmark.url,
        bookmark.title.as_deref().unwrap_or("")
    );
}

fn print_handoff_snapshot(snapshot: &HandoffSnapshot) -> Result<(), Box<dyn std::error::Error>> {
    println!("generated\t{}", snapshot.generated_at_unix);
    match &snapshot.active_tab {
        Some(tab) => println!(
            "active_tab\t{}\t{}\t{}",
            tab.id,
            tab.current_url.as_deref().unwrap_or("about:blank"),
            tab.title.as_deref().unwrap_or("")
        ),
        None => println!("active_tab\tnone"),
    }
    println!(
        "counts\ttabs={}\tsessions={}\tbookmarks={}\tpanes={}\tpage_contexts={}\telement_refs={}\tcommand_results={}\taudit_events={}",
        snapshot.tabs.len(),
        snapshot.sessions.len(),
        snapshot.bookmarks.len(),
        snapshot.agent_panes.len(),
        snapshot.page_contexts.len(),
        snapshot.element_refs.len(),
        snapshot.command_results.len(),
        snapshot.audit_events.len()
    );

    for tab in &snapshot.tabs {
        println!(
            "tab\t{}\t{}\t{}",
            tab.id,
            tab.current_url.as_deref().unwrap_or("about:blank"),
            tab.title.as_deref().unwrap_or("")
        );
    }
    for bookmark in &snapshot.bookmarks {
        println!(
            "bookmark\t{}\t{}\t{}",
            bookmark.id,
            bookmark.url,
            bookmark.title.as_deref().unwrap_or("")
        );
    }
    for pane in &snapshot.agent_panes {
        println!(
            "pane\t{}\t{:?}\t{}\t{}",
            pane.id,
            pane.position,
            pane.attached_tab_id.as_deref().unwrap_or(""),
            pane.url
        );
    }
    for event in snapshot.audit_events.iter().rev().take(5).rev() {
        println!(
            "audit\t{}\t{}\t{}",
            event.created_at_unix,
            event.id,
            serde_json::to_string(&event.kind)?
        );
    }

    Ok(())
}

fn print_handoff_restore_summary(summary: &HandoffRestoreReport) {
    println!(
        "restored\ttabs={}\tskipped_tabs={}\tbookmarks={}\tactive_tab={}",
        summary.opened_tabs.len(),
        summary.skipped_tabs,
        summary.imported_bookmarks.len(),
        summary.active_tab_id.as_deref().unwrap_or("")
    );
    for tab in &summary.opened_tabs {
        println!(
            "tab\t{}\t{}\t{}",
            tab.tab_id,
            tab.url,
            if tab.active { "active" } else { "" }
        );
    }
    for bookmark in &summary.imported_bookmarks {
        println!("bookmark\t{}\t{}", bookmark.bookmark_id, bookmark.url);
    }
}

fn open_vault(profile: &str) -> Result<CredentialVault, Box<dyn std::error::Error>> {
    let profile_dir = profile_dir(profile)?;
    ensure_private_profile_dir(&profile_dir)?;
    let index_path = profile_dir.join("credentials.json");
    Ok(CredentialVault::open(
        profile,
        index_path,
        Arc::new(OsKeyringStore::default()),
    )?)
}

fn default_control_file(profile: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(profile_dir(profile)?.join("control.json"))
}

fn audit_log_path(profile: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(profile_dir(profile)?.join("audit.jsonl"))
}

fn bookmark_path(profile: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(profile_dir(profile)?.join("bookmarks.json"))
}

fn profile_dir(profile: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dirs = ProjectDirs::from("dev", "Telescope", "Telescope")
        .ok_or("could not resolve platform data directory")?;
    Ok(dirs.data_dir().join("profiles").join(profile))
}

fn write_control_file(
    profile_dir: &Path,
    endpoint: &str,
    owner_token: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
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
        std::fs::write(&path, body)?;
    }

    Ok(path)
}

fn ensure_private_profile_dir(profile_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(profile_dir)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(profile_dir, std::fs::Permissions::from_mode(0o700))?;
    }

    Ok(())
}

fn write_private_file(path: &Path, body: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(body)?;
        file.sync_all()?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }

    #[cfg(not(unix))]
    {
        std::fs::write(path, body)?;
    }

    Ok(())
}

fn open_desktop_client(
    target: &DesktopTarget,
) -> Result<TelescopeClient, Box<dyn std::error::Error>> {
    match (&target.url, &target.token) {
        (Some(url), Some(token)) => Ok(TelescopeClient::new(url, token)?),
        (Some(_), None) => Err("TELESCOPE_TOKEN or --token is required with --url".into()),
        (None, Some(_)) => Err("TELESCOPE_URL or --url is required with --token".into()),
        (None, None) => {
            let control_file = target
                .control_file
                .clone()
                .unwrap_or(default_control_file(&target.profile)?);
            Ok(TelescopeClient::from_control_file(control_file)?)
        }
    }
}

fn parse_pane_position(input: &str) -> Result<PanePosition, String> {
    match input {
        "left" => Ok(PanePosition::Left),
        "right" => Ok(PanePosition::Right),
        "bottom" => Ok(PanePosition::Bottom),
        _ => Err("expected left, right, or bottom".to_string()),
    }
}

fn print_tab(tab: &telescope_sdk::TabState) {
    println!(
        "{}\t{}\t{}",
        tab.id,
        tab.current_url.as_deref().unwrap_or("about:blank"),
        tab.title.as_deref().unwrap_or("")
    );
}

fn print_page_context(context: &PageContextSnapshot, limit: usize) {
    println!(
        "context\t{}\t{}\t{}\tcaptured={}",
        context.tab_id,
        context.url,
        context.title.as_deref().unwrap_or(""),
        context.captured_at_unix
    );
    if let Some(selected_element_id) = &context.selected_element_id {
        println!("selected\t{}", compact_cell(selected_element_id, 240));
    }
    if let Some(text_preview) = &context.text_preview {
        println!("text\t{}", compact_cell(text_preview, 500));
    }

    let shown = context.interactive_elements.len().min(limit);
    println!(
        "interactive_elements\tshown={}\ttotal={}",
        shown,
        context.interactive_elements.len()
    );
    for element in context.interactive_elements.iter().take(limit) {
        let bounds = element
            .bounds
            .as_ref()
            .map(|bounds| {
                format!(
                    "{:.0},{:.0},{:.0}x{:.0}",
                    bounds.x, bounds.y, bounds.width, bounds.height
                )
            })
            .unwrap_or_default();
        println!(
            "element\t{}\t{}\t{}\t{}\t{}\t{}",
            compact_cell(&element.selector, 240),
            compact_cell(element.role.as_deref().unwrap_or(&element.tag_name), 80),
            compact_cell(element.label.as_deref().unwrap_or(""), 160),
            compact_cell(element.text.as_deref().unwrap_or(""), 160),
            element.input_type.as_deref().unwrap_or(""),
            bounds
        );
    }
}

fn print_element_reference(reference: &ElementReference) {
    let bounds = reference
        .bounds
        .as_ref()
        .map(|bounds| {
            format!(
                "{:.0},{:.0},{:.0}x{:.0}",
                bounds.x, bounds.y, bounds.width, bounds.height
            )
        })
        .unwrap_or_default();
    println!(
        "{}\t{}\t{}\t{}\t{}\t{}\t{}\tcreated={}",
        reference.id,
        reference.tab_id,
        compact_cell(&reference.selector, 240),
        compact_cell(reference.role.as_deref().unwrap_or(""), 80),
        compact_cell(reference.label.as_deref().unwrap_or(""), 160),
        compact_cell(reference.text.as_deref().unwrap_or(""), 160),
        bounds,
        reference.created_at_unix
    );
}

fn print_command_result(result: &CommandExecutionReport) {
    println!(
        "{}\t{}\t{}\t{}\tsession={}\torigin={}\t{}",
        result.completed_at_unix,
        result.command_id,
        result.tab_id,
        command_result_status_label(result),
        result.session_id.as_deref().unwrap_or(""),
        result
            .target_origin
            .as_ref()
            .map(|origin| origin.display_url())
            .unwrap_or_default(),
        compact_cell(result.message.as_deref().unwrap_or(""), 500)
    );
}

fn command_result_status_label(result: &CommandExecutionReport) -> &'static str {
    match &result.status {
        telescope_sdk::CommandExecutionStatus::Succeeded => "succeeded",
        telescope_sdk::CommandExecutionStatus::Failed => "failed",
    }
}

fn compact_cell(value: &str, max_chars: usize) -> String {
    let compact = value.split_whitespace().collect::<Vec<_>>().join(" ");
    let char_count = compact.chars().count();
    if char_count <= max_chars {
        return compact;
    }

    let keep = max_chars.saturating_sub(3);
    let mut truncated = compact.chars().take(keep).collect::<String>();
    truncated.push_str("...");
    truncated
}

fn print_session(session: &telescope_sdk::AgentSession) {
    let origins = session
        .policy
        .allowed_origins
        .iter()
        .map(|origin| origin.display_url())
        .collect::<Vec<_>>()
        .join(",");
    println!(
        "{}\torigins={}\tcredentials={}\tinteractions={}\tscripts={}\texpires={}",
        session.id,
        origins,
        session.policy.allow_credentials,
        session.policy.allow_interactions,
        session.policy.allow_scripts,
        session
            .policy
            .expires_at_unix
            .map(|value| value.to_string())
            .unwrap_or_else(|| "never".to_string())
    );
}

fn print_grant(grant: &telescope_sdk::AgentGrant) {
    let tabs = if grant.allowed_tab_ids.is_empty() {
        "*".to_string()
    } else {
        grant.allowed_tab_ids.join(",")
    };
    let client_origins = if grant.allowed_client_origins.is_empty() {
        "*".to_string()
    } else {
        grant
            .allowed_client_origins
            .iter()
            .map(|origin| origin.display_url())
            .collect::<Vec<_>>()
            .join(",")
    };
    println!(
        "{}\tsession={}\ttabs={}\tclient_origins={}\texpires={}",
        grant.token,
        grant.session_id,
        tabs,
        client_origins,
        grant
            .expires_at_unix
            .map(|value| value.to_string())
            .unwrap_or_else(|| "never".to_string())
    );
}

fn print_stopped_pane(stopped: &telescope_sdk::StoppedAgentPane) {
    match stopped {
        telescope_sdk::StoppedAgentPane::RevokedGrant(revoked) => {
            println!(
                "revoked grant {}\tclosed panes {}\tpurged commands {}",
                revoked.token,
                revoked.closed_pane_ids.len(),
                revoked.purged_command_ids.len()
            );
        }
        telescope_sdk::StoppedAgentPane::ClosedPane(pane) => {
            println!("closed pane {}", pane.id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pane_positions() {
        assert_eq!(parse_pane_position("left").unwrap(), PanePosition::Left);
        assert_eq!(parse_pane_position("right").unwrap(), PanePosition::Right);
        assert_eq!(parse_pane_position("bottom").unwrap(), PanePosition::Bottom);
        assert!(parse_pane_position("top").is_err());
    }

    #[test]
    fn desktop_doctor_reports_target_status_without_network() {
        assert_eq!(
            desktop_doctor_target_status(true, true, false),
            "direct-url-token"
        );
        assert_eq!(
            desktop_doctor_target_status(true, false, true),
            "missing-token"
        );
        assert_eq!(
            desktop_doctor_target_status(false, true, true),
            "missing-url"
        );
        assert_eq!(
            desktop_doctor_target_status(false, false, true),
            "control-file"
        );
        assert_eq!(
            desktop_doctor_target_status(false, false, false),
            "control-file-missing"
        );
    }

    #[test]
    fn desktop_doctor_maps_platform_webview_runtime() {
        assert_eq!(webview_runtime_for_os("linux"), "WebKitGTK");
        assert_eq!(webview_runtime_for_os("macos"), "WKWebView");
        assert_eq!(webview_runtime_for_os("windows"), "WebView2");
        assert_eq!(webview_runtime_for_os("freebsd"), "unsupported");
    }

    #[test]
    fn desktop_doctor_validates_control_file_shape_without_exposing_token() {
        let mut dir = std::env::temp_dir();
        dir.push(format!("telescope-cli-doctor-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("control.json");
        std::fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({
                "url": "http://127.0.0.1:47639",
                "owner_token": "owner-token",
            }))
            .unwrap(),
        )
        .unwrap();

        let valid = inspect_control_file(&path);
        assert!(valid.exists);
        assert!(valid.readable);
        assert!(valid.valid);
        assert_eq!(valid.error, None);

        std::fs::write(&path, br#"{"url":"http://127.0.0.1:47639"}"#).unwrap();
        let invalid = inspect_control_file(&path);
        assert!(invalid.exists);
        assert!(invalid.readable);
        assert!(!invalid.valid);
        assert_eq!(
            invalid.error.as_deref(),
            Some("control file is missing url or owner_token")
        );

        let missing = inspect_control_file(&dir.join("missing.json"));
        assert!(!missing.exists);
        assert!(!missing.readable);
        assert!(!missing.valid);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn open_codex_options_default_to_interactive_without_scripts() {
        let options = open_codex_options(
            "https://codex.example/login".to_string(),
            PanePosition::Right,
            600,
            false,
            false,
            false,
            false,
        );

        assert_eq!(options.url, "https://codex.example/login");
        assert_eq!(options.position, PanePosition::Right);
        assert!(options.allow_credentials);
        assert!(options.allow_interactions);
        assert!(!options.allow_scripts);
        assert_eq!(options.ttl_seconds, Some(600));
    }

    #[test]
    fn open_codex_options_support_script_only_profile() {
        let options = open_codex_options(
            "https://codex.example/login".to_string(),
            PanePosition::Left,
            60,
            false,
            true,
            true,
            true,
        );

        assert!(!options.allow_credentials);
        assert!(!options.allow_interactions);
        assert!(options.allow_scripts);
        assert_eq!(options.ttl_seconds, Some(60));
    }

    #[test]
    fn open_codex_read_only_conflicts_with_permission_toggles() {
        let parsed = Cli::try_parse_from([
            "telescope",
            "desktop",
            "--url",
            "http://127.0.0.1:47639",
            "--token",
            "owner-token",
            "open-codex",
            "https://codex.example/login",
            "--read-only",
            "--allow-scripts",
        ]);

        assert!(parsed.is_err());
    }

    #[test]
    fn open_codex_can_target_specific_tab() {
        let parsed = Cli::try_parse_from([
            "telescope",
            "desktop",
            "--url",
            "http://127.0.0.1:47639",
            "--token",
            "owner-token",
            "open-codex",
            "https://codex.example/login",
            "--tab-id",
            "tab-1",
            "--position",
            "bottom",
            "--read-only",
            "--json",
        ])
        .unwrap();

        assert!(matches!(
            parsed.command,
            Command::Desktop {
                command:
                    DesktopCommand::OpenCodex {
                        url: Some(url),
                        tab_id: Some(tab_id),
                        position: PanePosition::Bottom,
                        read_only: true,
                        json: true,
                        ..
                    },
                ..
            } if url == "https://codex.example/login" && tab_id == "tab-1"
        ));
    }

    #[test]
    fn open_codex_url_can_come_from_environment() {
        let parsed = Cli::try_parse_from([
            "telescope",
            "desktop",
            "--url",
            "http://127.0.0.1:47639",
            "--token",
            "owner-token",
            "open-codex",
            "--position",
            "left",
        ])
        .unwrap();

        assert!(matches!(
            parsed.command,
            Command::Desktop {
                command: DesktopCommand::OpenCodex {
                    url: None,
                    position: PanePosition::Left,
                    ..
                },
                ..
            }
        ));

        assert_eq!(
            codex_url_from_arg_or_env(Some(" https://codex.example/login ".to_string())).unwrap(),
            "https://codex.example/login"
        );
    }

    #[test]
    fn desktop_access_lifecycle_commands_parse() {
        let doctor = Cli::try_parse_from(["telescope", "desktop", "doctor", "--json"]).unwrap();
        assert!(matches!(
            doctor.command,
            Command::Desktop {
                command: DesktopCommand::Doctor { json: true },
                ..
            }
        ));

        let sessions = Cli::try_parse_from([
            "telescope",
            "desktop",
            "--url",
            "http://127.0.0.1:47639",
            "--token",
            "owner-token",
            "sessions",
            "--json",
        ])
        .unwrap();
        assert!(matches!(
            sessions.command,
            Command::Desktop {
                command: DesktopCommand::Sessions { json: true },
                ..
            }
        ));

        let revoke = Cli::try_parse_from([
            "telescope",
            "desktop",
            "--url",
            "http://127.0.0.1:47639",
            "--token",
            "owner-token",
            "revoke-session",
            "session-1",
        ])
        .unwrap();
        assert!(matches!(
            revoke.command,
            Command::Desktop {
                command: DesktopCommand::RevokeSession {
                    session_id,
                    json: false
                },
                ..
            } if session_id == "session-1"
        ));

        let grants = Cli::try_parse_from([
            "telescope",
            "desktop",
            "--url",
            "http://127.0.0.1:47639",
            "--token",
            "owner-token",
            "grants",
            "--json",
        ])
        .unwrap();
        assert!(matches!(
            grants.command,
            Command::Desktop {
                command: DesktopCommand::Grants { json: true },
                ..
            }
        ));

        let open = Cli::try_parse_from([
            "telescope",
            "desktop",
            "--url",
            "http://127.0.0.1:47639",
            "--token",
            "owner-token",
            "open",
            "https://example.com",
            "--json",
        ])
        .unwrap();
        assert!(matches!(
            open.command,
            Command::Desktop {
                command:
                    DesktopCommand::Open {
                        url,
                        tab_id: None,
                        json: true
                    },
                ..
            } if url == "https://example.com"
        ));

        let open_targeted = Cli::try_parse_from([
            "telescope",
            "desktop",
            "--url",
            "http://127.0.0.1:47639",
            "--token",
            "owner-token",
            "open",
            "https://example.com/target",
            "--tab-id",
            "tab-1",
        ])
        .unwrap();
        assert!(matches!(
            open_targeted.command,
            Command::Desktop {
                command:
                    DesktopCommand::Open {
                        url,
                        tab_id: Some(tab_id),
                        json: false
                    },
                ..
            } if url == "https://example.com/target" && tab_id == "tab-1"
        ));

        let new_tab = Cli::try_parse_from([
            "telescope",
            "desktop",
            "--url",
            "http://127.0.0.1:47639",
            "--token",
            "owner-token",
            "new-tab",
            "https://example.com/new",
        ])
        .unwrap();
        assert!(matches!(
            new_tab.command,
            Command::Desktop {
                command:
                    DesktopCommand::NewTab {
                        url: Some(url),
                        json: false
                    },
                ..
            } if url == "https://example.com/new"
        ));

        let activate_tab = Cli::try_parse_from([
            "telescope",
            "desktop",
            "--url",
            "http://127.0.0.1:47639",
            "--token",
            "owner-token",
            "activate-tab",
            "tab-1",
            "--json",
        ])
        .unwrap();
        assert!(matches!(
            activate_tab.command,
            Command::Desktop {
                command:
                    DesktopCommand::ActivateTab {
                        tab_id,
                        json: true
                    },
                ..
            } if tab_id == "tab-1"
        ));

        let close_tab = Cli::try_parse_from([
            "telescope",
            "desktop",
            "--url",
            "http://127.0.0.1:47639",
            "--token",
            "owner-token",
            "close-tab",
            "tab-1",
        ])
        .unwrap();
        assert!(matches!(
            close_tab.command,
            Command::Desktop {
                command:
                    DesktopCommand::CloseTab {
                        tab_id,
                        json: false
                    },
                ..
            } if tab_id == "tab-1"
        ));

        let context = Cli::try_parse_from([
            "telescope",
            "desktop",
            "--url",
            "http://127.0.0.1:47639",
            "--token",
            "owner-token",
            "context",
            "--tab-id",
            "tab-1",
            "--limit",
            "5",
            "--json",
        ])
        .unwrap();
        assert!(matches!(
            context.command,
            Command::Desktop {
                command:
                    DesktopCommand::Context {
                        tab_id: Some(tab_id),
                        limit: 5,
                        json: true
                    },
                ..
            } if tab_id == "tab-1"
        ));

        let refs = Cli::try_parse_from([
            "telescope",
            "desktop",
            "--url",
            "http://127.0.0.1:47639",
            "--token",
            "owner-token",
            "refs",
            "--tab-id",
            "tab-1",
            "--json",
        ])
        .unwrap();
        assert!(matches!(
            refs.command,
            Command::Desktop {
                command:
                    DesktopCommand::Refs {
                        tab_id: Some(tab_id),
                        json: true
                    },
                ..
            } if tab_id == "tab-1"
        ));

        let results = Cli::try_parse_from([
            "telescope",
            "desktop",
            "--url",
            "http://127.0.0.1:47639",
            "--token",
            "owner-token",
            "results",
            "--tab-id",
            "tab-1",
            "--limit",
            "10",
            "--json",
        ])
        .unwrap();
        assert!(matches!(
            results.command,
            Command::Desktop {
                command:
                    DesktopCommand::Results {
                        tab_id: Some(tab_id),
                        limit: 10,
                        json: true
                    },
                ..
            } if tab_id == "tab-1"
        ));

        let credential_fill = Cli::try_parse_from([
            "telescope",
            "desktop",
            "--url",
            "http://127.0.0.1:47639",
            "--token",
            "owner-token",
            "credentials",
            "fill",
            "--tab-id",
            "tab-1",
            "--credential-id",
            "credential-1",
            "--wait-seconds",
            "5",
            "--json",
        ])
        .unwrap();
        assert!(matches!(
            credential_fill.command,
            Command::Desktop {
                command:
                    DesktopCommand::Credentials {
                        command:
                            DesktopCredentialCommand::Fill {
                                tab_id: Some(tab_id),
                                credential_id: Some(credential_id),
                                wait_seconds: Some(5),
                                json: true
                            }
                    },
                ..
            } if tab_id == "tab-1" && credential_id == "credential-1"
        ));

        let bookmark_save = Cli::try_parse_from([
            "telescope",
            "desktop",
            "--url",
            "http://127.0.0.1:47639",
            "--token",
            "owner-token",
            "bookmarks",
            "save",
            "--tab-id",
            "tab-1",
            "--title",
            "Dashboard",
            "--json",
        ])
        .unwrap();
        assert!(matches!(
            bookmark_save.command,
            Command::Desktop {
                command:
                    DesktopCommand::Bookmarks {
                        command:
                            DesktopBookmarkCommand::Save {
                                tab_id: Some(tab_id),
                                title: Some(title),
                                json: true
                            }
                    },
                ..
            } if tab_id == "tab-1" && title == "Dashboard"
        ));

        let bookmark_open = Cli::try_parse_from([
            "telescope",
            "desktop",
            "--url",
            "http://127.0.0.1:47639",
            "--token",
            "owner-token",
            "bookmarks",
            "open",
            "bookmark-1",
            "--tab-id",
            "tab-1",
        ])
        .unwrap();
        assert!(matches!(
            bookmark_open.command,
            Command::Desktop {
                command:
                    DesktopCommand::Bookmarks {
                        command:
                            DesktopBookmarkCommand::Open {
                                bookmark_id,
                                tab_id: Some(tab_id),
                                new_tab: false,
                                json: false
                            }
                    },
                ..
            } if bookmark_id == "bookmark-1" && tab_id == "tab-1"
        ));

        let bookmark_open_new_tab = Cli::try_parse_from([
            "telescope",
            "desktop",
            "--url",
            "http://127.0.0.1:47639",
            "--token",
            "owner-token",
            "bookmarks",
            "open",
            "bookmark-1",
            "--new-tab",
            "--json",
        ])
        .unwrap();
        assert!(matches!(
            bookmark_open_new_tab.command,
            Command::Desktop {
                command:
                    DesktopCommand::Bookmarks {
                        command:
                            DesktopBookmarkCommand::Open {
                                bookmark_id,
                                tab_id: None,
                                new_tab: true,
                                json: true
                            }
                    },
                ..
            } if bookmark_id == "bookmark-1"
        ));

        let bookmark_open_conflict = Cli::try_parse_from([
            "telescope",
            "desktop",
            "--url",
            "http://127.0.0.1:47639",
            "--token",
            "owner-token",
            "bookmarks",
            "open",
            "bookmark-1",
            "--new-tab",
            "--tab-id",
            "tab-1",
        ]);
        assert!(bookmark_open_conflict.is_err());

        let back = Cli::try_parse_from([
            "telescope",
            "desktop",
            "--url",
            "http://127.0.0.1:47639",
            "--token",
            "owner-token",
            "back",
            "--tab-id",
            "tab-1",
            "--json",
        ])
        .unwrap();
        assert!(matches!(
            back.command,
            Command::Desktop {
                command:
                    DesktopCommand::Back {
                        tab_id: Some(tab_id),
                        json: true
                    },
                ..
            } if tab_id == "tab-1"
        ));

        let forward = Cli::try_parse_from([
            "telescope",
            "desktop",
            "--url",
            "http://127.0.0.1:47639",
            "--token",
            "owner-token",
            "forward",
            "--tab-id",
            "tab-1",
        ])
        .unwrap();
        assert!(matches!(
            forward.command,
            Command::Desktop {
                command:
                    DesktopCommand::Forward {
                        tab_id: Some(tab_id),
                        json: false
                    },
                ..
            } if tab_id == "tab-1"
        ));

        let reload = Cli::try_parse_from([
            "telescope",
            "desktop",
            "--url",
            "http://127.0.0.1:47639",
            "--token",
            "owner-token",
            "reload",
            "--tab-id",
            "tab-1",
        ])
        .unwrap();
        assert!(matches!(
            reload.command,
            Command::Desktop {
                command:
                    DesktopCommand::Reload {
                        tab_id: Some(tab_id),
                        json: false
                    },
                ..
            } if tab_id == "tab-1"
        ));

        let revoke_grant = Cli::try_parse_from([
            "telescope",
            "desktop",
            "--url",
            "http://127.0.0.1:47639",
            "--token",
            "owner-token",
            "revoke-grant",
            "tg_test",
        ])
        .unwrap();
        assert!(matches!(
            revoke_grant.command,
            Command::Desktop {
                command: DesktopCommand::RevokeGrant { token, json: false },
                ..
            } if token == "tg_test"
        ));

        let stop_pane = Cli::try_parse_from([
            "telescope",
            "desktop",
            "--url",
            "http://127.0.0.1:47639",
            "--token",
            "owner-token",
            "stop-pane",
            "pane-1",
            "--json",
        ])
        .unwrap();
        assert!(matches!(
            stop_pane.command,
            Command::Desktop {
                command: DesktopCommand::StopPane { pane_id, json: true },
                ..
            } if pane_id == "pane-1"
        ));

        let handoff = Cli::try_parse_from([
            "telescope",
            "desktop",
            "--url",
            "http://127.0.0.1:47639",
            "--token",
            "owner-token",
            "handoff",
            "--json",
        ])
        .unwrap();
        assert!(matches!(
            handoff.command,
            Command::Desktop {
                command: DesktopCommand::Handoff {
                    json: true,
                    output: None,
                    restore: None
                },
                ..
            }
        ));

        let handoff_output = Cli::try_parse_from([
            "telescope",
            "desktop",
            "--url",
            "http://127.0.0.1:47639",
            "--token",
            "owner-token",
            "handoff",
            "--output",
            "/tmp/telescope-handoff.json",
        ])
        .unwrap();
        assert!(matches!(
            handoff_output.command,
            Command::Desktop {
                command:
                    DesktopCommand::Handoff {
                        json: false,
                        output: Some(path),
                        restore: None
                    },
                ..
            } if path == PathBuf::from("/tmp/telescope-handoff.json")
        ));

        let handoff_restore = Cli::try_parse_from([
            "telescope",
            "desktop",
            "--url",
            "http://127.0.0.1:47639",
            "--token",
            "owner-token",
            "handoff",
            "--restore",
            "/tmp/telescope-handoff.json",
            "--json",
        ])
        .unwrap();
        assert!(matches!(
            handoff_restore.command,
            Command::Desktop {
                command:
                    DesktopCommand::Handoff {
                        json: true,
                        output: None,
                        restore: Some(path)
                    },
                ..
            } if path == PathBuf::from("/tmp/telescope-handoff.json")
        ));

        let conflicting_handoff = Cli::try_parse_from([
            "telescope",
            "desktop",
            "--url",
            "http://127.0.0.1:47639",
            "--token",
            "owner-token",
            "handoff",
            "--output",
            "/tmp/out.json",
            "--restore",
            "/tmp/in.json",
        ]);
        assert!(conflicting_handoff.is_err());
    }

    #[test]
    fn writes_secure_control_file_for_serve_discovery() {
        let mut dir = std::env::temp_dir();
        dir.push(format!("telescope-cli-control-{}", uuid::Uuid::new_v4()));

        let path = write_control_file(&dir, "http://127.0.0.1:47639", "owner-token").unwrap();
        let body: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(body["url"], "http://127.0.0.1:47639");
        assert_eq!(body["owner_token"], "owner-token");
        assert!(body["warning"].as_str().unwrap().contains("Owner token"));

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
    fn writes_private_handoff_file() {
        let mut dir = std::env::temp_dir();
        dir.push(format!("telescope-cli-handoff-{}", uuid::Uuid::new_v4()));
        let path = dir.join("handoff.json");

        write_private_file(&path, br#"{"tabs":[]}"#).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), r#"{"tabs":[]}"#);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn restores_handoff_snapshot_tabs_and_bookmarks_against_local_server() {
        let plane = ControlPlane::new(CredentialVault::ephemeral(
            "handoff-restore-test",
            Arc::new(telescope_core::MemorySecretStore::new()),
        ));
        let (server, endpoint) = bind_control_server("127.0.0.1:0").unwrap();
        let token = "handoff-restore-token";
        let server_plane = plane.clone();
        std::thread::spawn(move || {
            let _ = serve_server(server, token.to_string(), server_plane);
        });
        let client = TelescopeClient::new(endpoint, token).unwrap();
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

        let summary = client.restore_handoff_snapshot(&snapshot).unwrap();

        assert_eq!(summary.opened_tabs.len(), 2);
        assert_eq!(summary.skipped_tabs, 1);
        assert_eq!(summary.imported_bookmarks.len(), 1);
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

    fn tab_state(id: &str, current_url: Option<&str>) -> telescope_sdk::TabState {
        telescope_sdk::TabState {
            id: id.to_string(),
            current_url: current_url.map(str::to_string),
            session_id: None,
            title: None,
            created_at_unix: 1,
            updated_at_unix: 1,
        }
    }
}
