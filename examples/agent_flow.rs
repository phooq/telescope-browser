use telescope_sdk::TelescopeClient;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = if let Ok(path) = std::env::var("TELESCOPE_CONTROL_FILE") {
        TelescopeClient::from_control_file(path)?
    } else {
        TelescopeClient::from_env()?
    };

    let session = client.create_session(["https://example.com"], true)?;
    let tab = client.create_tab(Some("https://example.com/login"), Some(&session.id))?;

    println!("created session {} and tab {}", session.id, tab.id);
    Ok(())
}
