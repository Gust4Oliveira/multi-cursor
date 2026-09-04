//! Sync Multi Cursor account tokens into the stores Cursor Agent CLI reads.
//!
//! The IDE keeps auth in `state.vscdb` (`cursorAuth/*`). The Agent CLI
//! (`cursor-agent` / `agent`) authenticates via macOS Keychain
//! (`cursor-access-token` / `cursor-refresh-token`) and keeps identity
//! metadata in `~/.cursor/cli-config.json` (`authInfo`). Account switches
//! that only rewrite `state.vscdb` leave the CLI on the previous login.

use std::fs;
use std::process::Command;

use serde_json::{json, Map, Value};

use crate::auth::{
    display_name_from_snapshot, email_from_snapshot, has_login_tokens, AuthSnapshot,
};
use crate::paths::{active_dot_cursor_dir, home_dir};

const KEYCHAIN_ACCOUNT: &str = "cursor-user";
const ACCESS_TOKEN_SERVICE: &str = "cursor-access-token";
const REFRESH_TOKEN_SERVICE: &str = "cursor-refresh-token";

fn security_output(args: &[&str]) -> Result<std::process::Output, String> {
    Command::new("security")
        .args(args)
        .output()
        .map_err(|e| format!("Failed to run security {}: {e}", args.first().unwrap_or(&"")))
}

fn delete_keychain_password(service: &str) -> Result<(), String> {
    let output = security_output(&[
        "delete-generic-password",
        "-s",
        service,
        "-a",
        KEYCHAIN_ACCOUNT,
    ])?;
    // Item not found is fine (exit 44 on macOS).
    if output.status.success() || output.status.code() == Some(44) {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("could not be found")
        || stderr.contains("The specified item could not be found")
    {
        return Ok(());
    }
    Err(format!(
        "Failed to delete Keychain item {service}: {}",
        stderr.trim()
    ))
}

fn set_keychain_password(service: &str, password: &str) -> Result<(), String> {
    delete_keychain_password(service)?;
    let output = security_output(&[
        "add-generic-password",
        "-s",
        service,
        "-a",
        KEYCHAIN_ACCOUNT,
        "-w",
        password,
        "-U",
    ])?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "Failed to write Keychain item {service}: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

fn clear_keychain_tokens() -> Result<(), String> {
    delete_keychain_password(ACCESS_TOKEN_SERVICE)?;
    delete_keychain_password(REFRESH_TOKEN_SERVICE)?;
    Ok(())
}

fn write_keychain_tokens(access: &str, refresh: &str) -> Result<(), String> {
    set_keychain_password(ACCESS_TOKEN_SERVICE, access)?;
    set_keychain_password(REFRESH_TOKEN_SERVICE, refresh)?;
    Ok(())
}

fn cli_config_path() -> Result<std::path::PathBuf, String> {
    // Prefer the live ~/.cursor that environment swaps rename into place.
    let live = active_dot_cursor_dir()?.join("cli-config.json");
    if live.exists() {
        return Ok(live);
    }
    Ok(home_dir()?.join(".cursor").join("cli-config.json"))
}

fn update_cli_config_auth_info(auth_info: Option<Value>) -> Result<(), String> {
    let path = cli_config_path()?;
    if !path.exists() {
        // CLI creates this on first run; nothing to rewrite yet.
        return Ok(());
    }

    let raw = fs::read_to_string(&path).map_err(|e| format!("Read cli-config.json: {e}"))?;
    let mut value: Value =
        serde_json::from_str(&raw).map_err(|e| format!("Parse cli-config.json: {e}"))?;
    let obj = value
        .as_object_mut()
        .ok_or_else(|| "cli-config.json root must be an object".to_string())?;

    match auth_info {
        Some(info) => {
            obj.insert("authInfo".to_string(), info);
        }
        None => {
            obj.remove("authInfo");
        }
    }

    let pretty = serde_json::to_string_pretty(&value)
        .map_err(|e| format!("Serialize cli-config.json: {e}"))?;
    fs::write(&path, format!("{pretty}\n")).map_err(|e| format!("Write cli-config.json: {e}"))?;
    Ok(())
}

fn auth_info_from_snapshot(snap: &AuthSnapshot) -> Value {
    let mut map = Map::new();
    if let Some(email) = email_from_snapshot(snap) {
        map.insert("email".to_string(), json!(email));
    }
    if let Some(name) = display_name_from_snapshot(snap) {
        map.insert("displayName".to_string(), json!(name));
    }
    // Drop stale userId / authId / team* from a previous account so
    // `agent about` re-derives identity from the Keychain tokens instead of
    // showing the old login.
    Value::Object(map)
}

/// Push account tokens into Keychain + `cli-config.json` for cursor-agent.
pub fn sync_cli_auth_from_snapshot(snap: &AuthSnapshot) -> Result<(), String> {
    if !has_login_tokens(snap) {
        return clear_cli_auth();
    }

    let access = snap
        .keys
        .get("cursorAuth/accessToken")
        .map(String::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "Missing access token in account snapshot".to_string())?;
    let refresh = snap
        .keys
        .get("cursorAuth/refreshToken")
        .map(String::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "Missing refresh token in account snapshot".to_string())?;

    write_keychain_tokens(access, refresh)?;
    update_cli_config_auth_info(Some(auth_info_from_snapshot(snap)))?;
    Ok(())
}

/// Clear Agent CLI credentials (Keychain + cli-config authInfo).
pub fn clear_cli_auth() -> Result<(), String> {
    clear_keychain_tokens()?;
    update_cli_config_auth_info(None)?;
    Ok(())
}
