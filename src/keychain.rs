//! macOS Keychain access for saved profile passwords.

use std::process::Command;

const SERVICE_NAME: &str = "sstp-gui";

/// Keychain entries are keyed by profile id (stable and unique), not by
/// username, so two profiles can share the same username on different
/// servers.
pub fn keychain_set(profile_id: &str, password: &str) -> bool {
    let _ = Command::new("security").args(["delete-generic-password", "-a", profile_id, "-s", SERVICE_NAME]).output();
    Command::new("security")
        .args(["add-generic-password", "-a", profile_id, "-s", SERVICE_NAME, "-w", password, "-U"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub fn keychain_get(profile_id: &str) -> Option<String> {
    let out =
        Command::new("security").args(["find-generic-password", "-a", profile_id, "-s", SERVICE_NAME, "-w"]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let pw = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!pw.is_empty()).then_some(pw)
}

pub fn keychain_delete(profile_id: &str) {
    let _ = Command::new("security").args(["delete-generic-password", "-a", profile_id, "-s", SERVICE_NAME]).output();
}
