//! File-based coordination between the unprivileged GUI process and the
//! root-elevated worker process (see `worker.rs`) that owns the actual
//! `utun` interface and TLS connection. Everything here follows the same
//! pattern the rest of this app already relies on throughout this
//! session's hardening work: small files under
//! `~/Library/Application Support/sstp-gui/`, polled rather than pushed,
//! because a `do shell script ... with administrator privileges` call
//! gives no realtime channel back to the caller.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

fn support_dir() -> PathBuf {
    let dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")).join("Library/Application Support/sstp-gui");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

pub fn status_path() -> PathBuf {
    support_dir().join("vpn-status.json")
}

pub fn disconnect_marker_path() -> PathBuf {
    support_dir().join("disconnect-requested")
}

fn pending_password_path() -> PathBuf {
    support_dir().join("pending-password")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerState {
    Connecting,
    Connected,
    Disconnected,
    Error,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VpnStatusFile {
    pub state: Option<WorkerState>,
    pub interface: Option<String>,
    pub local_ip: Option<String>,
    pub peer_ip: Option<String>,
    pub dns1: Option<String>,
    pub dns2: Option<String>,
    pub message: Option<String>,
    /// The worker process's own pid, so a reader can tell a "connected"
    /// status left over from a crashed/killed worker apart from a real,
    /// still-running one (`has_default_route`'s job in `route.rs`).
    pub pid: Option<u32>,
}

pub fn write_status(status: &VpnStatusFile) {
    if let Ok(json) = serde_json::to_string_pretty(status) {
        let _ = std::fs::write(status_path(), json);
    }
}

pub fn read_status() -> Option<VpnStatusFile> {
    let content = std::fs::read_to_string(status_path()).ok()?;
    serde_json::from_str(&content).ok()
}

pub fn clear_status() {
    let _ = std::fs::remove_file(status_path());
}

/// True if `pid` names a process that's still alive. Uses `kill(pid, 0)`
/// (signal 0: no-op, just an existence/permission check) rather than
/// shelling out, since we already need `libc` for `utun.rs`.
///
/// The worker this is almost always called about runs as root (see
/// `worker.rs`) while this GUI process runs as the regular user, so
/// `kill()` on a live worker pid fails with `EPERM` -- the kernel checks
/// the target exists before it checks permission, so `EPERM` actually
/// *proves* the process is alive; only `ESRCH` means it's really gone.
/// Treating `EPERM` as "dead" (a bare `ret == 0` check) was the actual bug
/// behind the status display getting stuck on "Connecting" forever even
/// once the tunnel was fully up.
pub fn pid_alive(pid: u32) -> bool {
    let ret = unsafe { libc::kill(pid as libc::pid_t, 0) };
    ret == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Writes `password` to a `0600` file only the current user can read, for
/// the about-to-be-elevated worker process to consume — this keeps the
/// password out of `ps`/process-argument visibility, the same reasoning
/// `build_connect_command` used to write pppd's `chap-secrets` file rather
/// than pass a password as a bare argument.
pub fn write_pending_password(password: &str) -> std::io::Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let path = pending_password_path();
    std::fs::write(&path, password)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(path)
}

/// Reads and immediately deletes the pending-password file; called once by
/// the worker at startup. Deleting it even if the read fails avoids ever
/// leaving a stale plaintext password sitting on disk.
pub fn take_pending_password() -> std::io::Result<String> {
    let path = pending_password_path();
    let result = std::fs::read_to_string(&path);
    let _ = std::fs::remove_file(&path);
    result
}

pub fn request_disconnect() {
    let _ = std::fs::write(disconnect_marker_path(), b"");
}

pub fn disconnect_requested() -> bool {
    disconnect_marker_path().exists()
}

pub fn clear_disconnect_request() {
    let _ = std::fs::remove_file(disconnect_marker_path());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_round_trips_through_json() {
        let status = VpnStatusFile {
            state: Some(WorkerState::Connected),
            interface: Some("utun7".to_string()),
            local_ip: Some("10.100.1.21".to_string()),
            peer_ip: Some("10.100.1.250".to_string()),
            dns1: Some("172.19.50.203".to_string()),
            dns2: None,
            message: None,
            pid: Some(12345),
        };
        let json = serde_json::to_string(&status).unwrap();
        let restored: VpnStatusFile = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.state, Some(WorkerState::Connected));
        assert_eq!(restored.interface.as_deref(), Some("utun7"));
        assert_eq!(restored.pid, Some(12345));
    }

    #[test]
    fn current_process_pid_is_alive_and_pid_one_style_bogus_check() {
        let my_pid = std::process::id();
        assert!(pid_alive(my_pid));
        // A pid essentially guaranteed not to exist right now.
        assert!(!pid_alive(999_999));
    }

    #[test]
    fn pid_alive_treats_a_root_owned_process_as_alive() {
        // pid 1 (launchd on macOS) is always root-owned and always
        // running; an unprivileged test process signaling it always gets
        // EPERM, never ESRCH -- this is exactly the case that broke the
        // worker-liveness check (the worker runs as root, this GUI doesn't).
        assert!(pid_alive(1), "EPERM must count as alive, not dead");
    }
}
