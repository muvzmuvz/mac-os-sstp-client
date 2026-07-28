//! Default-route snapshot/heal safety net. This is the one part of the
//! pre-rewrite design that stays almost entirely as originally hardened
//! this session (multiple real incidents, see the memory of this
//! project) — a broken default route after a VPN teardown is just as
//! possible with our own worker process as it was with pppd (a crash
//! mid-negotiation, a killed worker, a kernel hiccup), so the same
//! snapshot-before/heal-after strategy applies. What changed is *what*
//! counts as "our own tunnel's interface": no more hardcoded `ppp0` +
//! `pgrep pppd`, since the interface name is now a dynamically assigned
//! `utunN` recorded in `ipc::VpnStatusFile` alongside the worker's own pid.

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use crate::elevate::{run_elevated, shell_quote};
use crate::ipc;
use crate::log::{append_to, vpn_log_path};

fn route_snapshot_path() -> PathBuf {
    let dir =
        dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")).join("Library/Application Support/sstp-gui");
    let _ = std::fs::create_dir_all(&dir);
    dir.join("pre-vpn-gateway.txt")
}

pub fn current_default_route() -> Option<(String, String)> {
    let out = Command::new("route").args(["-n", "get", "default"]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let gateway = text.lines().find_map(|l| l.trim().strip_prefix("gateway: "))?.trim().to_string();
    let iface = text.lines().find_map(|l| l.trim().strip_prefix("interface: "))?.trim().to_string();
    Some((gateway, iface))
}

/// True if `iface` is a utun interface that's genuinely still backed by
/// our own live worker process — i.e. the status file agrees this exact
/// interface belongs to a worker whose pid is still alive. Catches the
/// generalized version of the old "ppp0 zombie" case: a utun interface
/// that still exists (or a route still pointing at one) even though the
/// process that owned it is long gone.
fn owned_by_live_worker(iface: &str) -> bool {
    let Some(status) = ipc::read_status() else { return false };
    let Some(status_iface) = status.interface.as_deref() else { return false };
    if status_iface != iface {
        return false;
    }
    status.pid.is_some_and(ipc::pid_alive)
}

/// True only if there's a default route, its interface actually still
/// exists, *and* (when that interface is one of our utun tunnels) the
/// worker process that owns it is still alive.
pub fn has_default_route() -> bool {
    let Some((_, iface)) = current_default_route() else { return false };
    if iface.starts_with("utun") && !owned_by_live_worker(&iface) {
        return false;
    }
    Command::new("ifconfig").arg(&iface).output().map(|o| o.status.success()).unwrap_or(false)
}

/// Snapshots the current (pre-VPN) gateway to disk before connecting, so it
/// can be restored even if the app or the whole machine restarts before a
/// clean disconnect happens. Skips saving when the current default route
/// already points at one of our own live tunnels (nothing "pre-VPN" to
/// capture in that case — matches the old `iface != "ppp0"` guard).
pub fn save_route_snapshot() {
    if let Some((gateway, iface)) = current_default_route()
        && !(iface.starts_with("utun") && owned_by_live_worker(&iface))
    {
        let _ = std::fs::write(route_snapshot_path(), gateway);
    }
}

fn load_route_snapshot() -> Option<String> {
    std::fs::read_to_string(route_snapshot_path()).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

fn clear_route_snapshot() {
    let _ = std::fs::remove_file(route_snapshot_path());
}

/// Flushes the DNS resolver cache and, if a worker pid is recorded and
/// still alive, force-kills it. A worker that dies mid-negotiation or gets
/// killed can leave macOS's SystemConfiguration store pointing at DNS
/// servers only the now-dead tunnel could reach -- the machine looks
/// "offline" even when the default route itself is fine, and nothing but
/// this flush (or a reboot) clears it. This replaces the old
/// `pkill -9 -f sstpc/pppd` fragment: there's no external process to
/// pattern-match by name anymore, just our own worker's recorded pid.
fn cleanup_fragment() -> String {
    let mut cmd = String::from("dscacheutil -flushcache 2>/dev/null; killall -HUP mDNSResponder 2>/dev/null");
    if let Some(status) = ipc::read_status()
        && let Some(pid) = status.pid
        && ipc::pid_alive(pid)
    {
        cmd = format!("kill -9 {pid} 2>/dev/null; {cmd}");
    }
    cmd
}

/// Logs `ps`/route diagnostics so a disconnect/heal failure leaves forensic
/// evidence in the log instead of just "it didn't work".
pub fn log_network_diagnostics(context: &str) {
    let route_info = current_default_route();
    let status = ipc::read_status();
    append_to(
        &vpn_log_path(),
        &format!(
            "[diagnostics: {context}]\ncurrent default route: {route_info:?}\nrecorded vpn status: {status:?}"
        ),
    );
}

/// Guards against two `heal_route_if_broken` calls racing each other, e.g.
/// `spawn_disconnect`'s own call and `logic()`'s next 3-second status poll
/// both firing for the same teardown -- the poll loop can't tell a heal
/// that `spawn_disconnect` already kicked off (on its own detached thread,
/// with no access to `self.last_heal_attempt`) is still in flight, sees the
/// route still broken a moment later, and starts a second concurrent
/// elevated fix-up. That doubled every log line *and* the admin-password
/// prompt for a single disconnect. Since this function already spawns its
/// own thread and returns immediately, the natural place to prevent
/// overlapping runs is here, not in every caller.
static HEALING_IN_PROGRESS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

struct HealGuard;
impl Drop for HealGuard {
    fn drop(&mut self) {
        HEALING_IN_PROGRESS.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Checks the default route and, if it's broken, restores it from the saved
/// pre-VPN snapshot. Cheap (no admin prompt) when the route is already
/// fine; only escalates to `run_elevated` when there's actually no working
/// default route. Safe to call from the UI thread. A no-op if a previous
/// call's healing thread is still in flight (see `HEALING_IN_PROGRESS`).
///
/// The snapshot is only ever cleared after a *confirmed* successful
/// restore, and the restore itself is retried a few times -- both lessons
/// from this session's real incidents where a single failed attempt (or
/// clearing the snapshot regardless of outcome) permanently lost the only
/// way back to a working default route short of a reboot.
///
/// `notify_on_recovery` controls only the "your internet is back" success
/// notification, not whether the restore itself happens -- restoring the
/// pre-VPN gateway is needed after *every* disconnect (the VPN always owns
/// the default route while it's up), but that's routine teardown, not a
/// failure. `spawn_disconnect` (a normal, user-initiated disconnect) passes
/// `false`, since surfacing routine teardown as "Восстановлен доступ в
/// интернет после сбоя VPN" (recovered after a VPN failure) was actively
/// misleading. Callers reacting to the tunnel actually dropping
/// unexpectedly (an app-launch-time check after a previous crash, or the
/// status poll noticing a live tunnel died without going through
/// `spawn_disconnect`) pass `true`, since that really is worth telling the
/// user about. A restore *failure* is always worth surfacing regardless,
/// so that notification isn't gated.
pub fn heal_route_if_broken(notify_on_recovery: bool) {
    if has_default_route() {
        clear_route_snapshot();
        return;
    }
    use std::sync::atomic::Ordering;
    if HEALING_IN_PROGRESS.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        return;
    }
    std::thread::spawn(move || {
        let _guard = HealGuard;
        let Some(gw) = load_route_snapshot() else {
            append_to(&vpn_log_path(), "internet looks down and no pre-VPN gateway was saved to restore");
            log_network_diagnostics("heal: no snapshot available");
            let _ = run_elevated(&cleanup_fragment());
            return;
        };
        append_to(&vpn_log_path(), &format!("default route missing after VPN teardown, restoring gateway {gw}..."));
        let route_cmd = format!("route -n add default {gw} 2>/dev/null || route -n change default {gw}; ", gw = shell_quote(&gw));
        const MAX_ATTEMPTS: u32 = 4;
        for attempt in 1..=MAX_ATTEMPTS {
            let _ = run_elevated(&format!("{route_cmd}{}", cleanup_fragment()));
            if has_default_route() {
                append_to(&vpn_log_path(), &format!("default route restored (attempt {attempt}/{MAX_ATTEMPTS})"));
                if notify_on_recovery {
                    crate::elevate::show_notification(crate::i18n::t().notif_app_name, crate::i18n::t().notif_restored_after_failure);
                }
                clear_route_snapshot();
                return;
            }
            if attempt < MAX_ATTEMPTS {
                std::thread::sleep(Duration::from_secs(2));
            }
        }
        append_to(&vpn_log_path(), "failed to restore default route automatically after retries, keeping snapshot for the next attempt");
        log_network_diagnostics("heal: restore failed after retries");
        crate::elevate::show_notification(crate::i18n::t().notif_app_name, crate::i18n::t().notif_restore_failed);
    });
}
