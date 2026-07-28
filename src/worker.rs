//! The root-elevated worker process: the same `sstp-gui` binary,
//! re-invoked via `do shell script ... with administrator privileges`
//! with `--vpn-worker <server> <username>` (see `elevate::run_elevated`
//! and `main.rs`'s dispatch). This is what actually owns the TLS
//! connection and the `utun` interface for the lifetime of the tunnel —
//! unlike the old design (one-shot elevated shell command running
//! sstpc/pppd in the foreground), this process stays alive and keeps
//! running as root for as long as the VPN is connected, since `utun`
//! creation and route changes both need root and there's no privilege-
//! separated handoff of the fd to an unprivileged process (see the plan
//! doc's "Risks" section on this exact tradeoff).
//!
//! Coordinates with the unprivileged GUI process purely through the files
//! in `ipc.rs`: no realtime IPC channel exists back to the caller of
//! `do shell script`, so status is written to a file the GUI polls, and
//! disconnect requests are read from a marker file this process itself
//! polls.

use std::net::IpAddr;
use std::process::Command;
use std::time::Duration;

use sstp_proto::connection;

use crate::ipc::{self, VpnStatusFile, WorkerState};
use crate::log::{append_to, vpn_log_path};

/// How often the worker checks for a disconnect request while otherwise
/// idle-waiting on the connection's event channel.
const DISCONNECT_POLL_INTERVAL: Duration = Duration::from_millis(500);

pub fn run(server: String, username: String) -> ! {
    let exit_code = match run_inner(server, username) {
        Ok(()) => 0,
        Err(e) => {
            append_to(&vpn_log_path(), &format!("worker error: {e}"));
            ipc::write_status(&VpnStatusFile { state: Some(WorkerState::Error), message: Some(e), ..Default::default() });
            1
        }
    };
    ipc::clear_disconnect_request();
    std::process::exit(exit_code);
}

fn run_inner(server: String, username: String) -> Result<(), String> {
    let password = ipc::take_pending_password().map_err(|e| format!("could not read password handoff file: {e}"))?;
    if password.is_empty() {
        return Err("empty password".to_string());
    }

    append_to(&vpn_log_path(), &format!("worker starting, connecting to {server}..."));
    ipc::write_status(&VpnStatusFile { state: Some(WorkerState::Connecting), pid: Some(std::process::id()), ..Default::default() });

    // Resolved once up front, purely so the protective host route (added
    // once the tunnel comes up) targets the exact address our own TCP
    // connection is using -- see `add_protective_host_route`'s doc comment
    // for why this route exists at all.
    let server_ip = resolve_server_ip(&server).ok_or_else(|| format!("could not resolve {server}"))?;
    let pre_vpn_gateway = crate::route::current_default_route().map(|(gw, _)| gw);

    let runtime = tokio::runtime::Runtime::new().map_err(|e| format!("could not start async runtime: {e}"))?;
    runtime.block_on(async_main(server, username, password, server_ip, pre_vpn_gateway))
}

async fn async_main(
    server: String,
    username: String,
    password: String,
    server_ip: IpAddr,
    pre_vpn_gateway: Option<String>,
) -> Result<(), String> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let mut handle = Some(connection::connect(server, username, password, tx));

    let mut route_protected = false;
    let mut disconnect_sent = false;

    loop {
        tokio::select! {
            event = rx.recv() => {
                match event {
                    Some(connection::Event::Progress(msg)) => {
                        append_to(&vpn_log_path(), &msg);
                    }
                    Some(connection::Event::Connected { interface, negotiated }) => {
                        append_to(&vpn_log_path(), &format!(
                            "connected: interface={interface} local={:?} peer={:?} dns1={:?} dns2={:?}",
                            negotiated.local_ip, negotiated.peer_ip, negotiated.dns1, negotiated.dns2
                        ));

                        if let Some(gw) = &pre_vpn_gateway {
                            add_protective_host_route(server_ip, gw);
                            route_protected = true;
                        } else {
                            append_to(&vpn_log_path(), "no pre-VPN gateway known -- skipping the protective host route (best effort only)");
                        }
                        set_default_route_via_interface(&interface);

                        ipc::write_status(&VpnStatusFile {
                            state: Some(WorkerState::Connected),
                            interface: Some(interface),
                            local_ip: negotiated.local_ip.map(|a| a.to_string()),
                            peer_ip: negotiated.peer_ip.map(|a| a.to_string()),
                            dns1: negotiated.dns1.map(|a| a.to_string()),
                            dns2: negotiated.dns2.map(|a| a.to_string()),
                            pid: Some(std::process::id()),
                            message: None,
                        });
                    }
                    Some(connection::Event::Disconnected) => {
                        append_to(&vpn_log_path(), "disconnected");
                        break;
                    }
                    Some(connection::Event::Error(e)) => {
                        append_to(&vpn_log_path(), &format!("connection error: {e}"));
                        if route_protected {
                            remove_protective_host_route(server_ip);
                        }
                        return Err(e);
                    }
                    None => {
                        // Channel closed without a terminal event -- treat
                        // as a clean-enough disconnect rather than hanging
                        // forever waiting for something that can't arrive.
                        break;
                    }
                }
            }

            _ = tokio::time::sleep(DISCONNECT_POLL_INTERVAL), if !disconnect_sent => {
                if ipc::disconnect_requested() {
                    append_to(&vpn_log_path(), "disconnect requested, tearing down gracefully...");
                    disconnect_sent = true;
                    // `Handle::disconnect` consumes the handle and awaits
                    // the connection task's own exit, which will surface as
                    // a `Disconnected`/`Error` event on `rx` shortly after
                    // (or this call itself returning is enough -- either
                    // way the loop above still drains any trailing event).
                    // `.take()` (rather than moving `handle` directly) is
                    // what lets the borrow checker see this branch can only
                    // ever run once, even though it's guarded at runtime by
                    // `disconnect_sent` rather than provably-once syntax.
                    if let Some(h) = handle.take() {
                        h.disconnect().await;
                    }
                }
            }
        }
    }

    if route_protected {
        remove_protective_host_route(server_ip);
    }
    ipc::write_status(&VpnStatusFile { state: Some(WorkerState::Disconnected), ..Default::default() });
    Ok(())
}

fn resolve_server_ip(server: &str) -> Option<IpAddr> {
    use std::net::ToSocketAddrs;
    server.to_socket_addrs().ok()?.next().map(|a| a.ip())
}

/// Adds a host route to the VPN server's own resolved IP via the original
/// (pre-VPN) gateway, *before* the default route is repointed at the
/// tunnel interface. Without this, the default-route change can route the
/// tunnel's own TLS control connection into itself -- a real incident this
/// session hit with the old pppd-based design (`Unrecoverable socket
/// error, 5` the instant `defaultroute` took effect). A host route
/// (`/32`) always wins over the broader default route in the routing
/// table's longest-prefix-match, so this keeps traffic to the server
/// itself on the original physical link regardless of what the default
/// route points at.
fn add_protective_host_route(server_ip: IpAddr, gateway: &str) {
    let _ = Command::new("/sbin/route").args(["-n", "add", "-host", &server_ip.to_string(), gateway]).status();
}

fn remove_protective_host_route(server_ip: IpAddr) {
    let _ = Command::new("/sbin/route").args(["-n", "delete", "-host", &server_ip.to_string()]).status();
}

/// Points the machine's default route at the tunnel interface -- the
/// direct Rust-owned equivalent of pppd's `defaultroute` option, except
/// this process is already running as root (it had to be, to create the
/// utun fd at all), so no separate elevated shell-out is needed the way
/// `route.rs`'s heal path still requires from the unprivileged GUI process.
fn set_default_route_via_interface(iface: &str) {
    let _ = Command::new("/sbin/route").args(["-n", "delete", "default"]).status();
    let _ = Command::new("/sbin/route").args(["-n", "add", "default", "-interface", iface]).status();
}
