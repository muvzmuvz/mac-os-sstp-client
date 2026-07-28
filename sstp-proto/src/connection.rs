//! The async I/O layer: owns the TLS connection and (once negotiated) the
//! utun interface, drives [`crate::engine::Engine`] with whatever arrives
//! on either, and exposes a small channel-based API to the rest of the
//! app. This is the one module in this crate that fundamentally can't be
//! unit-tested without a live server and root (see the plan doc's Phase 0),
//! so it's kept deliberately thin: every actual protocol decision lives in
//! `engine.rs` (which has 60+ tests covering it), this module just moves
//! bytes between sockets and that engine, and reacts to the events it
//! produces.
//!
//! macOS-only (same as `utun.rs`, which this depends on): this app has
//! never targeted other platforms (the GUI itself already depends on
//! `objc2`/AppKit), so there's no cross-platform abstraction to maintain
//! here.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::engine::{Engine, EngineEvent};
use crate::ipcp::NegotiatedConfig;
use crate::packet::{self, PacketReader};
use crate::utun::Utun;

/// How long to wait with no bytes received at all before sending an
/// `ECHO_REQUEST`, and how many consecutive unanswered echoes to tolerate
/// before giving up on the link — mirrors `sstp-state.c`'s own policy
/// (`sstp_state_recv`'s `SSTP_TIMEOUT` handling, `ctx->echo > 4`).
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_UNANSWERED_ECHOES: u32 = 4;

#[derive(Debug)]
pub enum Event {
    /// A milestone in the handshake worth logging -- not a state change the
    /// GUI needs to react to, just enough breadcrumb detail that a failure
    /// says *where* it happened (TCP vs TLS vs HTTP vs SSTP) instead of
    /// only what the final error was. This is what was missing when an
    /// earlier live failure only surfaced as an opaque top-level error with
    /// no indication of which phase it failed in.
    Progress(String),
    /// PPP/SSTP negotiation finished; the interface is configured and
    /// ready for traffic.
    Connected { interface: String, negotiated: NegotiatedConfig },
    /// The tunnel ended -- cleanly (a DISCONNECT/DISCONNECT_ACK exchange,
    /// either side initiated) or because the transport just died.
    Disconnected,
    /// Something unrecoverable happened; no further events follow.
    Error(String),
}

/// A handle to a running connection task. Dropping this *without* calling
/// [`Handle::disconnect`] leaves the background task running — always
/// disconnect explicitly (or let the whole process exit, which the OS
/// cleans up unconditionally, unlike a killed pppd's kernel-side state).
pub struct Handle {
    disconnect_tx: mpsc::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

impl Handle {
    /// Requests a graceful disconnect (SSTP `DISCONNECT`, waiting briefly
    /// for `DISCONNECT_ACK`) and waits for the connection task to fully
    /// exit before returning. Always terminates -- there is no failure
    /// mode here that leaves anything running, unlike pppd's SIGKILL/zombie
    /// interface problems this whole project used to fight.
    pub async fn disconnect(self) {
        let _ = self.disconnect_tx.send(()).await;
        let _ = self.task.await;
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("could not reach {0}: {1}")]
    Tcp(String, std::io::Error),
    #[error("TLS handshake failed: {0}")]
    Tls(#[from] native_tls::Error),
    #[error("server presented no certificate")]
    NoCertificate,
    #[error("invalid server address {0}")]
    InvalidServerName(String),
    #[error("utun interface error: {0}")]
    Utun(#[from] crate::utun::UtunError),
    #[error("{0}")]
    Protocol(String),
}

/// Starts connecting to `server` (`"host:port"`) in the background.
/// Returns immediately with a [`Handle`]; progress and the eventual
/// outcome (including handshake failures) are reported through `events`,
/// since the handshake, negotiation, and steady-state forwarding all share
/// one continuous read loop over the same TLS stream and can't cleanly be
/// split into a synchronous "connect" phase followed by a separate
/// background phase.
pub fn connect(server: String, username: String, password: String, events: mpsc::UnboundedSender<Event>) -> Handle {
    let (disconnect_tx, disconnect_rx) = mpsc::channel(1);
    let task = tokio::spawn(run(server, username, password, events, disconnect_rx));
    Handle { disconnect_tx, task }
}

async fn run(server: String, username: String, password: String, events: mpsc::UnboundedSender<Event>, disconnect_rx: mpsc::Receiver<()>) {
    match run_inner(&server, &username, &password, &events, disconnect_rx).await {
        Ok(()) => {
            let _ = events.send(Event::Disconnected);
        }
        Err(e) => {
            let _ = events.send(Event::Error(e.to_string()));
        }
    }
}

async fn run_inner(
    server: &str,
    username: &str,
    password: &str,
    events: &mpsc::UnboundedSender<Event>,
    mut disconnect_rx: mpsc::Receiver<()>,
) -> Result<(), ConnectError> {
    let host = server.rsplit_once(':').map(|(h, _)| h).unwrap_or(server);

    if host.is_empty() {
        return Err(ConnectError::InvalidServerName(server.to_string()));
    }

    let tcp = tokio::net::TcpStream::connect(server).await.map_err(|e| ConnectError::Tcp(server.to_string(), e))?;
    tcp.set_nodelay(true).ok();
    let _ = events.send(Event::Progress(format!("TCP connected to {server}")));

    let connector = tokio_native_tls::TlsConnector::from(crate::tls::client_config()?);
    let mut tls = connector.connect(host, tcp).await?;
    let _ = events.send(Event::Progress("TLS handshake completed".to_string()));

    let cert_der = tls
        .get_ref()
        .peer_certificate()
        .map_err(ConnectError::Tls)?
        .ok_or(ConnectError::NoCertificate)?
        .to_der()
        .map_err(ConnectError::Tls)?;

    // --- HTTP handshake ---
    let correlation_id = uuid::Uuid::new_v4().to_string();
    let request = crate::http::build_request(server, &correlation_id);
    tls.write_all(&request).await.map_err(|e| ConnectError::Protocol(format!("could not send SSTP HTTP request: {e}")))?;

    let mut http_buf = Vec::new();
    let body_offset = loop {
        let mut chunk = [0u8; 4096];
        let n = tls.read(&mut chunk).await.map_err(|e| ConnectError::Protocol(format!("HTTP handshake read failed: {e}")))?;
        if n == 0 {
            return Err(ConnectError::Protocol("connection closed during HTTP handshake".to_string()));
        }
        http_buf.extend_from_slice(&chunk[..n]);
        match crate::http::parse_response(&http_buf) {
            Ok((_, offset)) => break offset,
            Err(crate::http::ParseError::Incomplete) => continue,
            Err(e) => return Err(ConnectError::Protocol(format!("SSTP HTTP handshake failed: {e:?}"))),
        }
    };
    let _ = events.send(Event::Progress("SSTP HTTP handshake completed, switching to binary framing".to_string()));

    let mut reader = PacketReader::new();
    reader.push(&http_buf[body_offset..]);

    // --- SSTP + PPP engine ---
    let mut engine = Engine::new(username, password, &cert_der);
    tls.write_all(&engine.start()).await.map_err(|e| ConnectError::Protocol(format!("could not send CONNECT_REQ: {e}")))?;
    let _ = events.send(Event::Progress("sent SSTP CONNECT_REQ, waiting for CONNECT_ACK...".to_string()));

    let mut utun: Option<Arc<Utun>> = None;
    let mut utun_rx: Option<mpsc::Receiver<Vec<u8>>> = None;

    let mut tls_buf = [0u8; 16 * 1024];
    let mut idle_timer = tokio::time::interval(IDLE_TIMEOUT);
    idle_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    idle_timer.reset(); // don't fire immediately on the first tick
    let mut unanswered_echoes = 0u32;

    loop {
        tokio::select! {
            biased;

            _ = disconnect_rx.recv() => {
                let _ = tls.write_all(&engine.build_disconnect()).await;
                // Give the server a brief window to ack before closing
                // outright -- no harm either way since dropping `tls` at
                // function exit closes the connection regardless.
                let _ = tokio::time::timeout(Duration::from_secs(3), tls.read(&mut tls_buf)).await;
                return Ok(());
            }

            read_result = tls.read(&mut tls_buf) => {
                let n = read_result.map_err(|e| ConnectError::Protocol(format!("connection error: {e}")))?;
                if n == 0 {
                    return Ok(()); // server closed the connection
                }
                idle_timer.reset();
                unanswered_echoes = 0;
                reader.push(&tls_buf[..n]);

                loop {
                    let pkt = match reader.next_packet() {
                        Ok(Some(pkt)) => pkt,
                        Ok(None) => break,
                        Err(e) => return Err(ConnectError::Protocol(format!("malformed SSTP packet: {e}"))),
                    };

                    for event in engine.on_packet(pkt) {
                        match event {
                            EngineEvent::Send(bytes) => {
                                tls.write_all(&bytes).await.map_err(|e| ConnectError::Protocol(format!("write failed: {e}")))?;
                            }
                            EngineEvent::DeliverIpPacket(ip_pkt) => {
                                if let Some(u) = &utun {
                                    let _ = u.write_packet(&ip_pkt);
                                }
                            }
                            EngineEvent::Established { negotiated, mppe_keys: _ } => {
                                let (local, peer) = match (negotiated.local_ip, negotiated.peer_ip) {
                                    (Some(l), Some(p)) => (l, p),
                                    _ => return Err(ConnectError::Protocol("IPCP finished without both a local and peer address".to_string())),
                                };
                                let created = Utun::create()?;
                                created.configure_ipv4(local, peer).map_err(|e| ConnectError::Protocol(format!("could not configure utun interface: {e}")))?;
                                let interface_name = created.name().to_string();

                                let shared = Arc::new(created);
                                let reader_handle = shared.clone();
                                let (tx, rx) = mpsc::channel(64);
                                tokio::task::spawn_blocking(move || {
                                    let mut buf = vec![0u8; 16 * 1024];
                                    loop {
                                        match reader_handle.read_packet(&mut buf) {
                                            Ok(0) => continue,
                                            Ok(n) => {
                                                if tx.blocking_send(buf[..n].to_vec()).is_err() {
                                                    break; // receiver dropped -- connection is tearing down
                                                }
                                            }
                                            Err(_) => break, // fd closed (interface torn down)
                                        }
                                    }
                                });
                                utun = Some(shared);
                                utun_rx = Some(rx);

                                let _ = events.send(Event::Connected { interface: interface_name, negotiated });
                            }
                            EngineEvent::Disconnected => return Ok(()),
                            EngineEvent::Fatal(msg) => return Err(ConnectError::Protocol(msg)),
                            EngineEvent::Trace(msg) => {
                                let _ = events.send(Event::Progress(msg));
                            }
                        }
                    }
                }
            }

            _ = idle_timer.tick() => {
                if unanswered_echoes >= MAX_UNANSWERED_ECHOES {
                    return Err(ConnectError::Protocol(format!("no response from server after {MAX_UNANSWERED_ECHOES} keepalive echoes")));
                }
                unanswered_echoes += 1;
                tls.write_all(&engine.build_echo_request()).await.map_err(|e| ConnectError::Protocol(format!("keepalive write failed: {e}")))?;
            }

            Some(ip_pkt) = recv_from_utun(&mut utun_rx) => {
                let frame = packet::encode_data(&crate::ppp::encode(crate::ppp::Protocol::Ip, &ip_pkt));
                tls.write_all(&frame).await.map_err(|e| ConnectError::Protocol(format!("write failed: {e}")))?;
            }
        }
    }
}

/// A small helper so `tokio::select!` can branch on "no utun yet" (the
/// common case before `Established`) without a separate branch per phase:
/// `select!` treats a `None`-yielding future as simply never becoming
/// ready, which is exactly "no utun traffic possible yet".
async fn recv_from_utun(rx: &mut Option<mpsc::Receiver<Vec<u8>>>) -> Option<Vec<u8>> {
    match rx {
        Some(r) => r.recv().await,
        None => std::future::pending().await,
    }
}
