mod elevate;
mod ipc;
mod keychain;
mod log;
mod route;
mod worker;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use eframe::egui;
use muda::{Menu, MenuEvent, MenuItem};
use serde::{Deserialize, Serialize};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

use elevate::{run_elevated, shell_quote, show_notification};
use ipc::WorkerState;
use keychain::{keychain_delete, keychain_get, keychain_set};
use log::{append_to, tail, vpn_log_path};

const SERVICE_NAME: &str = "sstp-gui";

fn gen_id() -> String {
    format!("{:x}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos())
}

// --------------------------------------------------------------- profile --

#[derive(Serialize, Deserialize, Clone)]
struct Profile {
    id: String,
    name: String,
    server: String,
    username: String,
}

impl Profile {
    fn blank(n: usize) -> Self {
        Profile { id: gen_id(), name: format!("Сервер {n}"), server: String::new(), username: String::new() }
    }
}

// ---------------------------------------------------------------- config --

#[derive(Serialize, Deserialize, Clone, Default)]
struct Config {
    profiles: Vec<Profile>,
    selected: Option<String>,
}

impl Config {
    fn path() -> std::path::PathBuf {
        let base = dirs::config_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
        base.join(SERVICE_NAME).join("config.json")
    }

    fn load() -> Self {
        let path = Self::path();
        std::fs::read_to_string(&path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
    }

    fn save(&self) -> std::io::Result<()> {
        let path = Self::path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_string_pretty(self).unwrap())
    }

    fn selected_profile(&self) -> Option<&Profile> {
        let id = self.selected.as_ref()?;
        self.profiles.iter().find(|p| &p.id == id)
    }

    fn selected_profile_mut(&mut self) -> Option<&mut Profile> {
        let id = self.selected.clone()?;
        self.profiles.iter_mut().find(|p| p.id == id)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum VpnStatus {
    Disconnected,
    Connecting,
    Connected,
}

// -------------------------------------------------------------- tray icon --

fn make_dot_icon(rgba: [u8; 4]) -> Icon {
    const SIZE: u32 = 22;
    let mut buf = vec![0u8; (SIZE * SIZE * 4) as usize];
    let center = SIZE as f32 / 2.0;
    let radius = SIZE as f32 / 2.0 - 2.0;
    for y in 0..SIZE {
        for x in 0..SIZE {
            let dx = x as f32 + 0.5 - center;
            let dy = y as f32 + 0.5 - center;
            let idx = ((y * SIZE + x) * 4) as usize;
            if (dx * dx + dy * dy).sqrt() <= radius {
                buf[idx..idx + 4].copy_from_slice(&rgba);
            }
        }
    }
    Icon::from_rgba(buf, SIZE, SIZE).expect("valid icon buffer")
}

struct TrayItems {
    status: MenuItem,
    connect: MenuItem,
    disconnect: MenuItem,
    show: MenuItem,
    quit: MenuItem,
}

struct Tray {
    _icon: TrayIcon,
    items: TrayItems,
}

fn build_tray() -> Tray {
    let menu = Menu::new();
    let status = MenuItem::new("\u{25CF} Disconnected", false, None);
    let connect = MenuItem::new("Connect", true, None);
    let disconnect = MenuItem::new("Disconnect", false, None);
    let show = MenuItem::new("Show Window", true, None);
    let quit = MenuItem::new("Quit", true, None);
    menu.append_items(&[&status, &muda::PredefinedMenuItem::separator(), &connect, &disconnect, &muda::PredefinedMenuItem::separator(), &show, &quit])
        .unwrap();
    let icon = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_icon(make_dot_icon([140, 140, 140, 255]))
        .with_tooltip("SSTP GUI: Disconnected")
        .build()
        .expect("failed to build tray icon");
    Tray { _icon: icon, items: TrayItems { status, connect, disconnect, show, quit } }
}

// ------------------------------------------------------------------- app --

/// Which screen the central content shows: the default minimal connect
/// screen (a modern VPN client's usual home screen -- big status, one
/// button) or the profile-management/log screen tucked behind the gear icon.
#[derive(PartialEq, Eq)]
enum ViewMode {
    Connect,
    Settings,
}

struct SstpApp {
    config: Config,
    password: String,
    save_password: bool,
    vpn_status: Arc<Mutex<VpnStatus>>,
    interface: Arc<Mutex<Option<String>>>,
    busy: Arc<AtomicBool>,
    tray: Option<Tray>,
    last_poll: Instant,
    last_heal_attempt: Option<Instant>,
    styled: bool,
    view: ViewMode,
    connected_since: Option<Instant>,
}

impl SstpApp {
    fn new() -> Self {
        let mut config = Config::load();
        if config.profiles.is_empty() {
            let p = Profile::blank(1);
            config.selected = Some(p.id.clone());
            config.profiles.push(p);
        } else if config.selected.is_none() {
            config.selected = config.profiles.first().map(|p| p.id.clone());
        }
        let password = config.selected_profile().map(|p| keychain_get(&p.id).unwrap_or_default()).unwrap_or_default();

        // If the app (or the machine) restarted while a tunnel was up and
        // the worker never got to restore the route, the interface is gone
        // now but the default route may still be broken -- fix it before
        // the user notices the internet is down.
        if !route::has_default_route() {
            route::heal_route_if_broken(true);
        }
        ipc::clear_disconnect_request();

        SstpApp {
            save_password: !password.is_empty(),
            password,
            config,
            vpn_status: Arc::new(Mutex::new(VpnStatus::Disconnected)),
            interface: Arc::new(Mutex::new(None)),
            busy: Arc::new(AtomicBool::new(false)),
            tray: None,
            last_poll: Instant::now() - Duration::from_secs(10),
            last_heal_attempt: None,
            styled: false,
            view: ViewMode::Connect,
            connected_since: None,
        }
    }

    /// Switches the selected profile and reloads its password from Keychain.
    fn select_profile(&mut self, id: String) {
        self.config.selected = Some(id.clone());
        self.password = keychain_get(&id).unwrap_or_default();
        self.save_password = !self.password.is_empty();
        let _ = self.config.save();
    }

    fn add_profile(&mut self) {
        let p = Profile::blank(self.config.profiles.len() + 1);
        let id = p.id.clone();
        self.config.profiles.push(p);
        self.select_profile(id);
    }

    fn remove_profile(&mut self, id: &str) {
        keychain_delete(id);
        self.config.profiles.retain(|p| p.id != id);
        if self.config.selected.as_deref() == Some(id) {
            let next = self.config.profiles.first().map(|p| p.id.clone());
            match next {
                Some(next_id) => self.select_profile(next_id),
                None => {
                    self.config.selected = None;
                    self.password.clear();
                }
            }
        }
        let _ = self.config.save();
    }

    /// Launches the root worker process (`--vpn-worker <server> <username>`,
    /// the password handed off via a `0600` temp file, see `ipc.rs`) inside
    /// a single `do shell script ... with administrator privileges` call.
    /// That call blocks for the *entire* tunnel session -- the worker keeps
    /// running as root until it disconnects or errors out, exactly the way
    /// the old foreground `sstpc`/pppd process used to -- so this thread's
    /// job is simply to wait on it and reconcile the final status once it
    /// returns. The *live* connected/disconnected state the UI shows comes
    /// from polling `ipc::read_status()` in `logic()`, not from this call
    /// returning.
    fn spawn_connect(&self) {
        let vpn_status = self.vpn_status.clone();
        let busy = self.busy.clone();
        let Some(profile) = self.config.selected_profile().cloned() else {
            return;
        };
        let password = self.password.clone();
        busy.store(true, Ordering::SeqCst);
        *vpn_status.lock().unwrap() = VpnStatus::Connecting;

        std::thread::spawn(move || {
            if profile.server.is_empty() || profile.username.is_empty() || password.is_empty() {
                append_to(&vpn_log_path(), "connect aborted: server/username/password not set");
                show_notification("SSTP GUI", "Заполните сервер, логин и пароль");
                *vpn_status.lock().unwrap() = VpnStatus::Disconnected;
                busy.store(false, Ordering::SeqCst);
                return;
            }

            let Ok(exe) = std::env::current_exe() else {
                append_to(&vpn_log_path(), "connect aborted: could not determine our own executable path");
                *vpn_status.lock().unwrap() = VpnStatus::Disconnected;
                busy.store(false, Ordering::SeqCst);
                return;
            };
            if let Err(e) = ipc::write_pending_password(&password) {
                append_to(&vpn_log_path(), &format!("connect aborted: could not stage password handoff: {e}"));
                *vpn_status.lock().unwrap() = VpnStatus::Disconnected;
                busy.store(false, Ordering::SeqCst);
                return;
            }
            ipc::clear_status();
            ipc::clear_disconnect_request();

            // Snapshot the current gateway *before* touching anything, so a
            // worker that dies mid-negotiation can't strand the machine
            // without a way back.
            route::save_route_snapshot();

            append_to(&vpn_log_path(), &format!("connecting to {}...", profile.server));
            let cmd = format!(
                "{} --vpn-worker {} {}",
                shell_quote(&exe.to_string_lossy()),
                shell_quote(&profile.server),
                shell_quote(&profile.username)
            );

            // `run_elevated` blocks until the elevated shell command exits --
            // and unlike the old one-shot pppd/sstpc invocation, the worker
            // it launches now stays alive for the *entire connected
            // session*, not a quick one-off command. Running it on its own
            // detached thread lets this thread hand control back to the UI
            // (via `busy` below) almost immediately, instead of leaving the
            // power button unclickable and the status stuck on "Connecting"
            // for as long as the tunnel stays up.
            //
            // Deliberately does *not* touch `vpn_status`/`interface`/route
            // healing itself beyond logging -- `logic()`'s status-file poll
            // is the sole authority for those (it now also covers "the
            // worker exited before ever reaching Connected", the case this
            // used to handle here). Having *two* independent places each
            // reacting to the worker's exit by healing the route is exactly
            // what caused a single disconnect to run the whole
            // teardown-and-heal sequence twice: this thread's `run_elevated`
            // call returning (worker process exited) raced against
            // `spawn_disconnect`'s own confirmation+heal, both firing for
            // the same event.
            std::thread::spawn(move || {
                let result = run_elevated(&cmd);
                match result {
                    Ok(out) if !out.trim().is_empty() => append_to(&vpn_log_path(), out.trim()),
                    Err(e) => append_to(&vpn_log_path(), &format!("worker session ended: {e}")),
                    _ => {}
                }
            });

            busy.store(false, Ordering::SeqCst);
        });
    }

    /// Signals the running worker to disconnect (via the marker file it
    /// polls) and waits for it to confirm. Falls back to force-killing it
    /// by pid if it doesn't respond in time -- mirroring the old
    /// graceful-then-forceful pppd teardown, except now there's a single
    /// well-behaved async task on the other end instead of an external
    /// process with its own history of not honoring signals promptly.
    fn spawn_disconnect(&self) {
        let vpn_status = self.vpn_status.clone();
        let interface = self.interface.clone();
        let busy = self.busy.clone();
        busy.store(true, Ordering::SeqCst);

        std::thread::spawn(move || {
            append_to(&vpn_log_path(), "disconnecting...");
            ipc::request_disconnect();

            let deadline = Instant::now() + Duration::from_secs(10);
            let mut confirmed = false;
            while Instant::now() < deadline {
                match ipc::read_status().and_then(|s| s.state) {
                    Some(WorkerState::Disconnected) | Some(WorkerState::Error) | None => {
                        confirmed = true;
                        break;
                    }
                    _ => {}
                }
                std::thread::sleep(Duration::from_millis(300));
            }

            if !confirmed {
                append_to(&vpn_log_path(), "worker did not confirm disconnect within 10s, forcing...");
                route::log_network_diagnostics("disconnect: worker did not confirm in time");
                if let Some(pid) = ipc::read_status().and_then(|s| s.pid)
                    && ipc::pid_alive(pid)
                {
                    let _ = run_elevated(&format!("kill -9 {pid}"));
                }
            } else {
                append_to(&vpn_log_path(), "disconnected");
            }

            ipc::clear_disconnect_request();
            ipc::clear_status();
            *vpn_status.lock().unwrap() = VpnStatus::Disconnected;
            *interface.lock().unwrap() = None;
            // Restoring the pre-VPN gateway here is routine teardown (the
            // VPN owns the default route while connected), not recovery
            // from a failure -- `false` keeps the "recovered after a VPN
            // failure" notification from firing on every normal disconnect.
            route::heal_route_if_broken(false);
            busy.store(false, Ordering::SeqCst);
        });
    }

    fn handle_tray_events(&mut self, ctx: &egui::Context) {
        while let Ok(event) = MenuEvent::receiver().try_recv() {
            let Some(tray) = &self.tray else { break };
            if event.id == tray.items.connect.id() {
                self.spawn_connect();
            } else if event.id == tray.items.disconnect.id() {
                self.spawn_disconnect();
            } else if event.id == tray.items.show.id() {
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
            } else if event.id == tray.items.quit.id() {
                std::process::exit(0);
            }
        }
    }

    fn refresh_tray(&self) {
        let Some(tray) = &self.tray else { return };
        let status = *self.vpn_status.lock().unwrap();
        let busy = self.busy.load(Ordering::SeqCst);
        let (label, rgba) = match status {
            VpnStatus::Disconnected => ("\u{25CF} Disconnected", [140, 140, 140, 255]),
            VpnStatus::Connecting => ("\u{25CF} Connecting…", [230, 180, 40, 255]),
            VpnStatus::Connected => ("\u{25CF} Connected", [40, 190, 90, 255]),
        };
        tray.items.status.set_text(label);
        tray.items.connect.set_enabled(!busy && status == VpnStatus::Disconnected);
        tray.items.disconnect.set_enabled(!busy && status != VpnStatus::Disconnected);
        let _ = tray._icon.set_icon(Some(make_dot_icon(rgba)));
        let _ = tray._icon.set_tooltip(Some(label));
    }
}

/// A darker, flatter theme with a single blue accent, matching the app icon.
fn modern_visuals() -> egui::Visuals {
    let accent = egui::Color32::from_rgb(0x3C, 0x8C, 0xE0);
    let mut v = egui::Visuals::dark();
    v.panel_fill = egui::Color32::from_rgb(0x1E, 0x20, 0x24);
    v.window_fill = egui::Color32::from_rgb(0x1E, 0x20, 0x24);
    v.extreme_bg_color = egui::Color32::from_rgb(0x14, 0x15, 0x18);
    v.faint_bg_color = egui::Color32::from_rgb(0x26, 0x28, 0x2D);
    v.selection.bg_fill = accent;
    v.selection.stroke.color = egui::Color32::WHITE;
    v.hyperlink_color = accent;
    v.widgets.inactive.weak_bg_fill = egui::Color32::from_rgb(0x2A, 0x2C, 0x31);
    v.widgets.inactive.bg_fill = egui::Color32::from_rgb(0x2A, 0x2C, 0x31);
    v.widgets.hovered.weak_bg_fill = accent.linear_multiply(0.5);
    v.widgets.active.weak_bg_fill = accent;
    v.widgets.active.bg_fill = accent;
    v.window_corner_radius = egui::CornerRadius::same(10);
    v.menu_corner_radius = egui::CornerRadius::same(8);
    v.widgets.inactive.corner_radius = egui::CornerRadius::same(6);
    v.widgets.hovered.corner_radius = egui::CornerRadius::same(6);
    v.widgets.active.corner_radius = egui::CornerRadius::same(6);
    v.widgets.noninteractive.corner_radius = egui::CornerRadius::same(6);
    v
}

/// Small drawn (not glyph-based) close/remove icon, so it renders identically
/// regardless of font emoji coverage.
fn close_icon_button(ui: &mut egui::Ui) -> egui::Response {
    let size = egui::vec2(18.0, 18.0);
    let (rect, response) = ui.allocate_exact_size(size, egui::Sense::click());
    if ui.is_rect_visible(rect) {
        let color = if response.hovered() { egui::Color32::from_rgb(220, 90, 90) } else { ui.visuals().weak_text_color() };
        let painter = ui.painter();
        let pad = 5.0;
        let stroke = egui::Stroke::new(1.4, color);
        painter.line_segment([rect.left_top() + egui::vec2(pad, pad), rect.right_bottom() - egui::vec2(pad, pad)], stroke);
        painter.line_segment([rect.right_top() + egui::vec2(-pad, pad), rect.left_bottom() + egui::vec2(pad, -pad)], stroke);
    }
    response
}

/// Small drawn gear/settings icon, opening the profile-management screen.
fn gear_icon_button(ui: &mut egui::Ui) -> egui::Response {
    let size = egui::vec2(22.0, 22.0);
    let (rect, response) = ui.allocate_exact_size(size, egui::Sense::click());
    if ui.is_rect_visible(rect) {
        let color = if response.hovered() { ui.visuals().strong_text_color() } else { ui.visuals().weak_text_color() };
        let painter = ui.painter();
        let center = rect.center();
        let outer_r = rect.width() * 0.24;
        let stroke = egui::Stroke::new(1.6, color);
        painter.circle_stroke(center, outer_r, stroke);
        painter.circle_filled(center, outer_r * 0.35, color);
        let teeth = 6;
        for i in 0..teeth {
            let angle = (i as f32 / teeth as f32) * std::f32::consts::TAU;
            let dir = egui::vec2(angle.cos(), angle.sin());
            let inner = center + dir * (outer_r + 1.5);
            let tip = center + dir * (outer_r + 4.5);
            painter.line_segment([inner, tip], egui::Stroke::new(2.0, color));
        }
    }
    response
}

/// Small drawn back-arrow (chevron) icon, returning from the settings
/// screen to the main connect screen.
fn back_arrow_button(ui: &mut egui::Ui) -> egui::Response {
    let size = egui::vec2(22.0, 22.0);
    let (rect, response) = ui.allocate_exact_size(size, egui::Sense::click());
    if ui.is_rect_visible(rect) {
        let color = if response.hovered() { ui.visuals().strong_text_color() } else { ui.visuals().weak_text_color() };
        let stroke = egui::Stroke::new(1.8, color);
        let c = rect.center();
        let r = rect.width() * 0.22;
        ui.painter().line_segment([c + egui::vec2(r * 0.6, -r), c + egui::vec2(-r * 0.9, 0.0)], stroke);
        ui.painter().line_segment([c + egui::vec2(-r * 0.9, 0.0), c + egui::vec2(r * 0.6, r)], stroke);
    }
    response
}

/// The big circular connect/disconnect button that's the focal point of a
/// modern VPN client's home screen -- color and the drawn power-symbol icon
/// both track connection state, matching the tray icon's own color scheme
/// (`refresh_tray`) so the two never disagree.
fn power_button(ui: &mut egui::Ui, status: VpnStatus, enabled: bool) -> egui::Response {
    let diameter = 132.0;
    let sense = if enabled { egui::Sense::click() } else { egui::Sense::hover() };
    let (rect, response) = ui.allocate_exact_size(egui::vec2(diameter, diameter), sense);

    if ui.is_rect_visible(rect) {
        let (base, icon_color) = match status {
            VpnStatus::Disconnected => (egui::Color32::from_rgb(0x2A, 0x2C, 0x31), egui::Color32::from_rgb(0x9A, 0x9E, 0xA6)),
            VpnStatus::Connecting => (egui::Color32::from_rgb(0x4A, 0x3B, 0x10), egui::Color32::from_rgb(0xE6, 0xB4, 0x28)),
            VpnStatus::Connected => (egui::Color32::from_rgb(0x11, 0x40, 0x25), egui::Color32::from_rgb(0x34, 0xD1, 0x70)),
        };
        let fill = if response.hovered() && enabled { base.linear_multiply(1.4) } else { base };

        let painter = ui.painter();
        let center = rect.center();
        let radius = diameter / 2.0;
        painter.circle_filled(center, radius, fill);
        painter.circle_stroke(center, radius, egui::Stroke::new(2.0, icon_color.linear_multiply(0.6)));

        // Classic "power" glyph: an open ring with a gap at the top and a
        // vertical tick through the gap, drawn rather than relying on font
        // glyph coverage (same reasoning as `close_icon_button`).
        let icon_r = radius * 0.34;
        let icon_stroke = egui::Stroke::new(3.2, icon_color);
        painter.line_segment([center + egui::vec2(0.0, -icon_r * 1.55), center + egui::vec2(0.0, -icon_r * 0.25)], icon_stroke);
        let gap = 0.62_f32;
        let start = -std::f32::consts::FRAC_PI_2 + gap;
        let end = std::f32::consts::FRAC_PI_2 * 3.0 - gap;
        let segments = 28;
        let points: Vec<egui::Pos2> = (0..=segments)
            .map(|i| {
                let t = start + (end - start) * (i as f32 / segments as f32);
                center + egui::vec2(t.cos(), t.sin()) * icon_r
            })
            .collect();
        painter.add(egui::Shape::line(points, icon_stroke));
    }

    response
}

fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    if h > 0 { format!("{h:02}:{m:02}:{s:02}") } else { format!("{m:02}:{s:02}") }
}

impl eframe::App for SstpApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if !self.styled {
            ctx.set_visuals(modern_visuals());
            ctx.all_styles_mut(|style| {
                style.spacing.item_spacing = egui::vec2(8.0, 10.0);
                style.spacing.button_padding = egui::vec2(12.0, 6.0);
            });
            self.styled = true;
        }
        if self.tray.is_none() {
            self.tray = Some(build_tray());
        }
        self.handle_tray_events(ctx);
        self.refresh_tray();

        // Closing the window hides it instead of quitting; the app keeps
        // running in the status bar (the VPN tunnel, if any, is a separate
        // root worker process and is unaffected either way).
        if ctx.input(|i| i.viewport().close_requested()) {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        }

        if self.last_poll.elapsed() > Duration::from_secs(3) {
            self.last_poll = Instant::now();
            if !self.busy.load(Ordering::SeqCst) {
                let worker_status = ipc::read_status();
                let worker_up = matches!(worker_status.as_ref().and_then(|s| s.state), Some(WorkerState::Connected))
                    && worker_status.as_ref().and_then(|s| s.pid).is_some_and(ipc::pid_alive);
                // True once the worker has definitively stopped trying: it
                // wrote a terminal status, or its pid is simply gone.
                // Without this, a connect attempt that fails *before* ever
                // reaching Connected (bad TLS, bad credentials, ...) left
                // the UI stuck showing "Connecting" forever -- nothing else
                // transitions out of that state on failure. (This used to
                // be handled by a fallback in `spawn_connect`'s own thread,
                // which raced against `spawn_disconnect`'s cleanup and made
                // a single disconnect run route-healing twice; the poll
                // loop is now the sole authority for every state exit.)
                let worker_gave_up = match &worker_status {
                    Some(s) => matches!(s.state, Some(WorkerState::Error) | Some(WorkerState::Disconnected)) || !s.pid.is_some_and(ipc::pid_alive),
                    None => true,
                };

                let mut needs_heal = false;
                {
                    let mut s = self.vpn_status.lock().unwrap();
                    match (*s, worker_up) {
                        (VpnStatus::Connected, false) => {
                            // The tunnel dropped without going through
                            // spawn_disconnect (crash, killed externally,
                            // link loss) -- check whether it left the
                            // machine without a default route.
                            *s = VpnStatus::Disconnected;
                            *self.interface.lock().unwrap() = None;
                            needs_heal = true;
                        }
                        (VpnStatus::Connecting, true) | (VpnStatus::Disconnected, true) => {
                            *s = VpnStatus::Connected;
                            *self.interface.lock().unwrap() = worker_status.and_then(|s| s.interface);
                        }
                        (VpnStatus::Connecting, false) if worker_gave_up => {
                            // Failed before ever getting connected -- no
                            // route was ever touched, so no heal needed.
                            *s = VpnStatus::Disconnected;
                        }
                        _ => {}
                    }
                }
                if needs_heal {
                    // The tunnel dropped without going through
                    // spawn_disconnect -- a genuine unexpected failure, so
                    // the recovery notification is warranted.
                    route::heal_route_if_broken(true);
                    self.last_heal_attempt = Some(Instant::now());
                } else if *self.vpn_status.lock().unwrap() == VpnStatus::Disconnected
                    && !route::has_default_route()
                    && self.last_heal_attempt.is_none_or(|t| t.elapsed() > Duration::from_secs(30))
                {
                    // The route was already broken before this poll cycle
                    // (e.g. a previous heal attempt failed) -- keep
                    // retrying periodically instead of only once.
                    // `has_default_route()` itself is a cheap local check
                    // (no admin prompt); only the actual fix path escalates.
                    route::heal_route_if_broken(true);
                    self.last_heal_attempt = Some(Instant::now());
                }
            }
        }

        // Track when the connected-duration timer should start/stop, every
        // frame (cheap) rather than only on the 3s poll -- `vpn_status` can
        // also be flipped to Disconnected directly by the spawn_connect/
        // spawn_disconnect background threads, not just by this poll loop.
        match *self.vpn_status.lock().unwrap() {
            VpnStatus::Connected => {
                if self.connected_since.is_none() {
                    self.connected_since = Some(Instant::now());
                }
            }
            _ => self.connected_since = None,
        }

        ctx.request_repaint_after(Duration::from_millis(300));
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let status = *self.vpn_status.lock().unwrap();
        let busy = self.busy.load(Ordering::SeqCst);
        let mut pending_select: Option<String> = None;
        let mut pending_remove: Option<String> = None;
        let mut pending_add = false;

        // Nothing to connect to yet -- go straight to the screen that lets
        // the user add a server, rather than showing a connect button that
        // can't do anything.
        if self.config.selected_profile().is_none() {
            self.view = ViewMode::Settings;
        }

        egui::CentralPanel::default().show(ui, |ui| match self.view {
            ViewMode::Connect => self.connect_screen(ui, status, busy),
            ViewMode::Settings => {
                self.settings_screen(ui, &mut pending_select, &mut pending_remove, &mut pending_add);
            }
        });

        if let Some(id) = pending_select {
            self.select_profile(id);
        }
        if let Some(id) = pending_remove {
            self.remove_profile(&id);
        }
        if pending_add {
            self.add_profile();
            self.view = ViewMode::Settings;
        }
    }
}

impl SstpApp {
    /// The default home screen: a large status-colored power button and,
    /// once connected, how long for and which interface -- the same shape
    /// every mainstream VPN client (Mullvad, NordVPN, Tailscale, ...)
    /// settled on, instead of a permanently-open credentials form.
    fn connect_screen(&mut self, ui: &mut egui::Ui, status: VpnStatus, busy: bool) {
        let current_name = self.config.selected_profile().map(|p| p.name.clone()).unwrap_or_default();
        let mut pending_switch: Option<String> = None;

        ui.horizontal(|ui| {
            ui.add_space(4.0);
            egui::ComboBox::from_id_salt("profile_switch").width(160.0).selected_text(&current_name).show_ui(ui, |ui| {
                for profile in &self.config.profiles {
                    let selected = self.config.selected.as_deref() == Some(profile.id.as_str());
                    if ui.selectable_label(selected, &profile.name).clicked() && !selected {
                        pending_switch = Some(profile.id.clone());
                    }
                }
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if gear_icon_button(ui).on_hover_text("Настройки").clicked() {
                    self.view = ViewMode::Settings;
                }
                ui.add_space(4.0);
            });
        });
        if let Some(id) = pending_switch {
            self.select_profile(id);
        }

        let available = ui.available_height();
        ui.vertical_centered(|ui| {
            ui.add_space((available * 0.22).max(12.0));

            let response = power_button(ui, status, !busy);
            if response.clicked() {
                match status {
                    VpnStatus::Disconnected => self.spawn_connect(),
                    VpnStatus::Connecting | VpnStatus::Connected => self.spawn_disconnect(),
                }
            }
            let hover_text = match status {
                VpnStatus::Disconnected => "Подключиться",
                VpnStatus::Connecting => "Отменить",
                VpnStatus::Connected => "Отключиться",
            };
            response.on_hover_text(hover_text);

            ui.add_space(20.0);
            let (status_text, status_color) = match status {
                VpnStatus::Disconnected => ("Не подключено", egui::Color32::from_rgb(0x9A, 0x9E, 0xA6)),
                VpnStatus::Connecting => ("Подключение…", egui::Color32::from_rgb(0xE6, 0xB4, 0x28)),
                VpnStatus::Connected => ("Подключено", egui::Color32::from_rgb(0x34, 0xD1, 0x70)),
            };
            ui.label(egui::RichText::new(status_text).size(22.0).strong().color(status_color));

            ui.add_space(6.0);
            let subtitle = match status {
                VpnStatus::Connected => {
                    let dur = self.connected_since.map(|t| t.elapsed()).unwrap_or_default();
                    let iface = self.interface.lock().unwrap().clone();
                    match iface {
                        Some(i) => format!("{} · {i}", format_duration(dur)),
                        None => format_duration(dur),
                    }
                }
                _ => current_name.clone(),
            };
            ui.label(egui::RichText::new(subtitle).weak());
        });
    }

    /// Profile management + connection log, tucked behind the gear icon so
    /// the default screen stays uncluttered.
    fn settings_screen(&mut self, ui: &mut egui::Ui, pending_select: &mut Option<String>, pending_remove: &mut Option<String>, pending_add: &mut bool) {
        let can_go_back = self.config.selected_profile().is_some();
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.horizontal(|ui| {
                if can_go_back && back_arrow_button(ui).on_hover_text("Назад").clicked() {
                    self.view = ViewMode::Connect;
                }
                ui.heading("Настройки");
            });
            ui.add_space(12.0);

            ui.label(egui::RichText::new("Серверы").strong());
            ui.add_space(4.0);
            for profile in &self.config.profiles {
                let selected = self.config.selected.as_deref() == Some(profile.id.as_str());
                ui.horizontal(|ui| {
                    if ui.selectable_label(selected, &profile.name).clicked() {
                        *pending_select = Some(profile.id.clone());
                    }
                    if close_icon_button(ui).on_hover_text("Удалить сервер").clicked() {
                        *pending_remove = Some(profile.id.clone());
                    }
                });
            }
            ui.add_space(4.0);
            if ui.add(egui::Button::new("+ Добавить сервер").min_size(egui::vec2(ui.available_width(), 0.0))).clicked() {
                *pending_add = true;
            }

            if self.config.selected_profile().is_none() {
                return;
            }

            ui.add_space(16.0);
            ui.separator();
            ui.add_space(10.0);

            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.set_width(ui.available_width());
                let profile = self.config.selected_profile_mut().unwrap();
                egui::Grid::new("profile_fields").num_columns(2).spacing([10.0, 8.0]).show(ui, |ui| {
                    ui.label("Имя профиля:");
                    ui.text_edit_singleline(&mut profile.name);
                    ui.end_row();

                    ui.label("Сервер:");
                    ui.text_edit_singleline(&mut profile.server);
                    ui.end_row();

                    ui.label("Логин:");
                    ui.text_edit_singleline(&mut profile.username);
                    ui.end_row();

                    ui.label("Пароль:");
                    ui.add(egui::TextEdit::singleline(&mut self.password).password(true));
                    ui.end_row();
                });
                ui.checkbox(&mut self.save_password, "Сохранить пароль в Keychain");

                if ui.button("Сохранить настройки").clicked() {
                    let _ = self.config.save();
                    let id = self.config.selected.clone().unwrap();
                    if self.save_password && !self.password.is_empty() {
                        keychain_set(&id, &self.password);
                    } else if !self.save_password {
                        keychain_delete(&id);
                    }
                }
            });

            ui.add_space(16.0);
            ui.collapsing("Лог подключения", |ui| {
                egui::ScrollArea::vertical().max_height(220.0).stick_to_bottom(true).show(ui, |ui| {
                    let log = tail(&vpn_log_path(), 200);
                    ui.add(egui::TextEdit::multiline(&mut log.as_str()).desired_width(f32::INFINITY).font(egui::TextStyle::Monospace));
                });
            });
        });
    }
}

/// Works around a macOS AppKit bug (seen on macOS 26.5) where the automatic
/// Touch Bar customization observer aborts the process with SIGABRT during
/// a display-cycle flush. We don't use Touch Bar customization, so disabling
/// it entirely sidesteps the buggy code path.
#[cfg(target_os = "macos")]
fn disable_touch_bar_customization() {
    use objc2::MainThreadMarker;
    use objc2_app_kit::NSApplication;

    if let Some(mtm) = MainThreadMarker::new() {
        let app = NSApplication::sharedApplication(mtm);
        app.setAutomaticCustomizeTouchBarMenuItemEnabled(false);
    }
}

fn main() -> eframe::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--vpn-worker") {
        let (Some(server), Some(username)) = (args.get(2).cloned(), args.get(3).cloned()) else {
            eprintln!("usage: {} --vpn-worker <server> <username>  (password via the pending-password handoff file)", args[0]);
            std::process::exit(2);
        };
        worker::run(server, username); // never returns
    }

    #[cfg(target_os = "macos")]
    disable_touch_bar_customization();

    let options = eframe::NativeOptions { viewport: egui::ViewportBuilder::default().with_inner_size([760.0, 640.0]), ..Default::default() };
    eframe::run_native("SSTP GUI", options, Box::new(|_cc| Ok(Box::new(SstpApp::new()))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_round_trips_through_json() {
        let mut config = Config::default();
        let p = Profile::blank(1);
        config.selected = Some(p.id.clone());
        config.profiles.push(p);

        let json = serde_json::to_string_pretty(&config).unwrap();
        let restored: Config = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.selected, config.selected);
        assert_eq!(restored.profiles.len(), 1);
        assert_eq!(restored.profiles[0].id, config.profiles[0].id);
    }

    /// A profile saved by the *old* pppd-based version of this app had a
    /// `pppd_options` field we no longer have; serde must silently ignore
    /// unknown fields on read rather than fail to load an existing user's
    /// saved config.
    #[test]
    fn old_config_with_removed_pppd_options_field_still_loads() {
        let old_json = r#"{
            "profiles": [
                {"id": "abc123", "name": "work", "server": "vpn.example.com:8443", "username": "user", "pppd_options": "noauth defaultroute"}
            ],
            "selected": "abc123"
        }"#;
        let config: Config = serde_json::from_str(old_json).unwrap();
        assert_eq!(config.profiles.len(), 1);
        assert_eq!(config.profiles[0].server, "vpn.example.com:8443");
    }
}
