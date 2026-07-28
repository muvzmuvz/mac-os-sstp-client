//! Minimal localization: two languages, picked once at startup from the
//! system locale. Not a general-purpose i18n framework (gettext, fluent,
//! ...) -- with two languages and a few dozen short strings, a plain struct
//! of `&'static str` fields is simpler and keeps every reference to a
//! translated string a compile error away from a typo'd key, at the cost of
//! listing each string twice.

use std::process::Command;
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    Ru,
    En,
}

impl Lang {
    /// Reads the current user's macOS UI language preference via
    /// `defaults read -g AppleLocale` (e.g. `ru_RU`, `en_US`) -- the same
    /// source macOS itself uses to decide which `.lproj` bundle a
    /// well-behaved localized app would load. Falls back to English if the
    /// command fails or reports anything other than Russian, since that's
    /// a safe default for everyone else.
    fn detect() -> Lang {
        let out = Command::new("defaults").args(["read", "-g", "AppleLocale"]).output();
        match out {
            Ok(o) if o.status.success() => {
                let locale = String::from_utf8_lossy(&o.stdout);
                if locale.trim().starts_with("ru") {
                    Lang::Ru
                } else {
                    Lang::En
                }
            }
            _ => Lang::En,
        }
    }

    fn strings(self) -> &'static Strings {
        match self {
            Lang::Ru => &RU,
            Lang::En => &EN,
        }
    }
}

static CURRENT: OnceLock<Lang> = OnceLock::new();

/// The current language's strings. Detects (via `defaults read -g
/// AppleLocale`) and pins the language on first call, for the rest of the
/// process's lifetime -- self-initializing rather than requiring an
/// explicit `init()` call from every entry point (including the detached
/// route-healing/disconnect threads, which have no access to `SstpApp`
/// itself, and unit tests that exercise localized code paths) to get right.
pub fn t() -> &'static Strings {
    CURRENT.get_or_init(Lang::detect).strings()
}

pub struct Strings {
    pub connect: &'static str,
    pub cancel: &'static str,
    pub disconnect: &'static str,
    pub not_connected: &'static str,
    pub connecting: &'static str,
    pub connected: &'static str,
    pub settings: &'static str,
    pub settings_hover: &'static str,
    pub back: &'static str,
    pub servers: &'static str,
    pub add_server: &'static str,
    pub remove_server_hover: &'static str,
    pub profile_name_label: &'static str,
    pub server_label: &'static str,
    pub username_label: &'static str,
    pub password_label: &'static str,
    pub save_password_in_keychain: &'static str,
    pub save_settings: &'static str,
    pub connection_log: &'static str,
    pub fill_server_username_password: &'static str,
    pub default_server_name_prefix: &'static str,
    pub tray_status_disconnected: &'static str,
    pub tray_status_connecting: &'static str,
    pub tray_status_connected: &'static str,
    pub tray_connect: &'static str,
    pub tray_disconnect: &'static str,
    pub tray_show_window: &'static str,
    pub tray_quit: &'static str,
    pub notif_app_name: &'static str,
    pub notif_restored_after_failure: &'static str,
    pub notif_restore_failed: &'static str,
}

static RU: Strings = Strings {
    connect: "Подключиться",
    cancel: "Отменить",
    disconnect: "Отключиться",
    not_connected: "Не подключено",
    connecting: "Подключение…",
    connected: "Подключено",
    settings: "Настройки",
    settings_hover: "Настройки",
    back: "Назад",
    servers: "Серверы",
    add_server: "+ Добавить сервер",
    remove_server_hover: "Удалить сервер",
    profile_name_label: "Имя профиля:",
    server_label: "Сервер:",
    username_label: "Логин:",
    password_label: "Пароль:",
    save_password_in_keychain: "Сохранить пароль в Keychain",
    save_settings: "Сохранить настройки",
    connection_log: "Лог подключения",
    fill_server_username_password: "Заполните сервер, логин и пароль",
    default_server_name_prefix: "Сервер",
    tray_status_disconnected: "\u{25CF} Отключено",
    tray_status_connecting: "\u{25CF} Подключение…",
    tray_status_connected: "\u{25CF} Подключено",
    tray_connect: "Подключиться",
    tray_disconnect: "Отключиться",
    tray_show_window: "Показать окно",
    tray_quit: "Выход",
    notif_app_name: "SSTP GUI",
    notif_restored_after_failure: "Восстановлен доступ в интернет после сбоя VPN",
    notif_restore_failed: "Не удалось восстановить интернет автоматически, см. лог",
};

static EN: Strings = Strings {
    connect: "Connect",
    cancel: "Cancel",
    disconnect: "Disconnect",
    not_connected: "Not connected",
    connecting: "Connecting…",
    connected: "Connected",
    settings: "Settings",
    settings_hover: "Settings",
    back: "Back",
    servers: "Servers",
    add_server: "+ Add server",
    remove_server_hover: "Remove server",
    profile_name_label: "Profile name:",
    server_label: "Server:",
    username_label: "Username:",
    password_label: "Password:",
    save_password_in_keychain: "Save password in Keychain",
    save_settings: "Save settings",
    connection_log: "Connection log",
    fill_server_username_password: "Fill in the server, username and password",
    default_server_name_prefix: "Server",
    tray_status_disconnected: "\u{25CF} Disconnected",
    tray_status_connecting: "\u{25CF} Connecting…",
    tray_status_connected: "\u{25CF} Connected",
    tray_connect: "Connect",
    tray_disconnect: "Disconnect",
    tray_show_window: "Show Window",
    tray_quit: "Quit",
    notif_app_name: "SSTP GUI",
    notif_restored_after_failure: "Internet access restored after a VPN failure",
    notif_restore_failed: "Could not restore internet access automatically, see the log",
};

#[cfg(test)]
mod tests {
    use super::*;

    /// Both static tables are built by field name, so a forgotten field
    /// would be a compile error, not a silent gap -- this instead catches
    /// the more likely mistake of accidentally leaving a field empty or
    /// copy-pasting one language's text into the other's slot.
    fn as_list(s: &Strings) -> Vec<&'static str> {
        vec![
            s.connect,
            s.cancel,
            s.disconnect,
            s.not_connected,
            s.connecting,
            s.connected,
            s.settings,
            s.settings_hover,
            s.back,
            s.servers,
            s.add_server,
            s.remove_server_hover,
            s.profile_name_label,
            s.server_label,
            s.username_label,
            s.password_label,
            s.save_password_in_keychain,
            s.save_settings,
            s.connection_log,
            s.fill_server_username_password,
            s.default_server_name_prefix,
            s.tray_status_disconnected,
            s.tray_status_connecting,
            s.tray_status_connected,
            s.tray_connect,
            s.tray_disconnect,
            s.tray_show_window,
            s.tray_quit,
            s.notif_app_name,
            s.notif_restored_after_failure,
            s.notif_restore_failed,
        ]
    }

    #[test]
    fn no_string_is_accidentally_empty() {
        for s in as_list(&RU).into_iter().chain(as_list(&EN)) {
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn ru_and_en_are_not_the_same_table() {
        // A handful of fields (the app name) are deliberately identical in
        // both languages; if *every* field matched, RU was almost
        // certainly copy-pasted over EN (or vice versa) by mistake.
        let same = as_list(&RU).into_iter().zip(as_list(&EN)).filter(|(ru, en)| ru == en).count();
        assert!(same < as_list(&RU).len(), "RU and EN tables are identical");
    }

    #[test]
    fn detect_never_panics() {
        // Exercises the actual `defaults` subprocess call -- this test
        // machine may or may not report a Russian locale, so just check it
        // resolves to *something* without panicking either way.
        let _ = Lang::detect();
    }

    #[test]
    fn t_self_initializes_and_is_internally_consistent() {
        let strings = t();
        assert!(std::ptr::eq(strings, &RU) || std::ptr::eq(strings, &EN));
    }
}
