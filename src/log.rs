//! The shared log file both the GUI and the root worker append to, and
//! that the GUI's "connection log" panel tails. Previously filled by
//! whatever pppd/sstpc happened to write to stdout/their own `logfile`
//! option; now written directly by our own code on both sides, so every
//! line in it is something we chose to log, not scraped from an external
//! process's output.

use std::io::Write as _;
use std::path::{Path, PathBuf};

pub fn vpn_log_path() -> PathBuf {
    let dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")).join("Library/Logs");
    let _ = std::fs::create_dir_all(&dir);
    dir.join("sstp-gui.log")
}

pub fn append_to(path: &Path, line: &str) {
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(f, "{line}");
    }
}

pub fn tail(path: &Path, max_lines: usize) -> String {
    let Ok(content) = std::fs::read_to_string(path) else {
        return String::new();
    };
    let lines: Vec<&str> = content.lines().collect();
    let start = lines.len().saturating_sub(max_lines);
    lines[start..].join("\n")
}
