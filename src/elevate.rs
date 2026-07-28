//! Shell/AppleScript quoting and the `do shell script ... with
//! administrator privileges` helper used any time the (unprivileged) GUI
//! process needs a one-shot elevated command run — launching the root
//! worker process, and one-off route-repair commands in `route.rs`.

use std::process::Command;

/// Escapes a string for embedding inside a single-quoted POSIX shell
/// argument.
pub fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Escapes a string for embedding inside an AppleScript double-quoted
/// literal.
pub fn applescript_quote(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

pub fn show_notification(title: &str, message: &str) {
    let script =
        format!("display notification \"{}\" with title \"{}\"", applescript_quote(message), applescript_quote(title));
    let _ = Command::new("osascript").arg("-e").arg(&script).output();
}

/// Runs a shell command as root via the native macOS authorization dialog.
pub fn run_elevated(shell_cmd: &str) -> Result<String, String> {
    let script = format!("do shell script \"{}\" with administrator privileges", applescript_quote(shell_cmd));
    let out = Command::new("osascript").arg("-e").arg(&script).output().map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trips `shell_quote`'s output through a real `/bin/sh -c` so
    /// this is checking actual POSIX shell semantics, not just our
    /// assumption of them -- these strings end up inside a single
    /// `do shell script "..." with administrator privileges` call, so a
    /// quoting mistake here is a root command-injection bug, not a
    /// cosmetic one.
    fn shell_roundtrip(s: &str) -> String {
        let quoted = shell_quote(s);
        let out = Command::new("/bin/sh").arg("-c").arg(format!("printf '%s' {quoted}")).output().expect("sh should run");
        assert!(out.status.success(), "shell rejected quoted string: {quoted}");
        String::from_utf8(out.stdout).unwrap()
    }

    #[test]
    fn shell_quote_roundtrips_plain_and_hostile_input() {
        for s in [
            "",
            "plain",
            "with space",
            "it's a trap",
            "''; rm -rf / #",
            "$(rm -rf /)",
            "`rm -rf /`",
            "back\\slash",
            "new\nline",
            "quote\"double",
            "мультибайт пароль",
        ] {
            assert_eq!(shell_roundtrip(s), s, "shell_quote round-trip failed for {s:?}");
        }
    }

    /// Same idea as `shell_roundtrip`, but through `osascript` for
    /// `applescript_quote`, which feeds the same kind of privileged
    /// `do shell script` call from the AppleScript side.
    fn applescript_roundtrip(s: &str) -> String {
        let quoted = applescript_quote(s);
        let script = format!("return \"{quoted}\"");
        let out = Command::new("osascript").arg("-e").arg(&script).output().expect("osascript should run");
        assert!(out.status.success(), "osascript rejected quoted string: {quoted}");
        String::from_utf8(out.stdout).unwrap().trim_end_matches('\n').to_string()
    }

    #[test]
    fn applescript_quote_roundtrips_plain_and_hostile_input() {
        for s in ["", "plain", "with space", "back\\slash", "quote\"double", "both\\ and \" together", "мультибайт пароль"] {
            assert_eq!(applescript_roundtrip(s), s, "applescript_quote round-trip failed for {s:?}");
        }
    }
}
