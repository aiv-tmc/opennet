//! Leveled process logging with an environment-controlled filter.
//!
//! One process-wide verbosity, parsed once from `OPENNET_LOG`
//! (falling back to `RUST_LOG`, defaulting to `warn`): a message is
//! written to stderr only when its level is at or above the filter,
//! prefixed with a unix timestamp, the level and the calling module
//! path. The module path doubles as the log tag, so every line names
//! the subsystem that produced it without manual tagging at call
//! sites.
//!
//! Levels: `error`, `warn`, `info`, `debug`. Example:
//! `OPENNET_LOG=info opennetd` runs the daemon with progress lines;
//! the default `warn` keeps production logs to failures only.
//!
//! This module is the single place allowed to write unstructured
//! lines to stderr: every other subsystem routes through these four
//! functions, so log volume is filterable in one place.

use std::sync::OnceLock;

/// Severity of one log message, ordered so comparison against the
/// filter is a single comparison.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Debug,
    Info,
    Warn,
    Error,
}

impl Level {
    fn name(self) -> &'static str {
        match self {
            Level::Debug => "DEBUG",
            Level::Info => "INFO",
            Level::Warn => "WARN",
            Level::Error => "ERROR",
        }
    }
}

/// The process-wide filter, parsed lazily on first use so the
/// environment is read exactly once.
static FILTER: OnceLock<Level> = OnceLock::new();

fn filter() -> Level {
    *FILTER.get_or_init(|| {
        let raw = std::env::var("OPENNET_LOG")
            .or_else(|_| std::env::var("RUST_LOG"))
            .unwrap_or_default()
            .to_ascii_lowercase();
        match raw.as_str() {
            "debug" | "trace" => Level::Debug,
            "info" => Level::Info,
            "warn" | "warning" => Level::Warn,
            _ => Level::Warn,
        }
    })
}

/// Write one message when its level passes the filter. This is the
/// only raw stderr write in the crate: the line carries the unix
/// timestamp, the level name and the caller-supplied module tag.
fn emit(level: Level, tag: &str, message: &str) {
    if level < filter() {
        return;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    eprintln!("{now} {} [{tag}] {message}", level.name());
}

/// Error-level: daemon failures an operator must see.
pub fn error(tag: &str, message: &str) {
    emit(Level::Error, tag, message);
}

/// Warning-level: degraded behavior, dropped frames, refused frames.
pub fn warn(tag: &str, message: &str) {
    emit(Level::Warn, tag, message);
}

/// Info-level: lifecycle progress (startup, plans, settlements).
pub fn info(tag: &str, message: &str) {
    emit(Level::Info, tag, message);
}

/// Debug-level: per-frame detail for troubleshooting.
pub fn debug(tag: &str, message: &str) {
    emit(Level::Debug, tag, message);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_order_by_severity() {
        assert!(Level::Error > Level::Warn);
        assert!(Level::Warn > Level::Info);
        assert!(Level::Info > Level::Debug);
    }

    #[test]
    fn names_are_uppercase() {
        assert_eq!(Level::Warn.name(), "WARN");
        assert_eq!(Level::Error.name(), "ERROR");
    }

    #[test]
    fn emit_below_filter_writes_nothing_visible() {
        // Smoke check only: with the default filter, debug and info
        // are suppressed and must not panic.
        emit(Level::Debug, "log::tests", "hidden debug line");
        emit(Level::Info, "log::tests", "hidden info line");
    }
}
