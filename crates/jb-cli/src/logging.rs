//! The unified CLI logger: all tool output goes through the `log`
//! crate — both scenario steps and messages from the domain crates
//! (rockusb, amlogic, jb-core). Line format is
//! `HH:MM:SS.mmm LEVEL  message` (UTC, milliseconds; the level is
//! mandatory — INFO/WARN/ERROR/DEBUG). Output to stdout: the whole log
//! in one stream, `> file` captures everything. The level comes from
//! RUST_LOG (info by default).

use crate::progress;
use crate::util::ts_ms;
use log::{Log, Metadata, Record};
use std::io::Write;

/// Initialize the global logger; called once at the start of main,
/// before any output.
pub fn init() {
    let inner = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format(|buf, record| {
            writeln!(
                buf,
                "{} {:<5} {}",
                ts_ms(),
                record.level(),
                record.args()
            )
        })
        .target(env_logger::Target::Stdout)
        .build();
    log::set_max_level(inner.filter());
    // A duplicate logger is impossible (set_boxed_logger is the very
    // first thing main does), so a failure here means a programming
    // error — silently continuing is wrong, but crashing the CLI over
    // it is not worth it either.
    let _ = log::set_boxed_logger(Box::new(BarAware { inner }));
}

/// A logger that yields the line to the active progress bar: warnings
/// from the domain crates arrive mid-transfer too, and without suspend
/// the bar rendering would overwrite them on the terminal.
struct BarAware {
    inner: env_logger::Logger,
}

impl Log for BarAware {
    fn enabled(&self, metadata: &Metadata) -> bool {
        self.inner.enabled(metadata)
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        match progress::active_bar() {
            Some(bar) => bar.suspend(|| self.inner.log(record)),
            None => self.inner.log(record),
        }
    }

    fn flush(&self) {
        self.inner.flush();
    }
}
