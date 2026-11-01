//! Small CLI-wide helpers (the unified logger's timestamp).

/// HH:MM:SS.mmm (UTC) timestamp — the prefix of every line of the
/// unified logger (logging.rs).
pub(crate) fn ts_ms() -> String {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => {
            let secs = d.as_secs() % 86400;
            format!(
                "{:02}:{:02}:{:02}.{:03}",
                secs / 3600,
                (secs / 60) % 60,
                secs % 60,
                d.subsec_millis()
            )
        }
        Err(_) => String::from("00:00:00.000"),
    }
}
