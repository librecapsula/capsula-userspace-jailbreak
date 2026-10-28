//! Non-Windows stub: USB needs no driver binding on macOS/Linux.

use std::path::{Path, PathBuf};

pub struct Session;

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

impl Session {
    pub fn new() -> Self {
        Session
    }
    pub fn log_path(&self) -> &Path {
        Path::new("")
    }
    pub fn elevated(&self) -> bool {
        true
    }
    pub fn ensure_supervision(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
}

pub fn pause_if_own_console() {}

pub fn fix_cwd_if_system32() -> Option<PathBuf> {
    None
}
