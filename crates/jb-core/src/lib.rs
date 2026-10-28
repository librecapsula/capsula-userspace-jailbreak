//! capsula-jailbreak domain: everything independent of the transport
//! and of the UI.
//!
//! Method: userspace overwrite. userdata is not signed and is freely
//! rewritable; no other partition is touched. The configuration lives
//! in resources/config.toml (embedded into the binary).

pub mod backup;
pub mod backup_store;
pub mod config;
pub mod firstgen;
pub mod flash;
pub mod gpt;
pub mod ota;
pub mod rkfw;
pub mod session;
pub mod userdata;

/// SoC backend identity. Rockchip only today; the contract is kept for
/// a future Amlogic backend.
pub trait SocBackend {
    /// Human-readable vendor name.
    fn name(&self) -> &'static str;
}
