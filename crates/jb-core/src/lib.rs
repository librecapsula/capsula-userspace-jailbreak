//! capsula-jailbreak shared domain: the platform contract, the
//! scenario skeleton and everything both platforms need.
//!
//! Method: userspace overwrite. The data partition (userdata on
//! rockchip, data on amlogic) is not signed and is freely rewritable;
//! no other partition is touched. The configuration lives in
//! resources/config.toml (embedded into the binary).
//!
//! The dependency layers: jb-cli (the binary: arguments, dispatch, UI)
//! → jb-rockchip / jb-amlogic (the platform domains and their
//! Backend+Platform implementations) → this crate (the contract:
//! `backend`, the scenario skeleton `scenario`, progress events,
//! the overlay file set, the capture storage, the config). This crate
//! knows no transports and no platforms.

pub mod backend;
pub mod backup_store;
pub mod config;
pub mod format;
pub mod overlay;
pub mod progress;
pub mod scenario;
