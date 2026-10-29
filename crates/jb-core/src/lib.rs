//! capsula-jailbreak domain: everything independent of the transport
//! and of the UI.
//!
//! Method: userspace overwrite. userdata is not signed and is freely
//! rewritable; no other partition is touched. The configuration lives
//! in resources/config.toml (embedded into the binary).
//!
//! Today the crate is the Rockchip (RK3308) domain: GPT, the full-dump
//! pipeline, the userdata overlay, the embedded loader, bring-up and
//! first-generation detection. The platform dispatch (which backend a
//! USB device belongs to) lives one level up, in jb-cli
//! (`backend::Backend` / `rockchip`).

pub mod aml;
pub mod backup;
pub mod backup_store;
pub mod config;
pub mod firstgen;
pub mod flash;
pub mod gpt;
pub mod loader;
pub mod session;
pub mod userdata;
