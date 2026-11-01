//! The rockchip platform (RK3308): the domain (bring-up over the
//! rockusb loader personas, the full GPT dump, the ext4 userdata
//! overlay, WRITE_LBA flashing) plus the [`jb_core::backend::Backend`]
//! and [`jb_core::scenario::Platform`] implementations that drive the
//! shared scenario skeleton over this hardware.
//!
//! First-generation columns (their locked BootROM rejects our loader)
//! and `--no-backup` runs work over the stock loader; on first
//! generation the dump is NOT intact (0xCC above the 32 MiB read mask)
//! and userdata is always built from scratch.

pub mod backup;
pub mod firstgen;
pub mod flash;
pub mod gpt;
pub mod loader;
pub mod platform;
pub mod session;
pub mod userdata;
