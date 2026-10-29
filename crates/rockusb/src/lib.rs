//! Native Rockchip protocol stack for VK Capsula (RK3308) and other
//! Rockchip boards. A port of `xrock` v1.1.3 (github.com/xboot/xrock,
//! MIT) without libusb or subprocesses — transport via `nusb` (pure
//! Rust).
//!
//! Layers:
//!
//! - [`transport`] — USB transport: 2207:* mode enumeration, interface
//!   claim, bulk/control transfers; `Transport` trait + mock.
//! - [`loader_container`] — BOOT/LDR loader container parser (RKBOOT).
//! - [`maskrom`] — BootROM stage: DownloadBoot (control 0x0C, stage
//!   codes 0x471/0x472, CRC16-CCITT, RC4, 4096-byte chunks).
//! - [`loader`] — usbplug stage: rockusb over bulk CBW/CSW ('USBC'/
//!   'USBS'): flash read/write/erase by LBA, RAM read/write, reset, info.
//! - [`monitor`] — DeviceMonitor: bus events with timestamps, priority
//!   330d > usbplug > maskrom, debounce (port of common.sh).
//!
//! Everything Rockchip-vendor-specific lives inside this crate; jb-core
//! talks to abstractions, and a second backend (Amlogic) will be added
//! later as a separate crate on the same principle.

pub mod error;
pub mod loader;
pub mod loader_container;
pub mod maskrom;
pub mod mock;
pub mod monitor;
pub mod transport;
pub mod util;

pub use error::{Error, Result};
pub use loader::LoaderSession;
pub use loader_container::LoaderContainer;
pub use maskrom::MaskRomSession;
pub use monitor::DeviceMonitor;
pub use transport::{
    current_mode, device_serial, list_modes, DeviceMode, NusbTransport, Transport,
};

/// USB VID of all Rockchip modes.
pub const USB_VID_ROCKCHIP: u16 = 0x2207;
/// USB VID the stock u-boot enumerates its fastboot gadget under
/// (Google's, by u-boot tradition). The tool never talks to it: on the
/// Capsula hardware this persona means an EMERGENCY state — the only
/// correct action is a power cycle back into loader mode.
pub const USB_VID_FASTBOOT: u16 = 0x18d1;
/// fastboot gadget PID (under [`USB_VID_FASTBOOT`]).
pub const USB_PID_FASTBOOT: u16 = 0xd00d;
/// MaskROM (BootROM) PID — the same after `db` (usbplug): told apart by
/// iProduct == "USB-MSC".
pub const USB_PID_MASKROM: u16 = 0x330e;
/// Loader mode PID (u-boot rockusb).
pub const USB_PID_LOADER: u16 = 0x330d;
/// Live Linux gadget PID (adb); NOT a download mode.
pub const USB_PID_LINUX_GADGET: u16 = 0x0006;
