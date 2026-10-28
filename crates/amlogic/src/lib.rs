//! Native Amlogic update (USB burning) protocol stack — the download
//! mode of the Amlogic SoCs (VK Capsula Mini rev. MRC02B on A113X and
//! other boards). Cross-platform over `usbcore`/nusb (WinUSB on
//! Windows); a port of the wire protocol of the vendor `update` tool:
//!
//! - device side: u-boot `drivers/usb/gadget/v2_burning/` (2015.01
//!   vendor trees) and the BootROM requests documented in pyamlboot
//!   `PROTOCOL.md` (github.com/superna9999/pyamlboot);
//! - host side reference: pyamlboot (`pyamlboot.py`, `optimus.py`).
//!
//! Both download stages enumerate as `1b8e:c003` and speak the same
//! vendor requests on EP0 plus two bulk endpoints:
//!
//! - **BootROM (IPL)**: memory read/write/fill, run, large memory
//!   transfers, identify (with the OTP password flags).
//! - **u-boot burning gadget (TPL)**: everything above plus textual
//!   burning commands (AM_REQ_BULKCMD / AM_REQ_TPL_CMD → the
//!   `optimus_working` dispatcher: `download`, `upload`, `verify`,
//!   `disk_initial`, `save_setting`, `burn_complete`, ...), which give
//!   full storage access.
//!
//! On the VK Capsula Mini the vendor u-boot raises this download mode
//! on every power-up for a short factory flashing window. Identify
//! promptly; the window's lifetime depends on the bootloader. Secure
//! boot does not gate this window on A113X.

pub mod checksum;
pub mod error;
pub mod session;
pub mod soc;

use nusb::MaybeFuture;

pub use checksum::add_sum;
pub use error::{Error, Result};
pub use session::{
    AmlogicSession, BULKCMD_MAX, BULK_REPLY_LEN, MEDIA_ACK_LEN, MEDIA_CHUNK, NAND_STAGE,
    UPLOAD_SLOT,
};
pub use soc::{SocId, Stage, STAGE_MINOR_IPL, STAGE_MINOR_SPL, STAGE_MINOR_TPL};

/// USB VID of all Amlogic download modes.
pub const USB_VID_AMLOGIC: u16 = 0x1b8e;
/// Download-mode PID (BootROM and the u-boot burning gadget alike).
pub const USB_PID_UPDATE: u16 = 0xc003;

/// DRAM scratch addresses of the vendor flasher (flasher.sh): the
/// kernel-load address doubles as the NAND staging buffer.
pub const RAM_SCRATCH: u32 = 0x0108_0000;
/// Where `env export -t` writes the environment text.
pub const ENV_ADDR: u32 = 0x0200_0000;
/// Size reserved for the env text.
pub const ENV_SIZE: usize = 0x1_0000;

/// Vendor partition map of the Capsula Mini NAND (256 MiB, flasher.sh
/// VPART_*): name -> (offset, size). The AML reserved areas (bbt, env,
/// keys, dtb, ddr at 0x280000..0x5c0000) are deliberately not listed:
/// they are device-unique and must not be reflashed from a dump.
pub const PARTITIONS: &[(&str, u32, u32)] = &[
    ("bootloader", 0x0000_0000, 0x0020_0000),
    ("tpl", 0x0080_0000, 0x0080_0000),
    ("misc", 0x0100_0000, 0x0020_0000),
    ("boot_a", 0x0120_0000, 0x0100_0000),
    ("boot_b", 0x0220_0000, 0x0100_0000),
    ("system_a", 0x0320_0000, 0x0400_0000),
    ("system_b", 0x0720_0000, 0x0400_0000),
    ("data", 0x0b20_0000, 0x04e0_0000),
];

/// Look up a partition in [`PARTITIONS`].
pub fn partition(name: &str) -> Option<(&'static str, u32, u32)> {
    PARTITIONS.iter().find(|(n, _, _)| *n == name).copied()
}

/// Whether an Amlogic download-mode device is on the bus right now
/// (enumeration only, the device is not opened).
pub fn present() -> usbcore::Result<bool> {
    Ok(nusb::list_devices()
        .wait()?
        .any(|d| d.vendor_id() == USB_VID_AMLOGIC && d.product_id() == USB_PID_UPDATE))
}

/// Vendor request codes of the update protocol (EP0, recipient device).
pub mod req {
    pub const WRITE_MEM: u8 = 0x01;
    pub const READ_MEM: u8 = 0x02;
    pub const FILL_MEM: u8 = 0x03;
    pub const MODIFY_MEM: u8 = 0x04;
    pub const RUN_IN_ADDR: u8 = 0x05;
    pub const WRITE_AUX: u8 = 0x06;
    pub const READ_AUX: u8 = 0x07;

    pub const WR_LARGE_MEM: u8 = 0x11;
    pub const RD_LARGE_MEM: u8 = 0x12;

    pub const IDENTIFY_HOST: u8 = 0x20;

    pub const TPL_CMD: u8 = 0x30;
    pub const TPL_STAT: u8 = 0x31;
    pub const WRITE_MEDIA: u8 = 0x32;
    pub const READ_MEDIA: u8 = 0x33;
    pub const BULKCMD: u8 = 0x34;
    pub const PASSWORD: u8 = 0x35;
    pub const NOP: u8 = 0x36;

    pub const GET_AMLC: u8 = 0x50;
    pub const WRITE_AMLC: u8 = 0x60;
}

/// RUN_IN_ADDR data flag: keep the USB phy powered across the jump.
pub const FLAG_KEEP_POWER_ON: u32 = 0x10;
