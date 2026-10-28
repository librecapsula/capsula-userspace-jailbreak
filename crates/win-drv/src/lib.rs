//! Automatic WinUSB binding for Rockchip boards on Windows.
//!
//! capsula-jb talks to the board over WinUSB (nusb). Windows allows one
//! function driver per device node, and a board cycles through several
//! USB identities while capsula-jb works on it (loader 330d, MaskROM and
//! usbplug 330e, the post-jailbreak adb gadget 0006) — each a separate
//! devnode that picks its driver at creation. A vendor "Rockusb" driver
//! package (RKDevTool's DriverAssistant), when installed, outranks the
//! Zadig-style INFs on freshly created nodes, which used to force a
//! manual Zadig pass for every state transition.
//!
//! This crate removes the manual step. It carries the Zadig/libwdi
//! generated WinUSB driver packages (see `resources/drivers/winusb/`),
//! installs their self-signed signer certificates into the machine
//! trust stores, and force-binds every Rockchip devnode to WinUSB —
//! from an elevated helper process when needed (one UAC prompt). The
//! binding work itself is `UpdateDriverForPlugAndPlayDevices`: the
//! same newdev API Zadig calls.
//!
//! On other platforms everything is a no-op.

use std::path::{Path, PathBuf};

/// A Zadig/libwdi-generated WinUSB driver package for one hardware ID.
pub struct Package {
    /// Hardware ID the INF matches, e.g. `USB\VID_2207&PID_330D`.
    pub hwid: &'static str,
    /// File names must be kept verbatim: the catalog signs the INF by
    /// name, and the INF references the catalog by name.
    pub inf_name: &'static str,
    pub cat_name: &'static str,
    pub inf: &'static [u8],
    pub cat: &'static [u8],
    /// The self-signed signer certificate (extracted from the
    /// catalog). Installed into ROOT and TrustedPublisher so the
    /// package signature validates on a fresh machine — exactly what
    /// Zadig does after generating it.
    pub cer: &'static [u8],
}

pub const PACKAGE_330D: Package = Package {
    hwid: "USB\\VID_2207&PID_330D",
    inf_name: "usb_download_gadget.inf",
    cat_name: "USB_download_gadget.cat",
    inf: include_bytes!("../../../resources/drivers/winusb/capsula-330d/usb_download_gadget.inf"),
    cat: include_bytes!("../../../resources/drivers/winusb/capsula-330d/USB_download_gadget.cat"),
    cer: include_bytes!("../../../resources/drivers/winusb/capsula-330d/capsula-330d.cer"),
};

/// One package covers both 330e faces: MaskROM and usbplug share the
/// PID and differ only by iProduct, which does not take part in driver
/// matching.
pub const PACKAGE_330E: Package = Package {
    hwid: "USB\\VID_2207&PID_330E",
    inf_name: "usb-msc.inf",
    cat_name: "USB-MSC.cat",
    inf: include_bytes!("../../../resources/drivers/winusb/capsula-330e/usb-msc.inf"),
    cat: include_bytes!("../../../resources/drivers/winusb/capsula-330e/USB-MSC.cat"),
    cer: include_bytes!("../../../resources/drivers/winusb/capsula-330e/capsula-330e.cer"),
};

/// All packages we keep bound to WinUSB.
///
/// The adb gadget (2207:0006) is deliberately absent: a package for it
/// can only be generated against a live post-jailbreak gadget (Zadig
/// signs the exact INF). adb over Wi-Fi needs no driver at all, and USB
/// adb keeps working through any installed Android/Google WinUSB driver.
pub const PACKAGES: &[&Package] = &[&PACKAGE_330D, &PACKAGE_330E];

#[cfg(windows)]
mod sys;

#[cfg(windows)]
pub use sys::{fix_cwd_if_system32, pause_if_own_console, Session};

#[cfg(not(windows))]
mod stub;

#[cfg(not(windows))]
pub use stub::{fix_cwd_if_system32, pause_if_own_console, Session};

/// Does this error message look like "the devnode is bound to a wrong
/// driver"? nusb reports a non-WinUSB binding as "incompatible driver
/// is installed for the device"; match loosely to survive rewording.
pub fn is_binding_error(msg: &str) -> bool {
    msg.contains("incompatible driver")
}

/// Walk an `anyhow` chain looking for a driver-binding error (rockusb
/// wraps nusb errors deep enough that the top message is not enough).
pub fn chain_is_binding_error(err: &anyhow::Error) -> bool {
    err.chain().any(|c| is_binding_error(&c.to_string()))
}

/// Directory the packages are materialized into for installation
/// (`UpdateDriverForPlugAndPlayDevices` needs a real INF path).
pub fn materialize_dir(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("capsula-jb-winusb-{tag}"))
}

/// Marker used by the CLI to detect a present board before the first
/// open attempt (proactive UAC instead of a failed first attempt).
#[cfg(windows)]
pub fn any_rockchip_node_misbound() -> bool {
    sys::rockchip_nodes().iter().any(|n| !n.bound_ok())
}

#[cfg(not(windows))]
pub fn any_rockchip_node_misbound() -> bool {
    false
}

/// Wait until every present Rockchip node is bound (the first install
/// restarts the devnode; give it time to settle before the first open
/// attempt). Returns false on timeout. No-op on non-Windows.
#[cfg(windows)]
pub fn wait_until_bound(timeout: std::time::Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while any_rockchip_node_misbound() {
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    true
}

#[cfg(not(windows))]
pub fn wait_until_bound(_timeout: std::time::Duration) -> bool {
    true
}

/// Shared piece of helper/inline logging: append a line to the session
/// log next to the done file.
pub fn log_line(log: &Path, msg: &str) {
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)
    {
        let _ = writeln!(f, "[{}] {msg}", chrono_free_now());
    }
}

fn chrono_free_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_error_detection() {
        assert!(is_binding_error(
            "incompatible driver is installed for this device"
        ));
        assert!(is_binding_error(
            "usb: incompatible driver is installed for the device"
        ));
        assert!(!is_binding_error("rockchip device not found"));
        assert!(!is_binding_error("usb: transfer was cancelled"));
    }

    #[test]
    fn packages_reference_the_rockchip_vendor_and_known_pids() {
        for pkg in PACKAGES {
            assert!(pkg.hwid.starts_with("USB\\VID_2207&PID_"));
            assert!(!pkg.inf_name.is_empty() && pkg.inf_name.ends_with(".inf"));
            assert!(!pkg.cat_name.is_empty() && pkg.cat_name.ends_with(".cat"));
            assert!(!pkg.inf.is_empty());
            assert!(!pkg.cat.is_empty());
            assert!(!pkg.cer.is_empty());
            // libwdi writes UTF-16 INFs with a BOM
            assert_eq!(&pkg.inf[..2], &[0xff, 0xfe], "{}", pkg.inf_name);
        }
    }
}
