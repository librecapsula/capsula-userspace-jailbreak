//! USB transport: a trait over nusb (mockable for tests) and Rockchip
//! device-mode enumeration.

use crate::error::{Error, Result};
use nusb::descriptors::TransferType;
use nusb::transfer::{ControlOut, ControlType, Direction, Recipient};
use nusb::MaybeFuture;
use std::io::{Read as _, Write as _};

/// Snapshot of a Rockchip device present on the bus.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DeviceMode {
    /// 2207:330d — u-boot loader (rockusb).
    Loader,
    /// 2207:330e — raw MaskROM (BootROM).
    MaskRom,
    /// 2207:330e with iProduct == "USB-MSC" — usbplug runs in RAM.
    /// (Told apart by iProduct, not by the PID.)
    UsbPlug,
    /// 2207:0006 — Linux gadget (adb); NOT a download mode.
    LinuxGadget,
    /// Any other PID of the vendor (diagnostics).
    Other(u16),
}

impl DeviceMode {
    pub fn pid(&self) -> u16 {
        match self {
            DeviceMode::Loader => 0x330d,
            DeviceMode::MaskRom | DeviceMode::UsbPlug => 0x330e,
            DeviceMode::LinuxGadget => 0x0006,
            DeviceMode::Other(p) => *p,
        }
    }

    /// VID of this mode (every persona enumerates under the vendor's).
    pub fn vid(&self) -> u16 {
        crate::USB_VID_ROCKCHIP
    }

    /// Does a bus device (vid, pid, iProduct) belong to this mode?
    fn matches(&self, vid: u16, pid: u16, product: Option<&str>) -> bool {
        vid == self.vid() && pid == self.pid() && {
            // usbplug and MaskROM share the PID — told apart by iProduct
            match self {
                DeviceMode::UsbPlug => product == Some("USB-MSC"),
                DeviceMode::MaskRom => product != Some("USB-MSC"),
                _ => true,
            }
        }
    }

    /// The "best" of the present modes: 330d > usbplug > maskrom >
    /// 0006 > others. None if the bus is empty.
    pub fn best(modes: &[DeviceMode]) -> Option<DeviceMode> {
        if modes.contains(&DeviceMode::Loader) {
            return Some(DeviceMode::Loader);
        }
        if modes.contains(&DeviceMode::UsbPlug) {
            return Some(DeviceMode::UsbPlug);
        }
        if modes.contains(&DeviceMode::MaskRom) {
            return Some(DeviceMode::MaskRom);
        }
        if modes.contains(&DeviceMode::LinuxGadget) {
            return Some(DeviceMode::LinuxGadget);
        }
        modes.first().cloned()
    }

    /// Short human-readable mode name for logs.
    pub fn label(&self) -> String {
        match self {
            DeviceMode::Loader => "u-boot loader (330d)".into(),
            DeviceMode::MaskRom => "MaskROM (330e)".into(),
            DeviceMode::UsbPlug => "usbplug (330e, USB-MSC)".into(),
            DeviceMode::LinuxGadget => "Linux gadget (0006, not a download mode)".into(),
            DeviceMode::Other(p) => format!("other ({p:04x})"),
        }
    }
}

/// Minimal synchronous transport needed by the Rockchip protocols.
/// Production: NusbTransport; tests: mock.
pub trait Transport {
    /// Vendor OUT control transfer on endpoint 0 (MaskROM DownloadBoot:
    /// request=0x0C, value=0, index=stage code 0x471/0x472).
    fn control_out(&mut self, request: u8, value: u16, index: u16, data: &[u8]) -> Result<()>;

    /// Write the whole buffer to a bulk-OUT endpoint (split into chunks).
    fn bulk_write(&mut self, endpoint: u8, data: &[u8]) -> Result<()>;

    /// Read exactly buf.len() bytes from a bulk-IN endpoint (loop until
    /// full).
    fn bulk_read(&mut self, endpoint: u8, buf: &mut [u8]) -> Result<()>;
}

/// Timeout for control transfers.
const CONTROL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Transport over nusb (blocking IO via the MaybeFuture/EndpointRead/
/// EndpointWrite adapters).
pub struct NusbTransport {
    #[allow(dead_code)] // kept for the interface lifetime
    device: nusb::Device,
    interface: nusb::Interface,
    /// bulk-IN endpoint (usually 0x81).
    pub ep_in: u8,
    /// bulk-OUT endpoint (usually 0x02).
    pub ep_out: u8,
}

impl NusbTransport {
    /// Open the Rockchip device in the given mode and claim interface 0.
    /// Errors if the device is not present.
    pub fn open(mode: &DeviceMode) -> Result<Self> {
        let info = find_device(mode).ok_or(Error::DeviceNotFound)?;
        Self::open_device_info(&info)
    }

    /// Open an exact DeviceInfo (to pick a specific instance).
    pub fn open_device_info(info: &nusb::DeviceInfo) -> Result<Self> {
        let device = info.open().wait()?;
        let interface = match device.claim_interface(0).wait() {
            Ok(i) => i,
            Err(_) => device.detach_and_claim_interface(0).wait()?,
        };

        // Find the bulk IN/OUT endpoints in the active configuration
        let config = device
            .active_configuration()
            .map_err(|e| Error::Usb(e.to_string()))?;
        let mut ep_in = None;
        let mut ep_out = None;
        'outer: for iface in config.interfaces() {
            for alt in iface.alt_settings() {
                for ep in alt.endpoints() {
                    if ep.transfer_type() != TransferType::Bulk {
                        continue;
                    }
                    match ep.direction() {
                        Direction::In => ep_in = Some(ep.address()),
                        Direction::Out => ep_out = Some(ep.address()),
                    }
                }
                if ep_in.is_some() && ep_out.is_some() {
                    break 'outer;
                }
            }
        }
        let (ep_in, ep_out) = (ep_in, ep_out);
        let (Some(ep_in), Some(ep_out)) = (ep_in, ep_out) else {
            return Err(Error::Usb("device has no bulk endpoints".into()));
        };

        Ok(NusbTransport {
            device,
            interface,
            ep_in,
            ep_out,
        })
    }
}

/// Maximum bytes per bulk-IN read request.
///
/// nusb enables the WinUSB RAW_IO pipe policy on bulk-IN endpoints,
/// and RAW_IO requests are never split by WinUSB: anything above the
/// host stack's maximum transfer size (2 MiB on common xHCI stacks;
/// measured: 2 MiB passes, 3 MiB fails with ERROR_INVALID_FUNCTION =
/// "usb: unknown (error 1)") fails instantly. Split larger reads into
/// 1 MiB pieces. This is protocol-transparent: the data phase is a
/// byte stream and the device does not see host request boundaries.
/// Bulk-OUT needs no cap — WinUSB splits large OUT requests itself
/// (RAW_IO is only set on IN endpoints by nusb).
const BULK_IN_MAX: usize = 1024 * 1024;

impl Transport for NusbTransport {
    fn control_out(&mut self, request: u8, value: u16, index: u16, data: &[u8]) -> Result<()> {
        self.interface
            .control_out(
                ControlOut {
                    control_type: ControlType::Vendor,
                    recipient: Recipient::Device,
                    request,
                    value,
                    index,
                    data,
                },
                CONTROL_TIMEOUT,
            )
            .wait()?;
        Ok(())
    }

    fn bulk_write(&mut self, endpoint: u8, data: &[u8]) -> Result<()> {
        let ep = self
            .interface
            .endpoint::<nusb::transfer::Bulk, nusb::transfer::Out>(endpoint)
            .map_err(|e| Error::Usb(e.to_string()))?;
        let mut writer = ep.writer(data.len().max(512));
        writer
            .write_all(data)
            .map_err(|e| Error::Usb(e.to_string()))?;
        // EndpointWrite buffers until full: without an explicit flush a
        // short write (the 31-byte CBW) is never submitted.
        writer.flush().map_err(|e| Error::Usb(e.to_string()))?;
        Ok(())
    }

    fn bulk_read(&mut self, endpoint: u8, buf: &mut [u8]) -> Result<()> {
        for chunk in buf.chunks_mut(BULK_IN_MAX) {
            let ep = self
                .interface
                .endpoint::<nusb::transfer::Bulk, nusb::transfer::In>(endpoint)
                .map_err(|e| Error::Usb(e.to_string()))?;
            let mut reader = ep.reader(chunk.len().max(512));
            reader
                .read_exact(chunk)
                .map_err(|e| Error::Usb(e.to_string()))?;
        }
        Ok(())
    }
}

/// Find the bus device of the given mode (first match). iProduct is
/// consulted for the 330e usbplug/MaskROM split.
pub fn find_device(mode: &DeviceMode) -> Option<nusb::DeviceInfo> {
    nusb::list_devices()
        .wait()
        .ok()?
        .find(|d| mode.matches(d.vendor_id(), d.product_id(), d.product_string()))
}

/// USB serial (iSerialNumber) of the device in the given mode, if it is
/// on the bus. On regular columns the loader serial starts with digits
/// (the chip UID prefix); first-generation units carry random-looking
/// hex — see `jb_core::firstgen`.
pub fn device_serial(mode: &DeviceMode) -> Option<String> {
    find_device(mode).and_then(|d| d.serial_number().map(|s| s.to_string()))
}

/// All Rockchip modes currently on the bus (deduplicated). Devices
/// under other VIDs (e.g. the stock u-boot fastboot gadget, which
/// enumerates under Google's 18d1) are not ours — not listed.
pub fn list_modes() -> Result<Vec<DeviceMode>> {
    let mut modes: Vec<DeviceMode> = Vec::new();
    for d in nusb::list_devices().wait()? {
        if d.vendor_id() != crate::USB_VID_ROCKCHIP {
            continue;
        }
        let m = match d.product_id() {
            0x330d => DeviceMode::Loader,
            0x330e if d.product_string() == Some("USB-MSC") => DeviceMode::UsbPlug,
            0x330e => DeviceMode::MaskRom,
            0x0006 => DeviceMode::LinuxGadget,
            p => DeviceMode::Other(p),
        };
        if !modes.contains(&m) {
            modes.push(m);
        }
    }
    Ok(modes)
}

/// The best mode present right now (see [`DeviceMode::best`]).
pub fn current_mode() -> Result<Option<DeviceMode>> {
    Ok(DeviceMode::best(&list_modes()?))
}
