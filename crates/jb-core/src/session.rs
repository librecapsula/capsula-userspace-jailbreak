//! Device bring-up (a port of board_ready / the backup.sh loop) and
//! pipeline primitives shared by the operations.
//!
//! Every regular-column operation runs over OUR usbplug loaded into RAM
//! from the OTA loader: the RAM-patch address is only known for this
//! build, so the DRAM signatures are always verified.
//!
//! First-generation columns never get there (their BootROM rejects the
//! loader); for them bring-up returns the stock u-boot rockusb loader
//! (330d with a gift serial), and the caller runs the no-backup
//! userdata flow. The fastboot persona (18d1:d00d) is an emergency
//! state of that u-boot — never a working channel.

use crate::config::Config;
use crate::firstgen::is_first_generation;
use rockusb::loader::RESET_SUBCODE_MASKROM;
use rockusb::monitor::wait_download_mode;
use rockusb::{
    Error as UsbError, LoaderContainer, LoaderSession, MaskRomSession, NusbTransport, Transport,
};
use std::time::Duration;

/// Progress events for CLI/GUI.
#[derive(Debug, Clone)]
pub enum Progress {
    /// A protocol line (the "==> ..." of the bash v1).
    Step(String),
    PartitionStart {
        name: String,
        sectors: u64,
    },
    PartitionProgress {
        name: String,
        done: u64,
        total: u64,
    },
    PartitionDone {
        name: String,
    },
}

pub type ProgressFn<'a> = &'a dyn Fn(Progress);

/// Bring-up error. `LoaderRejected`: the usbplug did not start — BootROM
/// silently rejected the loader signature (an unsupported board).
#[derive(Debug, thiserror::Error)]
pub enum BringUpError {
    #[error(transparent)]
    Usb(#[from] rockusb::Error),
    #[error("usbplug did not start: BootROM rejected the loader signature")]
    LoaderRejected,
}

/// The live device session after bring-up.
pub enum BroughtUp {
    /// Our usbplug in RAM (signatures verified): full backup + flash.
    Ours(LoaderSession<NusbTransport>),
    /// First generation: the stock u-boot rockusb loader (330d) with a
    /// gift serial. GPT is readable from it; userdata is writable.
    FirstGenStockLoader(LoaderSession<NusbTransport>),
}

/// Does this USB serial identify the column? Gadget fallbacks report
/// empty or all-zero strings (the BootROM gadget: "000000000") — those
/// must never become a backup cache key.
pub fn is_identifying(serial: &str) -> bool {
    !serial.is_empty() && serial.chars().any(|c| c != '0')
}

/// Bring the board into a working session. Returns the session plus the
/// column identity serial for the backup key. The serial is read
/// exactly ONCE — when the loader persona (330d) is recognized — and is
/// kept for the whole session; other personas never contribute (the
/// BootROM gadget reports zeros). A column that never shows up as 330d
/// (direct MaskROM entry, a usbplug left in RAM from a previous run)
/// yields an empty serial: the caller must not trust backup caches then.
///
/// - Loader (330d) with a regular serial: reset into MaskROM and load
///   our loader (the RAM-patch constants do not apply to the stock
///   u-boot usbplug);
/// - Loader (330d) with a first-generation serial: the stock loader
///   itself — `BroughtUp::FirstGenStockLoader` (our loader would be
///   rejected by its locked BootROM);
/// - raw MaskROM (330e): download the loader into RAM (flash untouched);
/// - a running usbplug (330e + USB-MSC): reuse it if it is ours;
/// - fastboot (18d1:d00d): an emergency state, not a working channel —
///   same handling as any non-download mode (wait, hint);
/// - empty bus / Linux gadget: print the hint and wait for a download mode.
pub fn bring_up(
    config: &Config,
    loader: &LoaderContainer,
    wait: Option<Duration>,
    progress: ProgressFn,
    // Loader serial the caller has already read (the CLI classification
    // pass does), so the session reads it at most once. None — read at
    // the first 330d recognition.
    known_serial: Option<String>,
) -> Result<(BroughtUp, String), BringUpError> {
    let hint = &config.hint.text;
    let mut serial: Option<String> = known_serial;
    loop {
        let mode = rockusb::current_mode()?;
        let Some(mode) = mode else {
            wait_download_mode(wait, hint)?;
            continue;
        };
        match mode {
            rockusb::DeviceMode::Loader => {
                // Read the identity exactly once, BEFORE the MaskROM
                // reset consumes the persona. A first-generation serial
                // also switches the whole scenario: its locked BootROM
                // will refuse our usbplug, and the reset itself would
                // kick the running stock loader — keep it instead.
                let serial = serial
                    .get_or_insert_with(|| {
                        rockusb::device_serial(&rockusb::DeviceMode::Loader)
                            .unwrap_or_default()
                    })
                    .clone();
                if is_first_generation(&serial) {
                    return Ok((
                        BroughtUp::FirstGenStockLoader(attach_stock_loader(progress)?),
                        serial,
                    ));
                }
                // sanity-check the pipe: a wedged loader endpoint fails
                // every transfer and can only be fixed by re-entering
                // the loader mode
                {
                    let mut probe = open_loader()?;
                    if let Err(e) = probe.ready() {
                        return Err(UsbError::WrongMode(format!(
                            "loader (330d) is present but not responding ({e}): \
                             power-cycle the device into loader mode again"
                        ))
                        .into());
                    }
                }
                progress(Progress::Step("loader (330d): resetting to MaskROM".into()));
                {
                    let mut s = open_loader()?;
                    if let Err(e) = s.reset(RESET_SUBCODE_MASKROM) {
                        return Err(UsbError::WrongMode(format!(
                            "reset to MaskROM was rejected ({e}): \
                             power-cycle the device into loader mode again"
                        ))
                        .into());
                    }
                }
                rockusb::monitor::wait_mode(rockusb::DeviceMode::MaskRom, Duration::from_secs(15))?;
            }
            rockusb::DeviceMode::MaskRom => {
                // no serial read here: the identity is the loader serial
                // captured above (loader entry) or nothing (direct
                // MaskROM entry — the BootROM gadget reports zeros)
                progress(Progress::Step(
                    "MaskROM: downloading the loader into RAM (flash untouched)".into(),
                ));
                {
                    let mut m = MaskRomSession::new(open_maskrom()?);
                    m.download(loader)?;
                }
                progress(Progress::Step("waiting for usbplug (up to 20 s)".into()));
                if rockusb::monitor::wait_mode(
                    rockusb::DeviceMode::UsbPlug,
                    Duration::from_secs(20),
                )
                .is_err()
                {
                    progress(Progress::Step("usbplug did not come up".into()));
                    return Err(BringUpError::LoaderRejected);
                }
                let mut s = open_loader()?;
                verify_usbplug_signatures(&mut s, config, progress)?;
                return Ok((BroughtUp::Ours(s), serial.unwrap_or_default()));
            }
            rockusb::DeviceMode::UsbPlug => {
                // a running usbplug is usable only if it is ours; no
                // serial read — see the MaskRom note
                let mut s = open_loader()?;
                match verify_usbplug_signatures(&mut s, config, &|_| {}) {
                    Ok(()) => {
                        progress(Progress::Step(
                            "usbplug is running, signatures match".into(),
                        ));
                        return Ok((BroughtUp::Ours(s), serial.unwrap_or_default()));
                    }
                    Err(_) => {
                        progress(Progress::Step(
                            "running usbplug is foreign: resetting to MaskROM".into(),
                        ));
                        let _ = s.reset(RESET_SUBCODE_MASKROM);
                        rockusb::monitor::wait_mode(
                            rockusb::DeviceMode::MaskRom,
                            Duration::from_secs(15),
                        )?;
                    }
                }
            }
            other => {
                // fastboot (18d1:d00d) is an emergency state of the stock
                // u-boot, not a working channel: fail fast with the
                // recovery instruction instead of waiting forever
                if matches!(other, rockusb::DeviceMode::Fastboot) {
                    return Err(UsbError::WrongMode(
                        "the device is in its EMERGENCY fastboot state \
                         (18d1:d00d): power-cycle it and re-enter loader mode \
                         (recovery button), then run the tool again"
                            .into(),
                    )
                    .into());
                }
                log::info!(
                    "device in {} mode, waiting for a download mode",
                    other.label()
                );
                wait_download_mode(wait, hint)?;
            }
        }
    }
}

fn open_loader() -> rockusb::Result<LoaderSession<NusbTransport>> {
    let t = NusbTransport::open(&rockusb::DeviceMode::Loader)
        .or_else(|_| NusbTransport::open(&rockusb::DeviceMode::UsbPlug))?;
    let (ep_in, ep_out) = (t.ep_in, t.ep_out);
    Ok(LoaderSession::new(t, ep_in, ep_out))
}

fn open_maskrom() -> rockusb::Result<NusbTransport> {
    NusbTransport::open(&rockusb::DeviceMode::MaskRom)
}

/// Open and sanity-check the stock rockusb loader of a first-generation
/// column (330d with a gift serial).
pub fn attach_stock_loader(
    progress: ProgressFn,
) -> rockusb::Result<LoaderSession<NusbTransport>> {
    progress(Progress::Step(
        "first-generation column: keeping the stock loader (330d)".into(),
    ));
    let mut s = open_loader()?;
    if let Err(e) = s.ready() {
        return Err(UsbError::WrongMode(format!(
            "stock loader (330d) is not responding ({e}): \
             power-cycle the device into loader mode again"
        )));
    }
    Ok(s)
}

/// Verify the usbplug signatures in DRAM: proof that our loader build is
/// running, whose RAM-patch address is known.
pub fn verify_usbplug_signatures<T: Transport>(
    s: &mut LoaderSession<T>,
    config: &Config,
    progress: ProgressFn,
) -> rockusb::Result<()> {
    let sig1 = hex::decode(&config.usbplug.signature1_hex)
        .map_err(|_| UsbError::Loader("signature1_hex is not hex".into()))?;
    let sig2 = hex::decode(&config.usbplug.signature2_hex)
        .map_err(|_| UsbError::Loader("signature2_hex is not hex".into()))?;
    let mut buf = [0u8; 64];
    for (addr, want, which) in [
        (config.usbplug.signature1_addr, &sig1, "signature1"),
        (config.usbplug.signature2_addr, &sig2, "signature2"),
    ] {
        s.read_mem(addr, &mut buf[..want.len()])?;
        if &buf[..want.len()] != want.as_slice() {
            progress(Progress::Step(format!(
                "usbplug mismatch: {which} at {addr:#x}"
            )));
            return Err(UsbError::WrongMode(
                "usbplug signatures do not match (foreign loader?)".into(),
            ));
        }
    }
    progress(Progress::Step("usbplug signatures verified".into()));
    Ok(())
}

/// Read and parse the on-device GPT (LBA1 + 33 sectors of entries).
pub fn read_gpt<T: Transport>(
    s: &mut LoaderSession<T>,
    progress: ProgressFn,
) -> rockusb::Result<crate::gpt::Gpt> {
    progress(Progress::Step("reading GPT".into()));
    let mut buf = vec![0u8; 34 * 512];
    s.read_lba(1, &mut buf)?;
    crate::gpt::Gpt::parse(&buf).map_err(|e| UsbError::Loader(format!("GPT: {e}")))
}

#[cfg(test)]
mod tests {
    use super::is_identifying;

    #[test]
    fn identifying_serials() {
        assert!(is_identifying("01139EB3613ABD80")); // real chipid
        assert!(is_identifying("e5fe5a07c23ce39a")); // first generation
        assert!(is_identifying("123")); // short but real
    }

    #[test]
    fn dummy_serials_are_not_identifying() {
        // the BootROM gadget reports zeros; an unread serial is empty
        assert!(!is_identifying("000000000"));
        assert!(!is_identifying("0"));
        assert!(!is_identifying(""));
    }
}
