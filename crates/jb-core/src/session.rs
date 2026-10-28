//! Device bring-up (a port of board_ready / the backup.sh loop) and
//! pipeline primitives shared by the operations.
//!
//! Every operation runs over OUR usbplug loaded into RAM from the OTA
//! loader: the RAM-patch address is only known for this build, so the
//! DRAM signatures are always verified.

use crate::config::Config;
use rockusb::loader::RESET_SUBCODE_MASKROM;
use rockusb::monitor::wait_download_mode;
use rockusb::{Error as UsbError, LoaderContainer, LoaderSession, MaskRomSession, Transport};
use std::time::Duration;

/// Progress events for CLI/GUI.
#[derive(Debug, Clone)]
pub enum Progress {
    /// A protocol line (the "==> ..." of the bash v1).
    Step(String),
    TransferStart {
        name: String,
        bytes: u64,
    },
    TransferProgress {
        name: String,
        done: u64,
        total: u64,
    },
    TransferDone {
        name: String,
    },
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

/// Bring the board into a working rockusb session.
///
/// - Loader (330d): reset into MaskROM and load our loader (the RAM-patch
///   constants do not apply to the stock u-boot usbplug);
/// - raw MaskROM (330e): download the loader into RAM (flash untouched);
/// - a running usbplug (330e + USB-MSC): reuse it if it is ours;
/// - empty bus / Linux gadget: print the hint and wait for a download mode.
pub fn bring_up(
    config: &Config,
    loader: &LoaderContainer,
    wait: Option<Duration>,
    progress: ProgressFn,
) -> Result<LoaderSession<rockusb::NusbTransport>, BringUpError> {
    let hint = &config.hint.text;
    loop {
        let mode = rockusb::current_mode()?;
        let Some(mode) = mode else {
            wait_download_mode(wait, hint)?;
            continue;
        };
        match mode {
            rockusb::DeviceMode::Loader => {
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
                return Ok(s);
            }
            rockusb::DeviceMode::UsbPlug => {
                // a running usbplug is usable only if it is ours
                let mut s = open_loader()?;
                match verify_usbplug_signatures(&mut s, config, &|_| {}) {
                    Ok(()) => {
                        progress(Progress::Step(
                            "usbplug is running, signatures match".into(),
                        ));
                        return Ok(s);
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
                log::info!(
                    "device in {} mode, waiting for a download mode",
                    other.label()
                );
                wait_download_mode(wait, hint)?;
            }
        }
    }
}

fn open_loader() -> rockusb::Result<LoaderSession<rockusb::NusbTransport>> {
    let t = rockusb::open_mode(&rockusb::DeviceMode::Loader)
        .or_else(|_| rockusb::open_mode(&rockusb::DeviceMode::UsbPlug))?;
    let (ep_in, ep_out) = (t.ep_in, t.ep_out);
    Ok(LoaderSession::new(t, ep_in, ep_out))
}

fn open_maskrom() -> rockusb::Result<rockusb::NusbTransport> {
    rockusb::open_mode(&rockusb::DeviceMode::MaskRom)
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
