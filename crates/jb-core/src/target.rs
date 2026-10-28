//! Unified wait for a supported speaker and dispatch on the SoC vendor.
//!
//! The happy case: the user launches the tool, is asked to plug the
//! speaker in, and the tool watches the bus. Two vendor families are
//! supported:
//!
//! - **Rockchip** (Capsula big / early minis, 2207:330d/330e): enter a
//!   download mode with the recovery button combo; the sighting is
//!   debounced like the v1 script.
//! - **Amlogic** (late minis, MRC02B board, 1b8e:c003): the stock u-boot
//!   raises its factory download window on every power-up for ~450 ms;
//!   the sighting is acted on immediately (no debounce — the window is
//!   half of the rockchip stability delay). Identify promptly; the
//!   lifetime of the window depends on the bootloader.

use crate::session::Progress;
use amlogic::AmlogicSession;
use rockusb::DeviceMode;
use std::time::{Duration, Instant};
use thiserror::Error;

/// Bus poll interval (the amlogic window is ~450 ms: poll faster than
/// the rockchip v1 cadence to keep the open+identify comfortably inside).
pub const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// A supported speaker detected on the bus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// A Rockchip Capsula in a download mode (loader/usbplug/MaskROM).
    Rockchip(DeviceMode),
    /// An Amlogic SoC in a download mode (BootROM or the u-boot burning
    /// gadget — told apart by identify at bring-up).
    Amlogic,
}

impl Target {
    pub fn label(&self) -> String {
        match self {
            Target::Rockchip(m) => format!("rockchip {}", m.label()),
            Target::Amlogic => "amlogic (1b8e:c003)".into(),
        }
    }
}

#[derive(Debug, Error)]
pub enum TargetError {
    /// The wait timed out with nothing on the bus.
    #[error("no supported speaker appeared on the bus within the timeout")]
    Timeout,
    /// USB error (enumeration/open failures).
    #[error(transparent)]
    Usb(#[from] usbcore::Error),
    /// Rockchip enumeration error.
    #[error(transparent)]
    Rockchip(#[from] rockusb::Error),
    /// The Amlogic device kept failing to open (driver problem?) —
    /// surfaced after repeated attempts instead of looping forever.
    #[error("amlogic device present but cannot be opened: {0}")]
    AmlogicOpen(String),
}

/// Watch the bus for a supported download mode. Prints `hint` once.
/// Rockchip sightings are debounced (rockusb DEBOUNCE); an Amlogic
/// sighting returns immediately — bring-up re-verifies by opening.
pub fn wait_target(timeout: Option<Duration>, hint: &str) -> Result<Target, TargetError> {
    let start = Instant::now();
    let mut hint_shown = false;
    loop {
        // rockchip first (deterministic order when both are connected)
        let modes = rockusb::list_modes()?;
        if let Some(m) = DeviceMode::best(&modes) {
            if matches!(
                m,
                DeviceMode::Loader | DeviceMode::UsbPlug | DeviceMode::MaskRom
            ) {
                // the window can be short: make sure it persists
                std::thread::sleep(rockusb::monitor::DEBOUNCE);
                if let Some(now) = rockusb::current_mode()? {
                    if matches!(
                        now,
                        DeviceMode::Loader | DeviceMode::UsbPlug | DeviceMode::MaskRom
                    ) {
                        log::info!("target stable: {}", Target::Rockchip(now.clone()).label());
                        return Ok(Target::Rockchip(now));
                    }
                }
                log::warn!("rockchip window closed within debounce — waiting again");
            }
        }
        if amlogic::present()? {
            log::info!("target: {}", Target::Amlogic.label());
            return Ok(Target::Amlogic);
        }
        if let Some(t) = timeout {
            if start.elapsed() >= t {
                return Err(TargetError::Timeout);
            }
        }
        if !hint_shown {
            if !hint.is_empty() {
                println!("{hint}");
            }
            hint_shown = true;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// Open and identify the Amlogic device, retrying until `deadline` —
/// the first open/identify may race the ~450 ms u-boot window closing;
/// then the user power-cycles the speaker again and the next window is
/// caught. Persistent open failures (e.g. a missing driver) surface
/// after several attempts instead of looping forever. Returns the live
/// session with the identify reply.
pub fn bring_up_amlogic(
    deadline: Option<Duration>,
    progress: &dyn Fn(Progress),
) -> Result<(AmlogicSession<rockusb::NusbTransport>, amlogic::SocId), TargetError> {
    // The download window is ~1 s per power-up and closes regardless of
    // identify, so the hot path must be lean: open directly on every
    // poll (one bus enumeration per attempt, no presence pre-check) and
    // treat "not found" as an empty bus.
    let start = Instant::now();
    let mut open_failures = 0u32;
    let mut seen = false;
    loop {
        match open_and_identify(progress) {
            Ok(pair) => return Ok(pair),
            Err(amlogic::Error::DeviceNotFound) => {
                if seen {
                    log::info!("usb: 1b8e:c003 gone (+{}ms)", start.elapsed().as_millis());
                    seen = false;
                }
                // the reference flasher polls at 10 ms; a busy spin here
                // starves nothing but burns a core for minutes
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e @ amlogic::Error::MultipleDevices) => {
                return Err(TargetError::AmlogicOpen(e.to_string()));
            }
            Err(e) => {
                if !seen {
                    log::info!(
                        "usb: 1b8e:c003 appeared (+{}ms)",
                        start.elapsed().as_millis()
                    );
                    seen = true;
                }
                open_failures += 1;
                if open_failures >= 10 {
                    return Err(TargetError::AmlogicOpen(e.to_string()));
                }
                log::warn!(
                    "amlogic open/identify failed ({e}) (+{}ms); retrying",
                    start.elapsed().as_millis()
                );
            }
        }
        if let Some(d) = deadline {
            if start.elapsed() >= d {
                return Err(TargetError::Timeout);
            }
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn open_and_identify(
    progress: &dyn Fn(Progress),
) -> amlogic::Result<(AmlogicSession<rockusb::NusbTransport>, amlogic::SocId)> {
    let t = Instant::now();
    let mut s = AmlogicSession::open()?;
    let opened = t.elapsed();
    // Identify before any settling delay. prime() already retries a
    // transiently unavailable bulk pipe, and BootROM has no burning pipe.
    // The first bulkcmd of a session can lose its leading bytes
    // (flasher.sh prime_bulk): sacrifice a command nobody needs. A
    // failure means a dead bulk pipe — continuing would burn the whole
    // window on commands whose status nobody can read, so fail the
    // attempt and let the caller reconnect (the reference flasher fails
    // the run on a failed prime).
    let soc = s.identify_and_prime()?;
    log::info!("amlogic: open +{opened:?}, identify +{:?}", t.elapsed());
    progress(Progress::Step(format!("amlogic download device: {soc}")));
    Ok((s, soc))
}
