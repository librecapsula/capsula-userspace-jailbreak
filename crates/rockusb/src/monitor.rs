//! DeviceMonitor: watch the 2207:* bus with event logging and debounce.
//! Port of wait_download_mode / rock_id from legacy/common.sh.

use crate::error::Result;
use crate::transport::{list_modes, DeviceMode};
use std::time::{Duration, Instant};

/// Bus poll interval (bash v1: 50 ms — the mini loader window is < 1 s).
pub const POLL_INTERVAL: Duration = Duration::from_millis(50);
/// Stability window: an appearance must persist longer than this to
/// count (bash v1: 150 ms).
pub const DEBOUNCE: Duration = Duration::from_millis(150);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MonitorEvent {
    /// A device appeared on the bus.
    Appeared(DeviceMode),
    /// A device disappeared from the bus.
    Disappeared(DeviceMode),
}

/// Diffing monitor: poll() compares the current bus state with the
/// previous one and reports appear/disappear events (with logging, like
/// _usblog).
#[derive(Debug, Default)]
pub struct DeviceMonitor {
    last: Vec<DeviceMode>,
    started: bool,
}

impl DeviceMonitor {
    pub fn new() -> Self {
        Self::default()
    }

    /// One bus poll; events are logged and returned.
    pub fn poll(&mut self) -> Result<Vec<MonitorEvent>> {
        let cur = list_modes()?;
        let mut events = Vec::new();
        if !self.started {
            // whatever is present at start is not an event (as in v1)
            self.started = true;
        } else {
            for m in &cur {
                if !self.last.contains(m) {
                    log::info!("usb: appeared 2207:{:04x} ({})", m.pid(), m.label());
                    events.push(MonitorEvent::Appeared(m.clone()));
                }
            }
            for m in &self.last {
                if !cur.contains(m) {
                    log::info!("usb: gone 2207:{:04x} ({})", m.pid(), m.label());
                    events.push(MonitorEvent::Disappeared(m.clone()));
                }
            }
        }
        self.last = cur;
        Ok(events)
    }

    /// Current modes.
    pub fn modes(&self) -> &[DeviceMode] {
        &self.last
    }
}

/// Wait for a download mode (loader 330d / usbplug / MaskROM 330e) with
/// debounce: a short blink (the dead 0006 gadget or contact bounce) does
/// not count. Without a timeout — forever. Prints the hint once.
pub fn wait_download_mode(timeout: Option<Duration>, hint: &str) -> Result<DeviceMode> {
    let start = Instant::now();
    let mut monitor = DeviceMonitor::new();
    let mut hint_shown = false;
    loop {
        monitor.poll()?;
        if let Some(mode) = DeviceMode::best(monitor.modes()) {
            if matches!(
                mode,
                DeviceMode::Loader | DeviceMode::UsbPlug | DeviceMode::MaskRom
            ) {
                // the window can be short: make sure it persists
                std::thread::sleep(DEBOUNCE);
                let now = crate::transport::current_mode()?;
                if matches!(
                    now,
                    Some(DeviceMode::Loader | DeviceMode::UsbPlug | DeviceMode::MaskRom)
                ) {
                    let label = now.as_ref().map(|m| m.label()).unwrap_or_default();
                    log::info!("download mode stable: {label}");
                    return Ok(now.unwrap());
                }
                log::warn!("download mode window closed within {DEBOUNCE:?} — try again");
            }
        }
        if let Some(t) = timeout {
            if start.elapsed() >= t {
                return Err(crate::error::Error::DeviceNotFound);
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

/// Wait for a specific mode (e.g. UsbPlug after a download); plain poll.
pub fn wait_mode(mode: DeviceMode, timeout: Duration) -> Result<()> {
    let start = Instant::now();
    loop {
        if list_modes()?.contains(&mode) {
            return Ok(());
        }
        if start.elapsed() >= timeout {
            return Err(crate::error::Error::DeviceNotFound);
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// Wait for the Linux gadget (2207:0006) to come up AND stay on the bus
/// for `stable` continuously. The stock boot shows a brief 0006 blink
/// (the gadget dies without adbd) — a blink does not count; the window
/// restarts. Success = the gadget is alive for `stable`, which means
/// adbd is serving.
pub fn wait_gadget_stable(stable: Duration, timeout: Option<Duration>) -> Result<()> {
    let start = Instant::now();
    let mut seen_since: Option<Instant> = None;
    loop {
        let present = list_modes()?.contains(&DeviceMode::LinuxGadget);
        match (present, seen_since) {
            (true, Some(t0)) if t0.elapsed() >= stable => {
                log::info!("gadget 0006 stable for {:?}", t0.elapsed());
                return Ok(());
            }
            (true, Some(_)) => {} // still inside the stability window
            (true, None) => {
                log::info!("usb: appeared 2207:0006 (Linux gadget)");
                seen_since = Some(Instant::now());
            }
            (false, Some(t0)) => {
                // a blink: the stock gadget without adbd dies in ~1 s
                log::warn!(
                    "usb: 2207:0006 gone after {:?} (stock blink?) — waiting again",
                    t0.elapsed()
                );
                seen_since = None;
            }
            (false, None) => {}
        }
        if let Some(t) = timeout {
            if start.elapsed() >= t {
                return Err(crate::error::Error::DeviceNotFound);
            }
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}
