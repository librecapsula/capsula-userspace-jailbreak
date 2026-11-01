//! Platform dispatch. main — the entry point: argument parsing and
//! backend selection by the USB device that appears on the bus; the
//! whole scenario then runs through the `jb_core::backend::Backend`
//! contract implemented by the platform crates (jb-rockchip,
//! jb-amlogic). A future platform = a new crate implementing the
//! contract + a line in `backends()`.

use jb_core::backend::Backend;
use anyhow::bail;
use std::time::{Duration, Instant};

/// Every known platform in poll order. A future platform is added
/// here: recognized by its own USB device (`present`), the scenario
/// runs through the same contract.
pub(crate) fn backends() -> Vec<Box<dyn Backend>> {
    vec![
        Box::new(jb_rockchip::platform::Rockchip::new()),
        Box::new(jb_amlogic::platform::Amlogic::new()),
    ]
}

/// Pick a backend by the USB device on the bus: wait until a device of
/// any known platform appears and return its backend. While the bus is
/// empty, print the platform hints (how to enter the download mode).
pub(crate) fn pick_backend(wait: Option<Duration>) -> anyhow::Result<Box<dyn Backend>> {
    let start = Instant::now();
    let mut candidates = backends();
    let mut hint_shown = false;
    loop {
        let mut chosen: Option<usize> = None;
        for (i, b) in candidates.iter().enumerate() {
            if b.present()? {
                chosen = Some(i);
                break;
            }
        }
        if let Some(i) = chosen {
            let b = candidates.swap_remove(i);
            log::info!("платформа: {}", b.name());
            return Ok(b);
        }
        if !hint_shown {
            for b in &candidates {
                if let Some(h) = b.wait_hint() {
                    log::info!("{h}");
                }
            }
            hint_shown = true;
        }
        if let Some(t) = wait {
            if start.elapsed() >= t {
                bail!("ни одна поддерживаемая платформа не появилась на шине (--wait)");
            }
        }
        std::thread::sleep(rockusb::monitor::POLL_INTERVAL);
    }
}
