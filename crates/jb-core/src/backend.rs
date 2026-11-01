//! The platform contract. main (jb-cli) picks a backend by the USB
//! device that appears on the bus (platforms differ by VID:PID) and
//! the whole scenario then runs through it. A new platform = a new
//! `jb-<name>` crate implementing this trait (and the scenario's
//! `Platform` hooks on the same type) plus one line in the CLI's
//! `backends()`.

use crate::progress::ProgressFn;
use crate::scenario::{Confirm, Params};
use std::time::Duration;

/// One supported SoC/platform.
pub trait Backend {
    /// Short platform name (for the dispatch log line).
    fn name(&self) -> &'static str;

    /// Is a device of this platform on the bus right now. main uses
    /// this to pick the backend; the bus enumeration is the platform's
    /// business.
    fn present(&self) -> anyhow::Result<bool>;

    /// The hint printed while the bus is empty (how to enter the
    /// download mode), if the platform has one.
    fn wait_hint(&self) -> Option<&str> {
        None
    }

    /// The full scenario: prepare (session + backup) → measure →
    /// confirm → build the data image → write → finish. `confirm` is
    /// called before anything is written; an error aborts safely.
    fn jailbreak(
        &mut self,
        params: &Params,
        confirm: Confirm,
        progress: ProgressFn,
    ) -> anyhow::Result<()>;

    /// Capture only: nothing is written to the column.
    fn backup(&mut self, wait: Option<Duration>, progress: ProgressFn) -> anyhow::Result<()>;

    /// Restore the verified capture of the data partition back to the
    /// device (the inverse of the jailbreak's write step). Requires a
    /// complete capture; --no-backup is rejected by the CLI here.
    fn restore(
        &mut self,
        wait: Option<Duration>,
        confirm: Confirm,
        progress: ProgressFn,
    ) -> anyhow::Result<()>;
}
