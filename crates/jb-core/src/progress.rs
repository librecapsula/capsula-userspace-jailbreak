//! Progress events for the CLI/GUI. The domain emits them; the UI
//! renders them (jb-cli renders step lines through the unified logger
//! and partitions/transfers as indicatif bars).

/// Progress events for CLI/GUI.
#[derive(Debug, Clone)]
pub enum Progress {
    /// A human-readable progress line.
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
    /// A byte-oriented transfer (amlogic streams: partition capture,
    /// full NAND dump, partition write) — the same shape as the
    /// Partition* events, in bytes instead of sectors.
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
}

pub type ProgressFn<'a> = &'a dyn Fn(Progress);
