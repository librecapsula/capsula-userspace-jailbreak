//! High-level read-only Amlogic operations for the Capsula Mini (A113X).

pub mod backup;

use crate::session::{Progress, ProgressFn};
use amlogic::AmlogicSession;
use std::io::Write as _;
use std::path::Path;

/// Capture the raw text-export buffer of the u-boot environment.
/// Bulkcmd answers go to the serial console, so the
/// env is exported into DRAM and the DRAM is read back over USB
/// (flasher.sh `capture_env`). The buffer is zeroed first, or the tail
/// would carry the 0x55 wall of the BL2 memory test.
pub fn capture_env_raw<T: usbcore::Transport>(
    s: &mut AmlogicSession<T>,
) -> anyhow::Result<Vec<u8>> {
    s.bulk_cmd(&format!(
        "echo; mw.b {:#x} 0 {:#x}",
        amlogic::ENV_ADDR,
        amlogic::ENV_SIZE
    ))
    .map_err(|e| anyhow::anyhow!("mw.b: {e}"))?;
    s.bulk_cmd(&format!("echo; env export -t {:#x}", amlogic::ENV_ADDR))
        .map_err(|e| anyhow::anyhow!("env export: {e}"))?;
    let buf = s
        .read_dram(amlogic::ENV_ADDR, amlogic::ENV_SIZE, &|_| {})
        .map_err(|e| anyhow::anyhow!("read env from DRAM: {e}"))?;
    Ok(buf)
}

/// Decode the environment snapshot as text.
pub fn capture_env<T: usbcore::Transport>(s: &mut AmlogicSession<T>) -> anyhow::Result<String> {
    let buf = capture_env_raw(s)?;
    let end = buf
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| anyhow::anyhow!("env text is not NUL-terminated"))?;
    Ok(String::from_utf8_lossy(&buf[..end])
        .trim_matches('\u{55}')
        .trim_end()
        .to_string())
}

/// Incremental partition dump state: survives session reconnects (the
/// dump loop re-enters the download window via `reboot update` and
/// continues from the checkpoint).
pub struct DumpState {
    pub part: String,
    pub off: u32,
    pub size: usize,
    pub data: Vec<u8>,
    /// Set when the range reader returns fewer bytes than requested.
    /// A `failed:` status with a changed staging buffer does not imply a
    /// known shorter length: all uploaded bytes are preserved and the
    /// uncertain NAND completeness is logged by the range reader.
    pub short_read: bool,
}

impl DumpState {
    pub fn new(part: &str) -> anyhow::Result<DumpState> {
        let (_, off, size) = amlogic::partition(part).ok_or_else(|| {
            anyhow::anyhow!("unknown partition {part:?}; known: {}", known_parts())
        })?;
        Ok(DumpState {
            part: part.into(),
            off,
            size: size as usize,
            data: Vec::with_capacity(size as usize),
            short_read: false,
        })
    }

    pub fn done(&self) -> usize {
        self.data.len()
    }
}

/// Dump the next `max_bytes` of the partition through the live session.
/// Returns the number of bytes added; on a transport error the caller
/// reconnects (`reboot update`) and calls again.
pub fn dump_chunk<T: usbcore::Transport>(
    s: &mut AmlogicSession<T>,
    st: &mut DumpState,
    max_bytes: usize,
    progress: ProgressFn,
) -> anyhow::Result<usize> {
    dump_chunk_until(s, st, max_bytes, progress, &|| false)
}

/// [`dump_chunk`] with a cooperative stop (see
/// [`amlogic::AmlogicSession::read_nand_range_until`]): the partial
/// sub-range is kept in the state, and Ok(0) means "stopped, nothing
/// new" — the caller re-enters the window and continues.
pub fn dump_chunk_until<T: usbcore::Transport>(
    s: &mut AmlogicSession<T>,
    st: &mut DumpState,
    max_bytes: usize,
    progress: ProgressFn,
    stop: &dyn Fn() -> bool,
) -> anyhow::Result<usize> {
    let remaining = st.size - st.done();
    if remaining == 0 || st.short_read {
        return Ok(0);
    }
    let want = remaining.min(max_bytes);
    let base_done = st.done() as u64;
    let total = st.size as u64;
    let part = st.part.clone();
    match s.read_nand_range_until(
        st.off + st.done() as u32,
        want,
        &|d| {
            progress(Progress::PartitionProgress {
                name: part.clone(),
                done: base_done + d as u64,
                total,
            });
        },
        stop,
    ) {
        Ok(chunk) => {
            // a short chunk is a bad block ONLY when the range reader
            // ran to completion; the cooperative stop also returns a
            // partial chunk, and that is just the cycle boundary
            let short = chunk.len() < want && !stop();
            st.short_read = short;
            st.data.extend_from_slice(&chunk);
            Ok(chunk.len())
        }
        Err(e) => {
            // a bad-block read failure after a good prefix returns the
            // prefix; an empty prefix is a real error (caller retries)
            Err(anyhow::anyhow!("read {:#x}+{:#x}: {e}", st.off, st.done()))
        }
    }
}

/// Re-enter the download mode: re-initialize the whole gadget with the
/// `try_auto_burn` env script (fresh buffer manager and USB stack; the
/// u-boot `update` command runs nested — its reply is lost as the
/// gadget tears the pipes down), then a USB port reset to force the
/// re-enumeration. A bare reset re-attaches a WEDGED gadget for only
/// ~30 ms (verified on hardware) — the re-init is what actually
/// revives it.
pub fn reenter_download_window(s: &mut AmlogicSession<rockusb::NusbTransport>) {
    let _ = s.bulk_cmd("run try_auto_burn");
    // give the gadget a moment to tear down and re-init its stack
    std::thread::sleep(std::time::Duration::from_millis(300));
    let _ = s.reset();
}

/// Dump a vendor partition by name into `dir/<part>.bin`, through the
/// raw NAND offsets (nand read -> DRAM -> upload mem; flasher.sh
/// `read_big_from_flash`). A short read (bad blocks) is kept, matching
/// the flasher: the received length is the truth. Returns the number of
/// bytes written.
pub fn dump_partition<T: usbcore::Transport>(
    s: &mut AmlogicSession<T>,
    part: &str,
    dir: &Path,
    progress: ProgressFn,
) -> anyhow::Result<u64> {
    let (_, off, size) = amlogic::partition(part)
        .ok_or_else(|| anyhow::anyhow!("unknown partition {part:?}; known: {}", known_parts()))?;
    progress(Progress::PartitionStart {
        name: part.into(),
        sectors: size as u64 / 512,
    });
    let data = s
        .read_nand_range(off, size as usize, &|done| {
            progress(Progress::PartitionProgress {
                name: part.into(),
                done: done as u64,
                total: size as u64,
            });
        })
        .map_err(|e| anyhow::anyhow!("dump {part} at {off:#x}: {e}"))?;
    write_dump(dir, part, &data, progress)?;
    Ok(data.len() as u64)
}

/// Write the accumulated dump with its progress events.
pub fn write_dump(dir: &Path, part: &str, data: &[u8], progress: ProgressFn) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(format!("{part}.bin"));
    let mut f = std::fs::File::create(&path)?;
    f.write_all(data)?;
    progress(Progress::PartitionDone { name: part.into() });
    Ok(())
}

fn known_parts() -> String {
    amlogic::PARTITIONS
        .iter()
        .map(|(n, _, _)| *n)
        .collect::<Vec<_>>()
        .join(", ")
}
