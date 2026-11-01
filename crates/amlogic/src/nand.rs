//! A113X NAND geometry and the streaming read path (the only one).

use crate::transport::Transport;
use crate::{AmlogicSession, Error, Result, RAM_SCRATCH};
use std::io::Write;

pub const NAND_SIZE: u32 = 0x1000_0000;
pub const PAGE_SIZE: u32 = 2048;
pub const OOB_SIZE: u32 = 64;
/// AML reserved areas between the bootloader and tpl (device-unique;
/// never reflashed from a dump).
pub const RESERVED: &[(&str, u32, u32)] = &[
    ("bbt", 0x28_0000, 0x8_0000),
    ("env", 0x30_0000, 0x10_0000),
    ("keys", 0x40_0000, 0x10_0000),
    ("dtbrsv", 0x50_0000, 0x8_0000),
    ("ddr", 0x58_0000, 0x4_0000),
];

/// Stage size of the streaming read, in MAIN-area bytes: one
/// `nand read <ram> <off> <n>` moves this much NAND->DRAM, then ONE
/// `upload mem` arm streams the stage to the host in device-paced
/// bursts (flasher.sh `read_big_from_flash` mechanics with the
/// vendor's 8 MiB chunk). Proven live: 20 × 8 MiB stages in one
/// burning session (~11.7 MB/s) with an identify keepalive per stage.
pub const READ_STAGE_MAIN: usize = 0x80_0000;
/// Raw stages (page+OOB) stay at 4 MiB main so the staging buffer with
/// OOB (4.13 MiB) stays inside the proven DRAM window at RAM_SCRATCH.
pub const RAW_STAGE_MAIN: usize = 0x40_0000;

/// Logical bytes -> bytes with OOB appended per page.
pub fn raw_bytes(main_bytes: u32) -> Result<usize> {
    if main_bytes == 0 || main_bytes > NAND_SIZE || !main_bytes.is_multiple_of(PAGE_SIZE) {
        return Err(Error::InvalidArgument("invalid NAND page range".into()));
    }
    Ok((main_bytes / PAGE_SIZE) as usize * (PAGE_SIZE + OOB_SIZE) as usize)
}

impl<T: Transport> AmlogicSession<T> {
    /// Logical store capacity excludes bad erase blocks. Only known partitions
    /// are accepted, and the reported capacity cannot exceed their physical map.
    pub fn partition_readable_size(&mut self, name: &str) -> Result<usize> {
        let (_, _, physical) = crate::partition(name)
            .ok_or_else(|| Error::InvalidArgument(format!("unknown partition {name:?}")))?;
        self.bulk_cmd(&format!("echo; mw.b {RAM_SCRATCH:#x} 0xa5 0x8"))?;
        self.bulk_cmd(&format!("echo; store size {name} {RAM_SCRATCH:#x}"))?;
        let bytes = self.upload_read(RAM_SCRATCH, 8)?;
        let size = u64::from_le_bytes(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| Error::InvalidResponse("short store size result".into()))?,
        );
        if size == 0 || size > physical as u64 || !size.is_multiple_of(PAGE_SIZE as u64) {
            return Err(Error::InvalidResponse(format!(
                "partition {name}: invalid logical size {size:#x} for physical {physical:#x}"
            )));
        }
        Ok(size as usize)
    }

    /// `nand erase <off> <len>` — erasing a range of the logical
    /// address space. Idempotent: an interrupted window simply repeats
    /// the command in the next one. Bounds are page multiples.
    pub fn nand_erase(&mut self, offset: u32, len: u32) -> Result<()> {
        if len == 0
            || !offset.is_multiple_of(PAGE_SIZE)
            || !len.is_multiple_of(PAGE_SIZE)
            || offset as u64 + len as u64 > NAND_SIZE as u64
        {
            return Err(Error::InvalidArgument(
                "NAND erase outside A113X geometry".into(),
            ));
        }
        self.bulk_cmd(&format!("echo; nand erase {offset:#x} {len:#x}"))
            .map(|_| ())
    }

    /// Stream a NAND range to `out` — the one read path of this crate.
    ///
    /// Mechanics per stage (flasher.sh `read_big_from_flash`):
    /// identify keepalive, `mw.b` sentinel, one blocking `nand read`
    /// (the status read absorbs the whole staging silence), one
    /// `upload mem` arm, device-paced bursts written straight to `out`
    /// — a session death keeps every completed stage on disk.
    ///
    /// `len` is in MAIN-area bytes; with `raw` the stream carries
    /// page+OOB (`raw_bytes(len)` total) and the offset is physical.
    /// Returns the number of bytes written to `out`. A `failed:` from
    /// the device with a changed staging buffer (bad block past the
    /// good prefix) still uploads and keeps the received bytes without
    /// guessing validity from contents; a completely unchanged sentinel
    /// stops the stream early (a partial result — an entirely empty
    /// prefix is an error). Transport errors propagate after the
    /// received prefix is written.
    pub fn read_nand_range(
        &mut self,
        off: u32,
        len: u32,
        raw: bool,
        out: &mut dyn Write,
        progress: &dyn Fn(usize),
    ) -> Result<usize> {
        if len == 0 || off as u64 + len as u64 > NAND_SIZE as u64 {
            return Err(Error::InvalidArgument(
                "NAND read outside A113X geometry".into(),
            ));
        }
        if raw && (!off.is_multiple_of(PAGE_SIZE) || !len.is_multiple_of(PAGE_SIZE)) {
            return Err(Error::InvalidArgument("unaligned raw NAND range".into()));
        }
        let stage_main = if raw { RAW_STAGE_MAIN } else { READ_STAGE_MAIN } as u32;
        let mut main_done = 0u32;
        let mut written = 0usize;
        while main_done < len {
            let mut main = (len - main_done).min(stage_main);
            if raw {
                main -= main % PAGE_SIZE;
            }
            let file_len = if raw { raw_bytes(main)? } else { main as usize };

            // Keepalive: the burning session dies on ~300–450 ms of
            // device-side idle; the vendor tool identifies before every
            // operation, and the nand read below leaves the USB stack
            // untouched for tens of ms.
            self.identify()?;
            self.bulk_cmd(&format!("echo; mw.b {RAM_SCRATCH:#x} 0xa5 {file_len:#x}"))?;
            let (operation, count) = if raw {
                ("read.raw", main / PAGE_SIZE)
            } else {
                ("read", main)
            };
            let read_failure = match self.bulk_cmd(&format!(
                "echo; nand {operation} {RAM_SCRATCH:#x} {:#x} {count:#x}",
                off + main_done
            )) {
                Ok(_) => None,
                // a bad-block `failed:` does not prove the buffer is
                // empty: the live gadget fills the whole range and still
                // answers `failed:` when it skipped a bad block
                Err(e @ Error::CommandFailed(_)) => Some(e),
                // anything else is the session dying
                Err(other) => return Err(other),
            };
            self.send_bulk_cmd(&format!("upload mem {RAM_SCRATCH:#x} normal {file_len:#x}"))?;
            self.wait_bulk_status()?;
            let mut stage_buf = Vec::with_capacity(file_len);
            let staged = match self.upload_stream(file_len, &mut stage_buf) {
                Ok(n) => n,
                // a dead session still delivered a prefix into the stage
                // buffer — flush it so the caller's checkpoint keeps it
                Err(e) => {
                    if !stage_buf.is_empty() {
                        out.write_all(&stage_buf)?;
                    }
                    return Err(e);
                }
            };
            let unchanged = staged > 0 && stage_buf.iter().all(|&b| b == 0xa5);

            // An all-0xa5 stage is ambiguous: real NAND data or the
            // untouched sentinel. Never infer a length from contents.
            if let Some(error) = read_failure {
                if unchanged {
                    // the read did not happen at all; keep the prefix
                    if written == 0 {
                        return Err(error);
                    }
                    log::warn!(
                        "nand {operation} rejected at {:#x} (+{main_done:#x} of {len:#x}): \
                         {error} — keeping the prefix",
                        off + main_done
                    );
                    return Ok(written);
                }
                log::warn!(
                    "nand {operation} at {:#x} reported {error}; preserving all {staged:#x} \
                     uploaded bytes without trimming; NAND completeness is uncertain",
                    off + main_done
                );
            }
            if unchanged && staged == file_len {
                return Err(Error::InvalidResponse(format!(
                    "nand {operation} {:#x}: the staging buffer still holds the sentinel — \
                     the read did not happen",
                    off + main_done
                )));
            }
            out.write_all(&stage_buf)?;
            written += staged;
            main_done += main;
            progress(written);
            if staged < file_len {
                // short stream (ZLP) mid-stage — keep the prefix
                log::warn!(
                    "upload stream ended at {staged:#x} of {file_len:#x} bytes at {:#x}; \
                     keeping the prefix",
                    off + main_done
                );
                return Ok(written);
            }
        }
        Ok(written)
    }
}
