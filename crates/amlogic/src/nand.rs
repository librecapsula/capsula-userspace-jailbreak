//! Fixed A113X NAND geometry and read-only staging operations.

use crate::{AmlogicSession, Error, Result, RAM_SCRATCH};
use usbcore::Transport;

pub const NAND_SIZE: u32 = 0x1000_0000;
pub const PAGE_SIZE: u32 = 2048;
pub const OOB_SIZE: u32 = 64;
pub const CHUNK_SIZE: u32 = 0x80_0000;

pub const RESERVED: &[(&str, u32, u32)] = &[
    ("bbt", 0x28_0000, 0x8_0000),
    ("env", 0x30_0000, 0x10_0000),
    ("keys", 0x40_0000, 0x10_0000),
    ("dtbrsv", 0x50_0000, 0x8_0000),
    ("ddr", 0x58_0000, 0x4_0000),
];

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

    pub fn read_nand_chunk(&mut self, offset: u32, main_bytes: u32) -> Result<Vec<u8>> {
        self.stage_nand(offset, main_bytes, false)
    }

    pub fn read_raw_nand_chunk(&mut self, offset: u32, main_bytes: u32) -> Result<Vec<u8>> {
        self.stage_nand(offset, main_bytes, true)
    }

    pub fn read_nand_buffer(&mut self, bytes: usize) -> Result<Vec<u8>> {
        let max = raw_bytes(CHUNK_SIZE)?;
        if bytes == 0 || bytes > max || RAM_SCRATCH as u64 + bytes as u64 > 0x0190_0000 {
            return Err(Error::InvalidArgument(
                "read outside NAND staging buffer".into(),
            ));
        }
        self.bulk_cmd(&format!("upload mem {RAM_SCRATCH:#x} normal {bytes:#x}"))?;
        let data = self.receive_upload(bytes, &|| false, &|_| {})?;
        if data.len() != bytes {
            return Err(Error::InvalidResponse(format!(
                "short NAND buffer: {} of {bytes} bytes",
                data.len()
            )));
        }
        Ok(data)
    }

    fn stage_nand(&mut self, offset: u32, main_bytes: u32, raw: bool) -> Result<Vec<u8>> {
        if main_bytes == 0
            || main_bytes > CHUNK_SIZE
            || offset as u64 + main_bytes as u64 > NAND_SIZE as u64
        {
            return Err(Error::InvalidArgument(
                "NAND read outside A113X geometry".into(),
            ));
        }
        let (operation, count, bytes) = if raw {
            if !offset.is_multiple_of(PAGE_SIZE) {
                return Err(Error::InvalidArgument("unaligned raw NAND offset".into()));
            }
            ("read.raw", main_bytes / PAGE_SIZE, raw_bytes(main_bytes)?)
        } else {
            ("read", main_bytes, main_bytes as usize)
        };
        self.bulk_cmd(&format!("echo; mw.b {RAM_SCRATCH:#x} 0xa5 {bytes:#x}"))?;
        self.bulk_cmd(&format!(
            "echo; nand {operation} {RAM_SCRATCH:#x} {offset:#x} {count:#x}"
        ))?;
        let data = self.read_nand_buffer(bytes)?;
        if data.iter().all(|&byte| byte == 0xa5) {
            return Err(Error::InvalidResponse(
                "NAND did not replace the staging buffer".into(),
            ));
        }
        Ok(data)
    }
}
