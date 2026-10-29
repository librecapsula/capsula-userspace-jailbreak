//! Rockchip loader container (RKBOOT) parser: the `loader.bin` extracted
//! from OTA packages and `rk*_loader.bin` from rkbin. Port of loader.c
//! from xrock.
//!
//! Layout: a 102-byte header (tag "BOOT" or "LDR "), then 57-byte
//! entries (code471/code472/loader), data at each entry's offset/size,
//! and a trailing u32 LE CRC32 (the nonstandard MSB-first one) over the
//! whole buffer up to the CRC.
//!
//! `download` only uses the Code471/Code472 entries; loader entries
//! (FlashData/FlashBoot/...) exist for idblock flashing and are parsed
//! but not used here.

use crate::error::{Error, Result};
use crate::util::crc32_xrock;

const TAG_BOOT: u32 = 0x544F_4F42; // "BOOT" little-endian
const TAG_LDR: u32 = 0x2052_444C; // "LDR " little-endian

pub const ENTRY_TYPE_471: u32 = 1 << 0;
pub const ENTRY_TYPE_472: u32 = 1 << 1;
pub const ENTRY_TYPE_LOADER: u32 = 1 << 2;

const HEADER_SIZE: usize = 102;
const ENTRY_SIZE: usize = 57;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// DDR init / TPL (uploaded with stage code 0x471).
    Code471,
    /// usbplug (uploaded with stage code 0x472).
    Code472,
    /// Flash loader components (FlashData/FlashBoot/...).
    Loader,
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub kind: EntryKind,
    /// Entry name (wide string -> utf8; e.g. "UsbData", "FlashBoot").
    pub name: String,
    pub data_offset: u32,
    pub data_size: u32,
    /// Delay after uploading this entry, ms (used by download).
    pub data_delay: u32,
}

#[derive(Debug, Clone)]
pub struct LoaderContainer {
    pub data: Vec<u8>,
    pub is_newidb: bool,
    /// RC4 enabled for MaskROM upload (xrock semantics: rc4_flag == 0
    /// -> encrypt; verified on the loader.bin from OTA 44.90).
    pub is_rc4on: bool,
    pub is_signed: bool,
    pub chiptype: u32,
    pub version: u32,
    pub entries: Vec<Entry>,
}

fn u32le(d: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([d[off], d[off + 1], d[off + 2], d[off + 3]])
}

/// Wide-char entry name (every second byte, up to a non-printable one),
/// as loader_wide2str in xrock.
fn wide2str(raw: &[u8]) -> String {
    let mut s = String::new();
    let (pairs, _) = raw.as_chunks::<2>();
    for &[c, _] in pairs {
        if !(0x20..=0x7e).contains(&c) || c == 0 {
            break;
        }
        s.push(c as char);
    }
    s
}

impl LoaderContainer {
    pub fn parse(data: Vec<u8>) -> Result<Self> {
        if data.len() <= HEADER_SIZE {
            return Err(Error::Loader("file shorter than the header".into()));
        }
        let tag = u32le(&data, 0);
        if tag != TAG_BOOT && tag != TAG_LDR {
            return Err(Error::Loader(format!(
                "not a BOOT/LDR container (tag={tag:#x})"
            )));
        }
        let is_newidb = tag == TAG_LDR;

        let rc4_flag = data[44];
        // xrock: rc4_flag != 0 -> RC4 off
        let is_rc4on = rc4_flag == 0;
        let is_signed = data[43] == b'S';

        let version = u32le(&data, 6);
        let chiptype = u32le(&data, 21);
        let n471 = data[25] as usize;
        let n472 = data[31] as usize;
        let nloader = data[37] as usize;
        let nentry = n471 + n472 + nloader;
        if nentry == 0 || nentry > 32 {
            return Err(Error::Loader(format!("implausible entry count: {nentry}")));
        }

        let mut entries = Vec::with_capacity(nentry);
        for i in 0..nentry {
            let e = HEADER_SIZE + ENTRY_SIZE * i;
            if e + ENTRY_SIZE > data.len() {
                return Err(Error::Loader("entry beyond the end of file".into()));
            }
            let type_ = u32le(&data, e + 1);
            let kind = match type_ {
                ENTRY_TYPE_471 => EntryKind::Code471,
                ENTRY_TYPE_472 => EntryKind::Code472,
                ENTRY_TYPE_LOADER => EntryKind::Loader,
                other => {
                    return Err(Error::Loader(format!("unknown entry type {other:#x}")));
                }
            };
            let data_offset = u32le(&data, e + 45);
            let data_size = u32le(&data, e + 49);
            // Bounds must hold for EVERY entry: a mid-table entry pointing
            // past EOF would otherwise panic in download_stages' slicing
            // (the final length check below only covers the last entry).
            if data_offset as u64 + data_size as u64 > data.len() as u64 {
                return Err(Error::Loader(format!(
                    "entry {i} data ({data_offset}..{}) lies beyond the end of file ({})",
                    data_offset + data_size,
                    data.len()
                )));
            }
            entries.push(Entry {
                kind,
                name: wide2str(&data[e + 5..e + 45]),
                data_offset,
                data_size,
                data_delay: u32le(&data, e + 53),
            });
        }

        // Length check: last.offset + last.size + 4 (CRC) is the minimum;
        // extra trailing bytes are dropped (a BOOT container embedded in
        // an RKFW package).
        let last = entries.last().unwrap();
        let len = last.data_offset as usize + last.data_size as usize;
        if data.len() < len + 4 {
            return Err(Error::Loader(format!(
                "file size {} is below the table ({})",
                data.len(),
                len + 4
            )));
        }
        // CRC32 (the nonstandard one, init 0) over the buffer up to the CRC
        let expect = u32le(&data, len);
        let got = crc32_xrock(0, &data[..len]);
        if got != expect {
            return Err(Error::Loader(format!(
                "CRC32 mismatch: file says {expect:#010x}, computed {got:#010x}"
            )));
        }

        Ok(LoaderContainer {
            data,
            is_newidb,
            is_rc4on,
            is_signed,
            chiptype,
            version,
            entries,
        })
    }

    pub fn parse_file(path: &std::path::Path) -> Result<Self> {
        let data = std::fs::read(path).map_err(Error::Io)?;
        Self::parse(data)
    }

    /// Stages for the MaskROM `download`, in entry order:
    /// (stage code 0x471/0x472, name, data, delay_after_ms). Loader
    /// entries are skipped (as in main.c of xrock).
    pub fn download_stages(&self) -> Vec<(u16, &str, &[u8], u32)> {
        self.entries
            .iter()
            .filter(|e| e.kind != EntryKind::Loader)
            .map(|e| {
                let code = match e.kind {
                    EntryKind::Code471 => 0x471,
                    EntryKind::Code472 => 0x472,
                    EntryKind::Loader => unreachable!(),
                };
                let off = e.data_offset as usize;
                (
                    code,
                    e.name.as_str(),
                    &self.data[off..off + e.data_size as usize],
                    e.data_delay,
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_garbage() {
        assert!(LoaderContainer::parse(vec![0u8; 64]).is_err());
        let mut buf = vec![0u8; HEADER_SIZE + 4];
        buf[0..4].copy_from_slice(&TAG_BOOT.to_le_bytes());
        // nentry == 0
        assert!(LoaderContainer::parse(buf).is_err());
    }

    /// Synthetic container: 2x471 + 472 + a loader entry. No real
    /// firmware binaries live in the repository.
    fn synth_container() -> LoaderContainer {
        const N471: usize = 2;
        const N472: usize = 1;
        const NLOADER: usize = 1;
        const NENTRY: usize = N471 + N472 + NLOADER;
        const DATA_OFF: usize = HEADER_SIZE + NENTRY * ENTRY_SIZE;

        let mut boot = vec![0u8; HEADER_SIZE];
        boot[0..4].copy_from_slice(&TAG_BOOT.to_le_bytes());
        boot[4..6].copy_from_slice(&(HEADER_SIZE as u16).to_le_bytes());
        boot[43] = b'S'; // signed
        boot[44] = 1; // rc4_flag != 0 -> RC4 disabled
        boot[21..25].copy_from_slice(b"8033"); // rk3308
        boot[25] = N471 as u8;
        boot[31] = N472 as u8;
        boot[37] = NLOADER as u8;

        // (kind, name, size, fill) in order; the data follows the table
        let layout: [(u32, &str, usize, u8); NENTRY] = [
            (ENTRY_TYPE_471, "DDRa", 8, 0x11),
            (ENTRY_TYPE_471, "DDRb", 4, 0x22),
            (ENTRY_TYPE_472, "UsbData", 16, 0x33),
            (ENTRY_TYPE_LOADER, "FlashBoot", 32, 0x44),
        ];
        let mut entries = Vec::new();
        for (i, &(kind, name, size, _fill)) in layout.iter().enumerate() {
            let mut e = vec![0u8; ENTRY_SIZE];
            e[1..5].copy_from_slice(&kind.to_le_bytes());
            for (j, ch) in name.encode_utf16().enumerate() {
                e[5 + j * 2..7 + j * 2].copy_from_slice(&ch.to_le_bytes());
            }
            let mut off = DATA_OFF;
            for &(_, _, prev, _) in &layout[..i] {
                off += prev;
            }
            e[45..49].copy_from_slice(&(off as u32).to_le_bytes());
            e[49..53].copy_from_slice(&(size as u32).to_le_bytes());
            e[53..57].copy_from_slice(&1u32.to_le_bytes()); // delay 1ms
            entries.extend_from_slice(&e);
        }

        let mut data = boot;
        data.extend_from_slice(&entries);
        data.resize(DATA_OFF + layout.iter().map(|l| l.2).sum::<usize>(), 0);
        let mut off = DATA_OFF;
        for &(_kind, _name, size, fill) in &layout {
            data[off..off + size].fill(fill);
            off += size;
        }
        let crc = crc32_xrock(0, &data);
        data.extend_from_slice(&crc.to_le_bytes());
        LoaderContainer::parse(data).unwrap()
    }

    #[test]
    fn entry_data_beyond_eof_rejected() {
        // The LAST entry stays well-formed (the CRC path checks out),
        // but the FIRST one points far past EOF: parse must refuse
        // instead of panicking later in download_stages' slicing.
        let c = synth_container();
        let mut raw = c.data.clone();
        raw[HEADER_SIZE + 45..HEADER_SIZE + 49].copy_from_slice(&0x7fff_0000u32.to_le_bytes());
        // re-sign: the CRC covers everything up to the last entry's end
        let last = c.entries.last().unwrap();
        let len = last.data_offset as usize + last.data_size as usize;
        let crc = crc32_xrock(0, &raw[..len]);
        raw[len..len + 4].copy_from_slice(&crc.to_le_bytes());
        let err = LoaderContainer::parse(raw).expect_err("must reject");
        assert!(err.to_string().contains("beyond"), "{err}");
    }

    #[test]
    fn synthetic_container_parses_with_stages() {
        let c = synth_container();
        assert_eq!(c.entries.len(), 4);
        assert!(c.is_signed);
        assert!(!c.is_rc4on, "rc4_flag=1 -> RC4 disabled");
        assert_eq!(c.chiptype.to_le_bytes(), *b"8033");

        // download_stages: 471/472 in order only, loader entries skipped
        let stages = c.download_stages();
        assert_eq!(stages.len(), 3);
        assert_eq!(stages[0].0, 0x471);
        assert_eq!(stages[0].1, "DDRa");
        assert_eq!(stages[0].2, &[0x11; 8]);
        assert_eq!(stages[1].0, 0x471);
        assert_eq!(stages[2].0, 0x472);
        assert_eq!(stages[2].2, &[0x33; 16]);
        assert_eq!(stages.iter().map(|(_, _, d, _)| d.len()).sum::<usize>(), 28);
    }
}
