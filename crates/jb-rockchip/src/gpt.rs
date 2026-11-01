//! GPT header and partition table parser (raw sectors from LBA1 plus
//! the entries that follow — as `flash read 0x1 0x21` returns them).
//! Validation follows LibreRD (CRC32 of header/entries, bounds,
//! overlaps); output is TSV-compatible with the legacy gpt_parts.py
//! (`idx\tname\tstart\tsectors`, idx from 1).

use crc32fast::Hasher;
use thiserror::Error;

pub const LBA_SIZE: usize = 512;

#[derive(Debug, Error)]
pub enum GptError {
    #[error("no EFI PART signature at LBA 1")]
    NoSignature,
    #[error("GPT header CRC32 mismatch (corrupted data?)")]
    BadHeaderCrc,
    #[error("GPT entries CRC32 mismatch")]
    BadEntriesCrc,
    #[error("data shorter than the header requires ({0} bytes needed)")]
    TooShort(usize),
    #[error("partition #{idx} \"{name}\": {reason}")]
    BadEntry {
        idx: usize,
        name: String,
        reason: String,
    },
    #[error("GPT: {0}")]
    Malformed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GptEntry {
    /// Partition number in the table (from 1, like /dev/rkflash0pN and
    /// the legacy TSV).
    pub idx: u32,
    pub name: String,
    pub first_lba: u64,
    pub last_lba: u64,
    /// last - first + 1.
    pub sectors: u64,
}

#[derive(Debug, Clone)]
pub struct Gpt {
    pub entries: Vec<GptEntry>,
    pub first_usable_lba: u64,
    pub last_usable_lba: u64,
    /// LBA just past the entry table.
    pub entries_end_lba: u64,
}

fn u32le(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]])
}
fn u64le(d: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(d[o..o + 8].try_into().unwrap())
}
fn crc32(data: &[u8]) -> u32 {
    let mut h = Hasher::new();
    h.update(data);
    h.finalize()
}

impl Gpt {
    /// Parse an "LBA1 + entries" buffer (usually 34 sectors = 17 KiB).
    pub fn parse(data: &[u8]) -> Result<Self, GptError> {
        if data.len() < LBA_SIZE {
            return Err(GptError::TooShort(LBA_SIZE));
        }
        if &data[0..8] != b"EFI PART" {
            return Err(GptError::NoSignature);
        }
        let header_size = u32le(data, 12) as usize;
        if !(92..=LBA_SIZE).contains(&header_size) {
            return Err(GptError::Malformed(format!(
                "header_size={header_size} out of range"
            )));
        }
        // header CRC: the CRC field is zeroed before computing
        let mut hdr = data[..header_size].to_vec();
        let stored_crc = u32le(&hdr, 16);
        hdr[16..20].fill(0);
        if crc32(&hdr) != stored_crc {
            return Err(GptError::BadHeaderCrc);
        }

        let first_usable = u64le(data, 40);
        let last_usable = u64le(data, 48);
        let entry_lba = u64le(data, 72);
        let num_entries = u32le(data, 80);
        let entry_size = u32le(data, 84);
        let entries_crc = u32le(data, 88);
        if entry_size < 128 || !entry_size.is_multiple_of(8) {
            return Err(GptError::Malformed(format!(
                "entry_size={entry_size} is invalid"
            )));
        }
        // The GPT comes raw from the device and may be garbage: every
        // field feeding slice arithmetic must be bounds-checked here,
        // never trusted (an entry_lba of 0 would underflow below).
        if entry_lba < 2 {
            return Err(GptError::Malformed(format!(
                "entry_lba={entry_lba} is invalid (entries must follow LBA1)"
            )));
        }
        let entries_off = (entry_lba - 1) * LBA_SIZE as u64;
        let need = entries_off + num_entries as u64 * entry_size as u64;
        if (data.len() as u64) < need {
            return Err(GptError::TooShort(need as usize));
        }
        let entries_blob = &data[entries_off as usize..need as usize];
        if crc32(entries_blob) != entries_crc {
            return Err(GptError::BadEntriesCrc);
        }

        let mut entries = Vec::new();
        for (i, e) in entries_blob.chunks_exact(entry_size as usize).enumerate() {
            if e[..16].iter().all(|&b| b == 0) {
                continue; // empty entry (type GUID = 0)
            }
            let first = u64le(e, 32);
            let last = u64le(e, 40);
            let name_raw: Vec<u16> = e[56..128]
                .as_chunks::<2>()
                .0
                .iter()
                .take_while(|c| **c != [0, 0])
                .map(|c| u16::from_le_bytes(*c))
                .collect();
            let name = match String::from_utf16(&name_raw) {
                Ok(n) => n,
                Err(_) => {
                    return Err(GptError::BadEntry {
                        idx: i + 1,
                        name: String::new(),
                        reason: "invalid UTF-16 name".into(),
                    });
                }
            };
            let idx = (i + 1) as u32;
            if first == 0 || last < first {
                return Err(GptError::BadEntry {
                    idx: i + 1,
                    name,
                    reason: format!("invalid LBA range {first}..{last}"),
                });
            }
            if first < first_usable || last > last_usable {
                return Err(GptError::BadEntry {
                    idx: i + 1,
                    name,
                    reason: format!(
                        "range {first}..{last} outside usable {first_usable}..{last_usable}"
                    ),
                });
            }
            entries.push(GptEntry {
                idx,
                name,
                first_lba: first,
                last_lba: last,
                sectors: last - first + 1,
            });
        }
        if entries.is_empty() {
            return Err(GptError::Malformed("entry table is empty".into()));
        }
        // overlaps (entries are already in order)
        for w in entries.windows(2) {
            if w[0].last_lba >= w[1].first_lba {
                return Err(GptError::Malformed(format!(
                    "partitions overlap: {} and {}",
                    w[0].name, w[1].name
                )));
            }
        }
        Ok(Gpt {
            entries,
            first_usable_lba: first_usable,
            last_usable_lba: last_usable,
            entries_end_lba: entry_lba
                + (num_entries as u64 * entry_size as u64).div_ceil(LBA_SIZE as u64),
        })
    }

    pub fn find(&self, name: &str) -> Option<&GptEntry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// "idx\tname\tstart\tsectors" — byte-compatible with the legacy
    /// gpt_parts.py / partition_table.tsv in backups.
    pub fn to_tsv(&self) -> String {
        let mut s = String::new();
        for e in &self.entries {
            s.push_str(&format!(
                "{}\t{}\t{}\t{}\n",
                e.idx, e.name, e.first_lba, e.sectors
            ));
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic GPT image (LBA1 + entries), built in code: no real
    /// device dumps live in the repository. The layout mirrors a
    /// Capsule-14 partition table.
    fn synth_gpt(entries: &[(&str, u64, u64)]) -> Vec<u8> {
        // (name, first_lba, sectors); entries start at LBA2, 128 bytes each
        let mut data = vec![0u8; 34 * 512];
        let mut blob = vec![0u8; entries.len().max(4) * 128];
        for (i, (name, first, sectors)) in entries.iter().enumerate() {
            let e = &mut blob[i * 128..(i + 1) * 128];
            e[..16].copy_from_slice(&[0xaf; 16]); // type guid != 0
            e[32..40].copy_from_slice(&first.to_le_bytes());
            let last = first + sectors - 1;
            e[40..48].copy_from_slice(&last.to_le_bytes());
            for (j, ch) in name.encode_utf16().enumerate() {
                e[56 + j * 2..58 + j * 2].copy_from_slice(&ch.to_le_bytes());
            }
        }
        let hdr = &mut data[..512];
        hdr[..8].copy_from_slice(b"EFI PART");
        hdr[12..16].copy_from_slice(&92u32.to_le_bytes()); // header size
        hdr[72..80].copy_from_slice(&2u64.to_le_bytes()); // entry lba
        hdr[80..84].copy_from_slice(&(entries.len().max(4) as u32).to_le_bytes());
        hdr[84..88].copy_from_slice(&128u32.to_le_bytes()); // entry size
        let ecrc = crc32(&blob);
        hdr[88..92].copy_from_slice(&ecrc.to_le_bytes());
        hdr[40..48].copy_from_slice(&34u64.to_le_bytes()); // first usable
                                                           // last usable: past the last partition, within the flash
        let last_usable = entries.last().map(|(_, f, n)| f + n + 16).unwrap_or(4000);
        hdr[48..56].copy_from_slice(&last_usable.to_le_bytes());
        hdr[16..20].fill(0);
        let hcrc = crc32(&hdr[..92]);
        hdr[16..20].copy_from_slice(&hcrc.to_le_bytes());
        data[512..512 + blob.len()].copy_from_slice(&blob);
        data
    }

    fn capsule14_like() -> Vec<u8> {
        synth_gpt(&[
            ("uboot", 8192, 8192),
            ("trust", 16384, 8192),
            ("misc", 24576, 2048),
            ("boot_a", 26624, 32976),
            ("boot_b", 59600, 32976),
            ("system_a", 92576, 88064),
            ("system_b", 180640, 88064),
            ("userdata", 280992, 166463),
        ])
    }

    #[test]
    fn capsule14_like_layout_parses() {
        let gpt = Gpt::parse(&capsule14_like()).expect("parse");
        assert_eq!(gpt.entries.len(), 8);
        // entries are ordered, ranges do not overlap
        assert_eq!(gpt.find("boot_a").map(|e| e.first_lba), Some(26624));
        assert_eq!(gpt.find("boot_a").map(|e| e.sectors), Some(32976));
        assert_eq!(gpt.find("userdata").map(|e| e.last_lba), Some(447454));
        assert_eq!(gpt.find("userdata").map(|e| e.idx), Some(8));
        // TSV format: idx, name, start, sectors
        let tsv = gpt.to_tsv();
        assert!(tsv.starts_with("1\tuboot\t8192\t8192\n"));
        assert!(tsv.ends_with("8\tuserdata\t280992\t166463\n"));
        assert_eq!(tsv.lines().count(), 8);
    }

    #[test]
    fn corrupted_header_rejected() {
        let mut data = capsule14_like();
        data[20] ^= 0xff; // a field covered by the header CRC
        assert!(matches!(Gpt::parse(&data), Err(GptError::BadHeaderCrc)));
    }

    #[test]
    fn corrupted_entries_rejected() {
        let mut data = capsule14_like();
        data[512 + 40] ^= 0xff; // corrupt the first entry
        assert!(matches!(Gpt::parse(&data), Err(GptError::BadEntriesCrc)));
    }

    #[test]
    fn overlapping_partitions_rejected() {
        let data = synth_gpt(&[("a", 512, 512), ("b", 1023, 8)]); // b overlaps a
        assert!(matches!(Gpt::parse(&data), Err(GptError::Malformed(_))));
    }

    /// Rewrite a header field and re-sign the header CRC.
    fn patch_header(data: &mut [u8], offset: usize, bytes: &[u8]) {
        let hdr = &mut data[..512];
        hdr[offset..offset + bytes.len()].copy_from_slice(bytes);
        hdr[16..20].fill(0);
        let hcrc = crc32(&hdr[..92]);
        hdr[16..20].copy_from_slice(&hcrc.to_le_bytes());
    }

    #[test]
    fn zero_entry_lba_rejected_without_underflow() {
        // entry_lba == 0 used to underflow the slice arithmetic and
        // panic in debug builds; it must come back as a parse error
        let mut data = capsule14_like();
        patch_header(&mut data, 72, &0u64.to_le_bytes());
        match Gpt::parse(&data) {
            Err(GptError::Malformed(msg)) => assert!(msg.contains("entry_lba"), "{msg}"),
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn invalid_utf16_name_rejected() {
        // a lone surrogate in a partition name must not silently turn
        // into an empty name (two such partitions are indistinguishable)
        let mut data = capsule14_like();
        data[512 + 56..512 + 58].copy_from_slice(&0xD800u16.to_le_bytes());
        let blob = data[512..512 + 8 * 128].to_vec();
        patch_header(&mut data, 88, &crc32(&blob).to_le_bytes());
        match Gpt::parse(&data) {
            Err(GptError::BadEntry { reason, .. }) => assert!(reason.contains("UTF-16")),
            other => panic!("expected BadEntry, got {other:?}"),
        }
    }
}
