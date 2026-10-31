//! The UBI layer: PEB headers (EC/VID), the volume table (the layout
//! volume), parsing partition dumps and building images with volumes.
//!
//! The format follows `drivers/mtd/ubi/ubi-media.h`: all fields are
//! big-endian.

use crate::crc::crc32;
use crate::error::{Error, Result};

/// EC header magic (`UBI_EC_HDR_MAGIC` "UBI#").
pub const UBI_EC_HDR_MAGIC: u32 = 0x5542_4923;
/// VID header magic (`UBI_VID_HDR_MAGIC` "UBI!").
pub const UBI_VID_HDR_MAGIC: u32 = 0x5542_4921;
/// Volume table record magic (`UBI_VTBL_MAGIC`).
pub const UBI_VTBL_MAGIC: u32 = 0x4E4F_5655;

/// The UBI on-flash format version.
pub const UBI_VERSION: u8 = 1;
/// EC header size.
pub const UBI_EC_HDR_SIZE: usize = 64;
/// VID header size.
pub const UBI_VID_HDR_SIZE: usize = 64;
/// Volume table record size.
pub const UBI_VTBL_RECORD_SIZE: usize = 172;
/// The internal layout-volume id (`UBI_LAYOUT_VOLUME_ID`).
pub const UBI_LAYOUT_VOLUME_ID: u32 = 0x7FFF_FFFF;
/// A dynamic volume (`UBI_VID_DYNAMIC`).
pub const UBI_VID_DYNAMIC: u8 = 1;
/// A static volume (`UBI_VID_STATIC`).
pub const UBI_VID_STATIC: u8 = 2;
/// The volume "autoresize" flag (`UBI_VTBL_AUTORESIZE_FLG`).
pub const UBI_VTBL_AUTORESIZE_FLG: u8 = 0x01;

/// A PEB EC header (`struct ubi_ec_hdr`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcHeader {
    /// The erase counter.
    pub ec: u64,
    /// The VID header offset inside the PEB.
    pub vid_hdr_offset: u32,
    /// The data offset inside the PEB.
    pub data_offset: u32,
    /// The image sequence number.
    pub image_seq: u32,
}

impl EcHeader {
    /// Parse from raw (big-endian) bytes with a CRC check.
    pub fn parse(b: &[u8]) -> Result<EcHeader> {
        if b.len() < UBI_EC_HDR_SIZE {
            return Err(Error::BadNode("EC header truncated".into()));
        }
        if be32(b, 0) != UBI_EC_HDR_MAGIC {
            return Err(Error::BadNode(format!("bad EC magic {:#x}", be32(b, 0))));
        }
        let stored = be32(b, 60);
        if stored != crc32(&b[..60]) {
            return Err(Error::BadCrc("EC header crc mismatch".into()));
        }
        Ok(EcHeader {
            ec: be64(b, 8),
            vid_hdr_offset: be32(b, 16),
            data_offset: be32(b, 20),
            image_seq: be32(b, 24),
        })
    }

    /// Serialize to raw bytes with a CRC.
    pub fn to_bytes(&self) -> [u8; UBI_EC_HDR_SIZE] {
        let mut b = [0u8; UBI_EC_HDR_SIZE];
        b[0..4].copy_from_slice(&UBI_EC_HDR_MAGIC.to_be_bytes());
        b[4] = UBI_VERSION;
        b[8..16].copy_from_slice(&self.ec.to_be_bytes());
        b[16..20].copy_from_slice(&self.vid_hdr_offset.to_be_bytes());
        b[20..24].copy_from_slice(&self.data_offset.to_be_bytes());
        b[24..28].copy_from_slice(&self.image_seq.to_be_bytes());
        let crc = crc32(&b[..60]);
        b[60..64].copy_from_slice(&crc.to_be_bytes());
        b
    }
}

/// A PEB VID header (`struct ubi_vid_hdr`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VidHeader {
    /// Volume type (dynamic/static).
    pub vol_type: u8,
    /// The LEB copy flag (garbage collection).
    pub copy_flag: u8,
    /// Volume identifier.
    pub vol_id: u32,
    /// The LEB number inside the volume.
    pub lnum: u32,
    /// Static volumes: the data size.
    pub data_size: u32,
    /// Static volumes: the number of used LEBs.
    pub used_ebs: u32,
    /// Data padding.
    pub data_pad: u32,
    /// Static volumes: the data CRC.
    pub data_crc: u32,
}

impl VidHeader {
    /// Parse from raw (big-endian) bytes with a CRC check.
    pub fn parse(b: &[u8]) -> Result<VidHeader> {
        if b.len() < UBI_VID_HDR_SIZE {
            return Err(Error::BadNode("VID header truncated".into()));
        }
        if be32(b, 0) != UBI_VID_HDR_MAGIC {
            return Err(Error::BadNode(format!("bad VID magic {:#x}", be32(b, 0))));
        }
        let stored = be32(b, 60);
        if stored != crc32(&b[..60]) {
            return Err(Error::BadCrc("VID header crc mismatch".into()));
        }
        Ok(VidHeader {
            vol_type: b[6],
            copy_flag: b[7],
            vol_id: be32(b, 8),
            lnum: be32(b, 12),
            data_size: be32(b, 20),
            used_ebs: be32(b, 24),
            data_pad: be32(b, 28),
            data_crc: be32(b, 32),
        })
    }

    /// Serialize to raw bytes with a CRC.
    pub fn to_bytes(&self) -> [u8; UBI_VID_HDR_SIZE] {
        let mut b = [0u8; UBI_VID_HDR_SIZE];
        b[0..4].copy_from_slice(&UBI_VID_HDR_MAGIC.to_be_bytes());
        b[4] = UBI_VERSION;
        b[6] = self.vol_type;
        b[7] = self.copy_flag;
        b[8..12].copy_from_slice(&self.vol_id.to_be_bytes());
        b[12..16].copy_from_slice(&self.lnum.to_be_bytes());
        b[20..24].copy_from_slice(&self.data_size.to_be_bytes());
        b[24..28].copy_from_slice(&self.used_ebs.to_be_bytes());
        b[28..32].copy_from_slice(&self.data_pad.to_be_bytes());
        b[32..36].copy_from_slice(&self.data_crc.to_be_bytes());
        let crc = crc32(&b[..60]);
        b[60..64].copy_from_slice(&crc.to_be_bytes());
        b
    }
}

/// A volume table record (`struct ubi_vtbl_record`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VtblRecord {
    /// How many PEBs are reserved for the volume.
    pub reserved_pebs: u32,
    /// Volume alignment.
    pub alignment: u32,
    /// Data padding.
    pub data_pad: u32,
    /// Volume type.
    pub vol_type: u8,
    /// The update marker.
    pub upd_marker: u8,
    /// Name length.
    pub name_len: u16,
    /// The volume name (NUL-terminated).
    pub name: [u8; 128],
    /// Flags (`UBI_VTBL_AUTORESIZE_FLG`).
    pub flags: u8,
}

impl VtblRecord {
    /// An empty record (the volume slot is free).
    pub fn empty() -> VtblRecord {
        VtblRecord {
            reserved_pebs: 0,
            alignment: 0,
            data_pad: 0,
            vol_type: 0,
            upd_marker: 0,
            name_len: 0,
            name: [0; 128],
            flags: 0,
        }
    }

    /// Parse from raw (big-endian) bytes with a CRC check.
    pub fn parse(b: &[u8]) -> Result<VtblRecord> {
        if b.len() < UBI_VTBL_RECORD_SIZE {
            return Err(Error::BadNode("vtbl record truncated".into()));
        }
        let crc_stored = be32(b, UBI_VTBL_RECORD_SIZE - 4);
        let rec = VtblRecord {
            reserved_pebs: be32(b, 0),
            alignment: be32(b, 4),
            data_pad: be32(b, 8),
            vol_type: b[12],
            upd_marker: b[13],
            name_len: be16(b, 14),
            name: b[16..144].try_into().unwrap(),
            flags: b[144],
        };
        // An empty record (all FF / zeros) skips the CRC check.
        if rec.reserved_pebs == 0 {
            return Ok(rec);
        }
        // The record CRC is in the kernel form (crc32_le without the
        // final XOR) over all 168 bytes before the crc field.
        if crc_stored != crc32(&b[..UBI_VTBL_RECORD_SIZE - 4]) {
            return Err(Error::BadCrc("vtbl record crc mismatch".into()));
        }
        Ok(rec)
    }

    /// Serialize to raw bytes with a CRC.
    pub fn to_bytes(&self) -> [u8; UBI_VTBL_RECORD_SIZE] {
        let mut b = [0u8; UBI_VTBL_RECORD_SIZE];
        b[0..4].copy_from_slice(&self.reserved_pebs.to_be_bytes());
        b[4..8].copy_from_slice(&self.alignment.to_be_bytes());
        b[8..12].copy_from_slice(&self.data_pad.to_be_bytes());
        b[12] = self.vol_type;
        b[13] = self.upd_marker;
        b[14..16].copy_from_slice(&self.name_len.to_be_bytes());
        b[16..144].copy_from_slice(&self.name);
        b[144] = self.flags;
        let crc = crc32(&b[..UBI_VTBL_RECORD_SIZE - 4]);
        b[UBI_VTBL_RECORD_SIZE - 4..].copy_from_slice(&crc.to_be_bytes());
        b
    }

    /// The volume name as a string.
    pub fn name_str(&self) -> String {
        String::from_utf8_lossy(&self.name[..self.name_len as usize]).into_owned()
    }
}

fn be32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}
fn be16(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}
fn be64(b: &[u8], off: usize) -> u64 {
    u64::from_be_bytes([
        b[off],
        b[off + 1],
        b[off + 2],
        b[off + 3],
        b[off + 4],
        b[off + 5],
        b[off + 6],
        b[off + 7],
    ])
}

/// The geometry of a UBI dump or image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UbiGeometry {
    /// PEB size.
    pub peb_size: u32,
    /// The VID header offset.
    pub vid_hdr_offset: u32,
    /// The data offset.
    pub data_offset: u32,
}

impl UbiGeometry {
    /// The default geometry (as ubiformat): the VID header in the first
    /// min_io unit, the data after it (the 64-byte VID header is aligned
    /// up to min_io). For a 128 KiB PEB flash with 2 KiB min_io this
    /// gives vid @2048 and data @4096.
    pub fn from_peb_size(peb_size: u32, min_io_size: u32) -> UbiGeometry {
        let vid = min_io_size.min(peb_size);
        let data = (vid + UBI_VID_HDR_SIZE as u32).div_ceil(min_io_size) * min_io_size;
        UbiGeometry {
            peb_size,
            vid_hdr_offset: vid,
            data_offset: data,
        }
    }
}

/// A parsed UBI partition dump.
pub struct Dump<'a> {
    /// The raw partition dump.
    pub raw: &'a [u8],
    /// The dump geometry.
    pub geom: UbiGeometry,
    /// The volume table (layout volume records).
    pub vtbl: Vec<VtblRecord>,
}

impl<'a> Dump<'a> {
    /// Parse a dump: scan the PEBs, read the volume table (the layout
    /// volume).
    pub fn parse(raw: &'a [u8], geom: UbiGeometry) -> Result<Dump<'a>> {
        let peb = geom.peb_size as usize;
        if raw.len() < peb * 2 {
            return Err(Error::MissingData("dump is smaller than two PEBs".into()));
        }
        let mut vtbl = Vec::new();
        // The layout volume: two PEBs with vol_id 0x7FFFFFFF, lnum 0/1;
        // the vtbl records live in the data at data_offset.
        for base in [0usize, peb] {
            let vid = &raw[base + geom.vid_hdr_offset as usize..];
            let Ok(vh) = VidHeader::parse(vid) else {
                continue;
            };
            if vh.vol_id != UBI_LAYOUT_VOLUME_ID {
                continue;
            }
            let data = &raw[base + geom.data_offset as usize..base + peb];
            let recs = data.len() / UBI_VTBL_RECORD_SIZE;
            for r in 0..recs {
                let rec = VtblRecord::parse(&data[r * UBI_VTBL_RECORD_SIZE..])?;
                if vtbl.len() <= r {
                    vtbl.resize(r + 1, VtblRecord::empty());
                }
                if rec.reserved_pebs != 0 {
                    vtbl[r] = rec;
                }
            }
        }
        Ok(Dump { raw, geom, vtbl })
    }

    /// The volume list (id, name, type) from the volume table.
    pub fn volumes(&self) -> Vec<(u32, String, u8)> {
        self.vtbl
            .iter()
            .enumerate()
            .filter(|(_, r)| r.reserved_pebs != 0)
            .map(|(i, r)| (i as u32, r.name_str(), r.vol_type))
            .collect()
    }

    /// The LEBs of a volume (per the VID headers; unmapped — None).
    pub fn volume_lebs(&self, vol_id: u32) -> Vec<Option<Vec<u8>>> {
        let mut lebs: Vec<Option<Vec<u8>>> = Vec::new();
        let peb = self.geom.peb_size as usize;
        let mut base = 0usize;
        while base + peb <= self.raw.len() {
            let vid = &self.raw[base + self.geom.vid_hdr_offset as usize..];
            if let Ok(vh) = VidHeader::parse(vid) {
                if vh.vol_id == vol_id {
                    if lebs.len() <= vh.lnum as usize {
                        lebs.resize(vh.lnum as usize + 1, None);
                    }
                    lebs[vh.lnum as usize] =
                        Some(self.raw[base + self.geom.data_offset as usize..base + peb].to_vec());
                }
            }
            base += peb;
        }
        lebs
    }
}

/// Parameters for building a UBI image.
#[derive(Debug, Clone)]
pub struct BuildOptions {
    /// The image/dump geometry.
    pub geom: UbiGeometry,
    /// The image sequence number (EC headers).
    pub image_seq: u32,
    /// The initial erase counter.
    pub start_ec: u64,
}

/// Build a UBI image: volumes + the volume table (the layout volume) —
/// a minimal ubinize equivalent for dynamic volumes.
///
/// `volumes` is a list of (vol_id, name, volume LEBs); ids must be
/// < 0x7FFFFFFF.
pub fn build_image(volumes: &[Volume], opts: &BuildOptions) -> Result<Vec<u8>> {
    let peb = opts.geom.peb_size as usize;
    let data_len = peb - opts.geom.data_offset as usize;
    let mut out: Vec<u8> = Vec::new();
    let mut ec = opts.start_ec;

    // The volume table: records padded up to data_len.
    let n_volumes = volumes.len().max(1);
    let vtbl_bytes = {
        let mut v = vec![0u8; UBI_VTBL_RECORD_SIZE * n_volumes.next_power_of_two().max(2)];
        for (i, vol) in volumes.iter().enumerate() {
            let rec = VtblRecord {
                reserved_pebs: vol.lebs.len() as u32,
                alignment: 1,
                data_pad: 0,
                vol_type: UBI_VID_DYNAMIC,
                upd_marker: 0,
                name_len: vol.name.len() as u16,
                name: {
                    let mut n = [0u8; 128];
                    let bytes = vol.name.as_bytes();
                    if bytes.len() > 127 {
                        return Err(Error::Overflow("volume name is too long".into()));
                    }
                    n[..bytes.len()].copy_from_slice(bytes);
                    n
                },
                flags: UBI_VTBL_AUTORESIZE_FLG,
            };
            v[i * UBI_VTBL_RECORD_SIZE..(i + 1) * UBI_VTBL_RECORD_SIZE]
                .copy_from_slice(&rec.to_bytes());
        }
        v.resize(data_len, 0);
        v
    };

    // The two layout-volume PEBs.
    for lnum in 0..2u32 {
        let vh = VidHeader {
            vol_type: UBI_VID_DYNAMIC,
            copy_flag: 0,
            vol_id: UBI_LAYOUT_VOLUME_ID,
            lnum,
            data_size: 0,
            used_ebs: 0,
            data_pad: 0,
            data_crc: 0,
        };
        write_peb(&mut out, &opts.geom, &vh, Some(&vtbl_bytes), ec);
        ec += 1;
    }

    // The volumes.
    for vol in volumes {
        if vol.vol_id == UBI_LAYOUT_VOLUME_ID {
            return Err(Error::Other("reserved layout volume id".into()));
        }
        if vol.lebs.len() > u32::MAX as usize {
            return Err(Error::Overflow("volume is too large".into()));
        }
        for (lnum, leb) in vol.lebs.iter().enumerate() {
            let vh = VidHeader {
                vol_type: UBI_VID_DYNAMIC,
                copy_flag: 0,
                vol_id: vol.vol_id,
                lnum: lnum as u32,
                data_size: 0,
                used_ebs: 0,
                data_pad: 0,
                data_crc: 0,
            };
            match leb {
                Some(data) => {
                    if data.len() != data_len {
                        return Err(Error::Other(format!(
                            "LEB size {} != data size {data_len}",
                            data.len()
                        )));
                    }
                    write_peb(&mut out, &opts.geom, &vh, Some(data), ec);
                }
                None => {
                    // An unmapped LEB: the EC header is present, the VID
                    // stays all-FF.
                    write_peb(&mut out, &opts.geom, &vh, None, ec);
                }
            }
            ec += 1;
        }
    }
    Ok(out)
}

fn write_peb(out: &mut Vec<u8>, geom: &UbiGeometry, vh: &VidHeader, data: Option<&[u8]>, ec: u64) {
    out.resize(out.len() + geom.peb_size as usize, 0xFF);
    let start = out.len() - geom.peb_size as usize;
    let ec_hdr = EcHeader {
        ec,
        vid_hdr_offset: geom.vid_hdr_offset,
        data_offset: geom.data_offset,
        image_seq: 0,
    };
    out[start..start + UBI_EC_HDR_SIZE].copy_from_slice(&ec_hdr.to_bytes());
    if let Some(data) = data {
        let voff = start + geom.vid_hdr_offset as usize;
        out[voff..voff + UBI_VID_HDR_SIZE].copy_from_slice(&vh.to_bytes());
        let doff = start + geom.data_offset as usize;
        out[doff..doff + data.len()].copy_from_slice(data);
    }
}

/// A volume for image building.
pub struct Volume {
    /// The volume identifier.
    pub vol_id: u32,
    /// The volume name (for the volume table).
    pub name: String,
    /// The volume LEBs; None — unmapped.
    pub lebs: Vec<Option<Vec<u8>>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ec_vid_roundtrip() {
        let ec = EcHeader {
            ec: 42,
            vid_hdr_offset: 2048,
            data_offset: 4096,
            image_seq: 7,
        };
        let b = ec.to_bytes();
        assert_eq!(EcHeader::parse(&b).unwrap(), ec);

        let vh = VidHeader {
            vol_type: UBI_VID_DYNAMIC,
            copy_flag: 0,
            vol_id: 0,
            lnum: 5,
            data_size: 0,
            used_ebs: 0,
            data_pad: 0,
            data_crc: 0,
        };
        let b = vh.to_bytes();
        assert_eq!(VidHeader::parse(&b).unwrap(), vh);
    }

    #[test]
    fn build_then_parse() {
        let geom = UbiGeometry::from_peb_size(0x20000, 2048);
        let vol = Volume {
            vol_id: 0,
            name: "data".into(),
            lebs: vec![Some(vec![0xAB; (geom.peb_size - geom.data_offset) as usize]); 3],
        };
        let img = build_image(
            &[vol],
            &BuildOptions {
                geom,
                image_seq: 0,
                start_ec: 0,
            },
        )
        .unwrap();
        let dump = Dump::parse(&img, geom).unwrap();
        assert_eq!(
            dump.volumes(),
            vec![(0, "data".to_string(), UBI_VID_DYNAMIC)]
        );
        let lebs = dump.volume_lebs(0);
        assert_eq!(lebs.len(), 3);
        assert!(lebs.iter().all(|l| l.as_ref().unwrap()[0] == 0xAB));
    }
}
